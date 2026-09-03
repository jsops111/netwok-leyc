<script setup lang="ts">
import { computed, h, onMounted, ref, watch } from 'vue'
import {
  NButton, NDataTable, NInput, NSelect, NSwitch, NTag, useMessage,
} from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import StateDot from '@/components/cyber/StateDot.vue'
import MeterBar from '@/components/cyber/MeterBar.vue'
import PortFaceplate from '@/components/PortFaceplate.vue'
import { api, errText } from '@/api'
import type { Faceplate as FaceplateData, InterfaceRow, InterfaceSummaryRow } from '@/api'
import { ago, bps, dateTimeOf, int, pct } from '@/composables/useFormat'
import { STATE } from '@/theme'

/**
 * 设备接口明细。
 *
 * 这一页存在的理由:大屏上只有每台设备"最忙的 6 个口",而巡检、排障、
 * 交维要的是**完整的一张接口表** —— 哪个口 down 了、哪个口在丢包、
 * 哪个口快跑满了、哪个口的数字根本不能信。
 *
 * ## 「速率成色」是这一页最容易被忽略但最要紧的一列
 *
 * ifHC*(64 位)采不到时采集器会退回 32 位计数器,并在 meta 里标记。
 * **48 口千兆交换机满速时 32 位的 ifInOctets 约 34 秒回绕一次**,
 * 60 秒采集间隔算出来的速率纯粹是噪声 —— 而它看起来是一个正常的数字。
 * 不把它显式标出来,就会有人拿着一个噪声去排查一个不存在的流量问题
 * (见 CLAUDE.md 第 6 条)。
 *
 * ## 「异常」的定义排除了 admin down
 *
 * 48 口交换机上一半的口是空的,那些口 admin down 是**人为关的**,不是故障。
 * 所以「仅异常」筛的是 `admin up 但链路 down` 或者本周期新增了错包。
 * 把 admin down 也算进去,这个筛选就没用了。
 */

const message = useMessage()

const loading = ref(false)
const summary = ref<InterfaceSummaryRow[]>([])
const selected = ref<number | null>(null)

const rows = ref<InterfaceRow[]>([])
const rowsLoading = ref(false)
const total = ref(0)
const page = ref(1)
const pageSize = ref(50)

const keyword = ref('')
const problemOnly = ref(false)
const activeOnly = ref(false)
const ordering = ref('if_index')

const current = computed(() => summary.value.find((s) => s.device_id === selected.value) || null)

const totals = computed(() => {
  const list = summary.value
  return {
    devices: list.length,
    ports: list.reduce((a, b) => a + b.total, 0),
    problem: list.reduce((a, b) => a + b.problem, 0),
    errors: list.reduce((a, b) => a + b.errors, 0),
    legacy: list.reduce((a, b) => a + b.counter_32bit, 0),
  }
})

async function loadSummary() {
  loading.value = true
  try {
    const { data } = await api.interfaceSummary()
    // 关掉了「采集接口明细」的设备不列 —— 它们的接口表永远是空的
    summary.value = data.devices.filter((d) => d.collect_interfaces || d.total > 0)
    if (selected.value === null && summary.value.length) {
      selected.value = summary.value[0].device_id
    }
  } catch (e) {
    message.error(errText(e))
  } finally {
    loading.value = false
  }
}

/**
 * 面板图。**几何来自型号画像,口的名字和状态来自设备本身** ——
 * 所以一台插了扩展模块的交换机图上会多出那几个口,不用改代码。
 *
 * ⚠ 画错的面板比没有面板危险:有人会照着它去机房拔线,而拔错的是别人的。
 * 后端返回的 `note` 里说明了这张图可信到什么程度(有没有实机核对过 /
 * 是不是只是按接口名排的示意图),**组件里原样显示,不许收进折叠**。
 */
const faceplate = ref<FaceplateData | null>(null)
const faceLoading = ref(false)
/** 图上选中的口 —— 点一下就把它筛到下面的表里 */
const pickedId = ref<number | null>(null)

async function loadFaceplate() {
  if (selected.value === null) { faceplate.value = null; return }
  faceLoading.value = true
  try {
    const { data } = await api.deviceFaceplate(selected.value)
    faceplate.value = data
  } catch (e) {
    // **面板拿不到不该让整页打不开** —— 下面那张接口表才是主体
    faceplate.value = null
  } finally {
    faceLoading.value = false
  }
}

/**
 * 点了图上一个口:把它筛到下面的表里。
 *
 * **用接口名去筛,不用 id** —— 名字是人在设备上看到的东西,而且筛完
 * 那个词还留在搜索框里,人能看出"现在这张表是被筛过的"。用 id 静默筛
 * 会让人以为这台设备只有一个口。
 */
function pickPort(port: { id: number; if_name: string }) {
  pickedId.value = port.id
  keyword.value = port.if_name
}

async function loadRows() {
  if (selected.value === null) { rows.value = []; return }
  rowsLoading.value = true
  try {
    const { data } = await api.interfaces({
      device: selected.value,
      page: page.value,
      page_size: pageSize.value,
      ordering: ordering.value,
      keyword: keyword.value || undefined,
      problem: problemOnly.value ? true : undefined,
      active: activeOnly.value ? true : undefined,
    })
    rows.value = data.results
    total.value = data.count
  } catch (e) {
    message.error(errText(e))
  } finally {
    rowsLoading.value = false
  }
}

onMounted(async () => {
  await loadSummary()
  await loadRows()
  await loadFaceplate()
})

watch([selected, keyword, problemOnly, activeOnly, ordering], () => {
  page.value = 1
  void loadRows()
})
// 换设备要重画面板 —— 面板是按设备取的。**筛选变了不用重取**:
// 图上永远画这台设备的全部口,筛选只作用于下面那张表。
// 图跟着筛选变的话,"只看异常"会让面板上剩下三个孤零零的口 —— 那不是面板
watch(selected, () => { pickedId.value = null; void loadFaceplate() })
watch([page, pageSize], () => void loadRows())

async function toggleMonitor(row: InterfaceRow) {
  try {
    const { data } = await api.toggleInterfaceMonitor(row.id)
    row.monitored = data.monitored
    message.success(
      data.monitored
        ? `${row.if_name} 已纳入监控`
        : `${row.if_name} 已移出监控 —— 不再判 if_down / 带宽饱和事件,但仍然采流量`,
    )
  } catch (e) {
    message.error(errText(e))
  }
}

const ORDER_OPTIONS = [
  { label: '按 ifIndex(默认)', value: 'if_index' },
  { label: '入向流量最大在前', value: '-in_bps' },
  { label: '出向流量最大在前', value: '-out_bps' },
]

const exportUrl = computed(() => api.interfaceExportUrl({
  device: selected.value ?? undefined,
  ordering: ordering.value,
  keyword: keyword.value || undefined,
  problem: problemOnly.value ? true : undefined,
  active: activeOnly.value ? true : undefined,
}))

const summaryColumns: DataTableColumns<InterfaceSummaryRow> = [
  { title: '设备', key: 'device_name', minWidth: 160,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, r.device_name),
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
        `${r.mgmt_ip} · ${r.model_label}`),
    ]) },
  { title: '状态', key: 'state', width: 82,
    render: (r) => h(StateDot, { state: r.state, label: true }) },
  { title: '接口数', key: 'total', width: 96, className: 'num',
    render: (r) => h('span', { style: 'font-size:11.5px' }, [
      h('b', { style: 'font-size:12.5px' }, String(r.total)),
      h('span', { style: 'color:var(--cy-ink-3)' }, ` / up ${r.up}`),
    ]) },
  { title: '异常', key: 'problem', width: 72, className: 'num',
    render: (r) => h('span', {
      style: `font-size:11.5px;font-weight:700;color:${r.problem ? STATE.down : 'var(--cy-ink-3)'}`,
      title: 'admin up 但链路 down',
    }, r.problem ? String(r.problem) : '—') },
  { title: '错包', key: 'errors', width: 72, className: 'num',
    render: (r) => h('span', {
      style: `font-size:11.5px;color:${r.errors ? STATE.degraded : 'var(--cy-ink-3)'}`,
      title: '本周期新增了错包的接口数',
    }, r.errors ? String(r.errors) : '—') },
  { title: '速率成色', key: 'counter_32bit', width: 104,
    render: (r) => r.counter_32bit
      ? h(NTag, {
          size: 'tiny', bordered: false,
          style: `color:${STATE.degraded};border:1px solid ${STATE.degraded}`,
          title: '这些口退回了 32 位计数器,算出来的速率不可信',
        }, () => `${r.counter_32bit} 口 32 位`)
      : h('span', { style: `font-size:10.5px;color:${STATE.up}` }, '64 位'),
  },
  { title: '未监控', key: 'unmonitored', width: 76, className: 'num',
    render: (r) => h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' },
      r.unmonitored ? String(r.unmonitored) : '—') },
  { title: '最后采集', key: 'last_collected_at', width: 96,
    render: (r) => h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' },
      ago(r.last_collected_at)) },
  { title: '操作', key: 'act', width: 92, fixed: 'right',
    render: (r) => h(NButton, {
      size: 'tiny', ghost: true,
      type: selected.value === r.device_id ? 'primary' : 'default',
      onClick: () => { selected.value = r.device_id },
    }, () => '看接口') },
]

/** 一行的状态标签。**admin down 不标成故障** —— 那是人为关的。 */
function statusCell(r: InterfaceRow) {
  const tags = []
  if (r.oper_up) {
    tags.push(h('span', { style: `font-size:11px;font-weight:700;color:${STATE.up}` }, 'up'))
  } else if (r.admin_up === false) {
    tags.push(h('span', { style: 'font-size:11px;color:var(--cy-ink-3)', title: '人为关闭,不是故障' }, 'admin down'))
  } else if (r.oper_up === false) {
    tags.push(h('span', { style: `font-size:11px;font-weight:700;color:${STATE.down}` }, 'down'))
  } else {
    tags.push(h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, '未知'))
  }
  return h('div', { style: 'display:flex;flex-direction:column;gap:1px' }, tags)
}

const ifColumns: DataTableColumns<InterfaceRow> = [
  { title: 'ifIndex', key: 'if_index', width: 74, className: 'num',
    render: (r) => h('span', { style: "font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--cy-ink-3)" },
      String(r.if_index)) },
  { title: '接口', key: 'if_name', minWidth: 168,
    render: (r) => h('div', [
      h('div', { style: "font-size:12px;color:var(--cy-ink);font-family:'JetBrains Mono',monospace" }, r.if_name),
      r.if_alias
        ? h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' }, r.if_alias)
        : null,
    ]) },
  { title: '状态', key: 'oper_up', width: 92, render: statusCell },
  { title: '协商速率', key: 'speed_bps', width: 92, className: 'num',
    render: (r) => h('span', { style: "font-size:11px;font-family:'JetBrains Mono',monospace" },
      r.speed_bps ? bps(r.speed_bps) : '—') },
  { title: '入向 / 出向', key: 'rate', width: 168,
    render: (r) => h('div', { style: "font-size:11px;font-family:'JetBrains Mono',monospace;line-height:1.5" }, [
      h('div', null, `↓ ${bps(r.in_bps)}`),
      h('div', { style: 'color:var(--cy-ink-2)' }, `↑ ${bps(r.out_bps)}`),
    ]) },
  { title: '利用率', key: 'util', width: 128,
    render: (r) => {
      // 协商速率拿不到就算不出利用率 —— 显示"无速率"而不是 0%
      if (r.util_in_pct === null && r.util_out_pct === null) {
        return h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' }, '无速率')
      }
      const worst = Math.max(r.util_in_pct ?? 0, r.util_out_pct ?? 0)
      return h('div', { style: 'display:flex;align-items:center;gap:6px' }, [
        h('span', { style: 'flex:1' }, [
          h(MeterBar, { value: worst, max: 100, warn: 70, crit: 90, showValue: false }),
        ]),
        h('span', {
          style: `font-size:11px;font-family:'JetBrains Mono',monospace;width:38px;text-align:right;`
            + `color:${worst >= 90 ? STATE.down : worst >= 70 ? STATE.degraded : 'var(--cy-ink-2)'}`,
        }, pct(worst, 0)),
      ])
    } },
  { title: '错包增量', key: 'err', width: 96, className: 'num',
    render: (r) => {
      const total = (r.in_err_delta ?? 0) + (r.out_err_delta ?? 0)
      // 两个都是 null 说明还没有上一拍可比 —— 不是 0
      if (r.in_err_delta === null && r.out_err_delta === null) {
        return h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)', title: '还没有可比的上一拍' }, '—')
      }
      return h('span', {
        style: `font-size:11.5px;font-family:'JetBrains Mono',monospace;`
          + `color:${total ? STATE.degraded : 'var(--cy-ink-3)'};font-weight:${total ? 700 : 400}`,
      }, int(total))
    } },
  { title: '速率成色', key: 'counter_32bit', width: 92,
    render: (r) => r.counter_32bit
      ? h(NTag, {
          size: 'tiny', bordered: false,
          style: `color:${STATE.degraded};border:1px solid ${STATE.degraded}`,
          title: '这个口退回了 32 位计数器:千兆满速时约 34 秒回绕一次,'
            + '按 60 秒间隔算出来的速率是噪声,不要拿它去排查流量问题',
        }, () => '32 位')
      : h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' }, '64 位'),
  },
  { title: '最后变化', key: 'last_change', width: 96,
    render: (r) => h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' },
      r.last_change ? ago(r.last_change) : '—') },
  { title: '纳入监控', key: 'monitored', width: 84, fixed: 'right',
    render: (r) => h(NSwitch, {
      value: r.monitored, size: 'small',
      onUpdateValue: () => toggleMonitor(r),
    }) },
]
</script>

<template>
  <div class="ifs">
    <div class="tiles">
      <StatTile label="设备" :value="totals.devices" unit="台" :dim-zero="false"
                foot="开了「采集接口明细」的" />
      <StatTile label="接口总数" :value="totals.ports" unit="个" :dim-zero="false" />
      <StatTile label="异常接口" :value="totals.problem" unit="个" :color="STATE.down"
                foot="admin up 但链路 down(admin down 不算)" />
      <StatTile label="有错包" :value="totals.errors" unit="个" :color="STATE.degraded"
                foot="本周期新增了错包" />
      <StatTile label="32 位计数器" :value="totals.legacy" unit="个" :color="STATE.degraded"
                foot="这些口的速率不可信" />
    </div>

    <CyberPanel title="设备接口" subtitle="巡检 / 排障 / 交维要的那张完整接口表" flush>
      <template #actions>
        <NButton size="small" ghost :loading="loading" @click="loadSummary()">刷新</NButton>
      </template>
      <NDataTable
        :columns="summaryColumns" :data="summary" :loading="loading"
        size="small" :bordered="false" :single-line="false" :scroll-x="1080"
      />
      <div v-if="!summary.length && !loading" class="cy-empty">
        没有设备在采接口明细。到<b>配置中心 → 网络设备</b>打开「采集接口明细」——
        48 口设备一次要走近百个 OID,所以它是可以关掉的。<br>
        接口是**采集出来的**,不能手工添加;这里只有「纳入监控」那个开关可以调。
      </div>
    </CyberPanel>

    <CyberPanel
      v-if="current"
      :title="`${current.device_name} 的接口`"
      :subtitle="`${total} 个 · 采集于 ${current.last_collected_at ? dateTimeOf(current.last_collected_at) : '从未'}`"
      flush
    >
      <template #actions>
        <span v-if="current.counter_32bit" class="warn-inline">
          ⚠ 这台设备有 {{ current.counter_32bit }} 个口退回了 32 位计数器 ——
          那几行的速率是噪声,别拿它排查流量问题
        </span>
      </template>

      <!-- ============ 端口面板图 ============ -->
      <div v-if="faceLoading" class="face-loading">读取面板…</div>
      <PortFaceplate
        v-else-if="faceplate && faceplate.banks.length"
        :data="faceplate" :active-id="pickedId"
        class="face"
        @pick="pickPort"
      />
      <div v-else-if="!faceLoading && faceplate" class="face-empty">
        这台设备还没有采到接口,画不出面板图 —— 接口清单是采出来的,
        设备刚加进来时是空的。
      </div>

      <div class="filters">
        <NInput v-model:value="keyword" size="small" clearable placeholder="搜接口名 / 描述"
                style="width: 200px" />
        <NSelect v-model:value="ordering" :options="ORDER_OPTIONS" size="small" style="width: 172px" />
        <label class="tgl">
          <NSwitch v-model:value="problemOnly" size="small" />
          <span>只看异常(down / 有错包)</span>
        </label>
        <label class="tgl">
          <NSwitch v-model:value="activeOnly" size="small" />
          <span>只看 up 的</span>
        </label>
        <a :href="exportUrl" class="csv-link" download>导出 CSV(当前筛选)</a>
      </div>

      <NDataTable
        :columns="ifColumns" :data="rows" :loading="rowsLoading"
        size="small" :bordered="false" :single-line="false" :scroll-x="1240"
        :pagination="{
          page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [50, 100, 200],
          onUpdatePage: (p: number) => (page = p),
          onUpdatePageSize: (s: number) => { pageSize = s; page = 1 },
        }"
        remote
      />
      <div v-if="!rows.length && !rowsLoading" class="cy-empty">
        没有匹配的接口。清掉筛选条件,或者等一个采集周期 ——
        接口清单是采出来的,设备刚加进来时是空的。
      </div>
    </CyberPanel>
  </div>
</template>

<style scoped>
.face { margin: 0 0 12px; }
.face-loading, .face-empty {
  font-size: 11.5px; color: var(--cy-ink-3); padding: 8px 0;
}

.ifs { display: flex; flex-direction: column; gap: 14px; }
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 10px;
}
.warn-inline {
  font-size: 10.5px;
  color: var(--cy-degraded);
  line-height: 1.5;
  max-width: 460px;
}
.filters {
  display: flex;
  gap: 9px;
  align-items: center;
  flex-wrap: wrap;
  padding: 9px 12px 3px;
}
.tgl {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11.5px;
  color: var(--cy-ink-2);
  cursor: pointer;
}
.csv-link {
  font-size: 11px;
  color: var(--cy-cyan);
  text-decoration: none;
  border: 1px solid rgba(var(--cy-cyan-rgb), 0.45);
  padding: 3px 9px;
  margin-left: auto;
  transition: background 0.15s ease;
}
.csv-link:hover { background: rgba(var(--cy-cyan-rgb), 0.12); }
</style>
