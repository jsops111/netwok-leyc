<script setup lang="ts">
import { computed, h, onMounted, ref, watch } from 'vue'
import {
  NButton, NDataTable, NInput, NSelect, NSwitch, NTag, useMessage,
} from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import StateDot from '@/components/cyber/StateDot.vue'
import { api, errText } from '@/api'
import type { PolicySummaryRow, VipRow, VipSummary } from '@/api'
import { useMetaStore } from '@/stores/meta'
import { dateTimeOf } from '@/composables/useFormat'
import { STATE } from '@/theme'

/**
 * 防火墙**映射**(FortiOS 的 firewall vip)。
 *
 * ## 它回答的问题不在策略表里
 *
 * 策略表回答"允不允许",这一页回答 **"外面的 1.2.3.4:443 到底进到内网
 * 哪台机器的哪个端口"**。后者完全不在策略表里:一条入站策略的目的地址
 * 里只有一个 `web-vip` 这样的**名字**,它指向哪里只有登上设备才知道。
 *
 * (注意策略表里那个 `NAT` 列是**源** NAT —— 出去的时候换成出口地址,
 * 和这里说的映射不是一回事。)
 *
 * ## 三件必须在界面上说清楚的事
 *
 * 1. **端口为空 = 所有端口,不是"没配"。**`portforward` 关着时那是一条
 *    1:1 的**整机映射**,外网地址的每一个端口都落到内网那台机器上 ——
 *    暴露面比端口映射大得多。显示成空白(看着像没配好)或者 0(那是个
 *    具体端口号)都是错的。文案由后端算好(`ext_port_text`),
 *    前端不要再判一遍空字符串。
 * 2. **`used_by` 是三态。**`[]` = 没有任何策略引用它(配了但不生效,
 *    可以清理),`null` = 这次没查引用关系。混成一个空数组会让人
 *    删掉一条正在生效的映射 —— 和「命中计数」同一条规矩。
 * 3. **「没有同步到映射」≠「这台防火墙没有映射」。**SSH 的
 *    `show firewall vip` 可能没跑成、API 可能权限不够。前者是状态,
 *    后者是结论,页面上说的是前者。
 */

const message = useMessage()
const meta = useMetaStore()

const loading = ref(false)
const devices = ref<PolicySummaryRow[]>([])
const selected = ref<number | null>(null)

const vips = ref<VipRow[]>([])
const vipsLoading = ref(false)
const summary = ref<VipSummary | null>(null)

const keyword = ref('')
const wholeHostOnly = ref(false)
const unusedOnly = ref(false)
const typeFilter = ref<string | null>(null)

const current = computed(() => devices.value.find((d) => d.device_id === selected.value) || null)

/**
 * 前端筛。**映射一次全取回来**(page_size 500)—— 这一页要的是"扫一眼全部",
 * 分页会让「这台上有没有整机映射」这个问题要翻好几页才答得出来。
 * 一台防火墙几十到几百条映射,一次取完比翻页便宜。
 */
const shown = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  return vips.value.filter((v) => {
    if (wholeHostOnly.value && !v.whole_host) return false
    // **used_by 为 null 时筛不动** —— null 是"没查",不是"没有引用"
    if (unusedOnly.value && (v.used_by === null || v.used_by.length)) return false
    if (typeFilter.value && v.vip_type !== typeFilter.value) return false
    if (!kw) return true
    return [v.name, v.ext_ip, v.mapped_ip, v.comment, v.endpoint_text]
      .some((t) => (t || '').toLowerCase().includes(kw))
  })
})

async function loadDevices() {
  loading.value = true
  try {
    const { data } = await api.policySummary()
    devices.value = data.devices
    if (selected.value === null && data.devices.length) {
      selected.value = data.devices[0].device_id
    }
  } catch (e) {
    message.error(errText(e))
  } finally {
    loading.value = false
  }
}

async function loadVips() {
  if (selected.value === null) { vips.value = []; summary.value = null; return }
  vipsLoading.value = true
  try {
    const [list, sum] = await Promise.all([
      api.vips({ device: selected.value, page_size: 500, ordering: 'name' }),
      api.vipSummary(selected.value),
    ])
    vips.value = list.data.results
    summary.value = sum.data
  } catch (e) {
    message.error(errText(e))
  } finally {
    vipsLoading.value = false
  }
}

async function syncNow(deviceId: number) {
  try {
    const { data } = await api.syncPoliciesNow(deviceId)
    // 映射和策略是**同一次同步**拿回来的,所以这个按钮和策略页那个是同一个
    message.success(`${data.detail}(映射和策略是同一次同步)`)
  } catch (e) {
    message.error(errText(e))
  }
}

onMounted(async () => {
  await meta.load()
  await loadDevices()
  await loadVips()
})
watch(selected, () => void loadVips())

const typeOptions = computed(() => [
  { label: '全部类型', value: '' },
  ...meta.options('vip_type'),
])

const deviceColumns: DataTableColumns<PolicySummaryRow> = [
  { title: '状态', key: 'state', width: 74,
    render: (r) => h(StateDot, { state: r.state, label: true }) },
  { title: '防火墙', key: 'device_name', minWidth: 160,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, r.device_name),
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
        `${r.mgmt_ip} · ${r.vdom}`),
    ]) },
  { title: '同步', key: 'synced_at', minWidth: 170,
    render: (r) => h('div', [
      h('div', { style: 'font-size:11px;color:var(--cy-ink-2)' },
        r.synced_at ? dateTimeOf(r.synced_at) : '从未同步'),
      r.error
        ? h('div', { style: `font-size:10px;color:${STATE.down};line-height:1.4` }, r.error)
        : h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' }, `每 ${r.interval_minutes} 分钟`),
    ]) },
  { title: '', key: 'act', width: 92, fixed: 'right',
    render: (r) => h(NButton, { size: 'tiny', ghost: true,
      onClick: () => syncNow(r.device_id) }, () => '立即同步') },
]

const vipColumns: DataTableColumns<VipRow> = [
  { title: '名称', key: 'name', minWidth: 140,
    render: (r) => h('div', [
      h('div', { style: "font-size:11.5px;color:var(--cy-ink);font-family:'JetBrains Mono',monospace" },
        r.name),
      r.comment
        ? h('div', { style: 'font-size:10px;color:var(--cy-ink-3);line-height:1.4' }, r.comment)
        : null,
    ]) },
  { title: '外面看到的', key: 'ext', minWidth: 190,
    render: (r) => h('div', [
      h('div', { style: "font-size:11.5px;font-family:'JetBrains Mono',monospace;color:var(--cy-ink)" },
        // ext_port_text 是后端算好的:端口为空时它说「所有端口」而不是留白
        `${r.protocol ? r.protocol.toLowerCase() + '/' : ''}${r.ext_ip || '?'}:${r.ext_port_text}`),
      h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' },
        r.ext_intf.length ? `接口 ${r.ext_intf.join(', ')}` : '接口 any'),
    ]) },
  { title: '进到哪里', key: 'mapped', minWidth: 190,
    render: (r) => h('div', { style: "font-size:11.5px;font-family:'JetBrains Mono',monospace;color:var(--cy-cyan)" },
      // 负载均衡型没有 mappedip(后端在 realservers 里,是一组机器)——
      // 后端把那句话拼进了 endpoint_text,这里取箭头右边那半
      r.endpoint_text.split(' → ')[1] || '?') },
  { title: '类型', key: 'vip_type', width: 104,
    render: (r) => h('div', [
      h('div', { style: 'font-size:11px;color:var(--cy-ink-2)' }, r.vip_type_label),
      // **整机映射是这张表里唯一值得标出来的风险**:它把那台机器的每一个
      // 监听端口都暴露到了外面,而在列表里它和一条只映射 443 的规则
      // 长得几乎一样
      r.whole_host
        ? h(NTag, {
            size: 'tiny', bordered: false,
            style: `color:${STATE.degraded};border:1px solid ${STATE.degraded}`,
            title: '外网地址的所有端口都通到内网那台机器上 —— 该收窄成端口映射',
          }, () => '整机映射')
        : h('span', { style: 'font-size:10px;color:var(--cy-ink-3)' }, '端口映射'),
    ]) },
  { title: '被哪些策略引用', key: 'used_by', minWidth: 176,
    render: (r) => {
      // 三态,和「命中计数」同一条规矩:
      //   null  = 这次没查引用关系 → 「未知」
      //   []    = 确实没有策略引用 → **这条映射不生效**,可以清理
      if (r.used_by === null) {
        return h('span', {
          style: 'font-size:10.5px;color:var(--cy-ink-3)',
          title: '这次没有查引用关系 —— 不是"没有策略引用"',
        }, '未知')
      }
      if (!r.used_by.length) {
        return h('span', {
          style: `font-size:11px;color:${STATE.degraded};font-weight:700`,
          title: '没有任何策略的目的地址引用它 —— 配了但不生效,可以清理',
        }, '没有策略引用')
      }
      return h('div', { style: 'display:flex;gap:4px;flex-wrap:wrap' },
        r.used_by.slice(0, 8).map((u) => h(NTag, {
          size: 'tiny', bordered: false,
          // 停用的策略也要列出来,但要看得出它是停用的 ——
          // 一条映射"只被一条停用策略引用"等于没生效
          style: u.enabled ? '' : `color:${STATE.degraded};opacity:.85`,
          title: `#${u.seq + 1} ${u.name || '(未命名)'}${u.enabled ? '' : '(已停用)'}`,
        }, () => `#${u.policy_id}${u.enabled ? '' : '(停)'}`)))
    } },
  { title: '同步', key: 'method', width: 76,
    render: (r) => h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' },
      (r.method || '—').toUpperCase()) },
]
</script>

<template>
  <div class="mp">
    <!-- ============ 顶部 ============ -->
    <div class="tiles">
      <StatTile label="映射总数" :value="summary?.total ?? 0" unit="条" :dim-zero="false" />
      <StatTile
        label="整机映射" :value="summary?.whole_host.count ?? 0" unit="条"
        :color="STATE.degraded" foot="所有端口都通进去,暴露面大得多"
      />
      <StatTile
        label="没有策略引用" :value="summary?.unused.count ?? 0" unit="条"
        :color="STATE.degraded" foot="配了但不生效,可以清理"
      />
      <StatTile label="当前筛选" :value="shown.length" unit="条" :dim-zero="false" />
    </div>

    <!-- 这一页存在的理由,写在最上面 -->
    <div class="lead">
      防火墙策略回答<b>「允不允许」</b>,这一页回答
      <b>「外面的 1.2.3.4:443 到底进到内网哪台机器的哪个端口」</b> ——
      后者完全不在策略表里:一条入站策略的目的地址里只有一个
      <code>web-vip</code> 这样的名字。<br>
      <span class="dim">
        (策略表里那个 NAT 列是<b>源</b> NAT —— 出去的时候换成出口地址,
        和这里说的映射不是一回事。)
      </span>
    </div>

    <!-- ============ 防火墙 ============ -->
    <CyberPanel title="防火墙" subtitle="映射和策略是同一次同步拿回来的" flush>
      <template #actions>
        <NButton size="small" ghost :loading="loading" @click="loadDevices()">刷新</NButton>
      </template>
      <NDataTable
        :columns="deviceColumns" :data="devices" :loading="loading"
        size="small" :bordered="false" :single-line="false" :scroll-x="620"
        :row-props="(r: PolicySummaryRow) => ({
          style: 'cursor:pointer',
          onClick: () => (selected = r.device_id),
        })"
        :row-class-name="(r: PolicySummaryRow) => (r.device_id === selected ? 'picked' : '')"
      />
      <div v-if="!devices.length && !loading" class="cy-empty">
        没有防火墙在同步策略。到<b>配置中心 → 网络设备</b>把 FortiGate 的
        「同步防火墙策略」打开 —— 映射和策略是同一次同步拿回来的。
      </div>
    </CyberPanel>

    <!-- ============ 映射表 ============ -->
    <CyberPanel
      v-if="current"
      :title="`${current.device_name} 的映射`"
      :subtitle="`${vips.length} 条 · 数据截止于 ${current.synced_at ? dateTimeOf(current.synced_at) : '从未同步'}`"
      flush
    >
      <!-- **「没有同步到映射」≠「这台防火墙没有映射」** ——
           前者是状态,后者是结论。我们分不出是真没有还是没拉到 -->
      <div v-if="!vipsLoading && !vips.length" class="note">
        这台防火墙<b>没有同步到映射</b>。这<b>不等于</b>「它没有配映射」——
        SSH 通道的 <code>show firewall vip</code> 可能没跑成,
        API 通道可能权限不够(那个端点会回 403)。要确认得登上去看一眼,
        或者点上面那台的「立即同步」再来。
      </div>

      <div v-if="summary?.whole_host.count" class="note warn">
        <b>{{ summary.whole_host.count }} 条整机映射</b> ——
        <code>portforward</code> 关着,外网地址的<b>所有端口</b>都通到内网那台机器上。
        它在表里和一条只映射 443 的规则长得几乎一样,所以单独标出来了。
      </div>

      <div class="filters">
        <NInput
          v-model:value="keyword" size="small" clearable
          placeholder="搜名称 / 外部地址 / 内部地址 / 备注" style="width: 260px"
        />
        <NSelect
          v-model:value="typeFilter" :options="typeOptions" size="small"
          style="width: 150px" clearable placeholder="全部类型"
        />
        <label class="tgl">
          <NSwitch v-model:value="wholeHostOnly" size="small" />
          <span>只看整机映射</span>
        </label>
        <label class="tgl">
          <NSwitch v-model:value="unusedOnly" size="small" />
          <span>只看没有策略引用的</span>
        </label>
      </div>

      <NDataTable
        :columns="vipColumns" :data="shown" :loading="vipsLoading"
        size="small" :bordered="false" :single-line="false" :scroll-x="900"
        :pagination="{ pageSize: 25, showSizePicker: true, pageSizes: [25, 50, 100] }"
      />
      <div v-if="vips.length && !shown.length" class="cy-empty">
        没有匹配的映射。清掉筛选条件试试。
      </div>
    </CyberPanel>
  </div>
</template>

<style scoped>
.mp { display: flex; flex-direction: column; gap: 14px; }

.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 10px;
}

.lead {
  font-size: 11.5px;
  line-height: 1.7;
  color: var(--cy-ink-2);
  padding: 7px 11px;
  border-left: 2px solid var(--cy-line);
  background: rgba(var(--cy-raised-rgb), 0.45);
}
.dim { color: var(--cy-ink-3); }
.lead code, .note code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10.5px;
  color: var(--cy-cyan);
}

.note {
  font-size: 11.5px;
  line-height: 1.65;
  color: var(--cy-ink-2);
  padding: 6px 11px;
  margin-bottom: 10px;
  border-left: 2px solid var(--cy-line);
  background: rgba(var(--cy-raised-rgb), 0.5);
}
.note.warn {
  color: var(--cy-degraded);
  border-left-color: var(--cy-degraded);
  background: rgba(var(--cy-degraded-rgb), 0.06);
}

.filters {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}
.tgl { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: var(--cy-ink-2); }

:deep(.picked td) { background: rgba(var(--cy-cyan-rgb), 0.07) !important; }
</style>
