<script setup lang="ts">
import { computed, h, onMounted, ref, watch } from 'vue'
import {
  NButton, NDataTable, NInput, NModal, NSelect, NSpace, NSwitch, NTag, useMessage,
} from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import StateDot from '@/components/cyber/StateDot.vue'
import { api, errText } from '@/api'
import type { DeviceRow, LookupResult, NeighborRow, NeighborSummaryRow, TopologyLink } from '@/api'
import { ago, dateTimeOf } from '@/composables/useFormat'
import { STATE } from '@/theme'

/**
 * 邻居 / 拓扑 / 地址查找 —— 网络工程师排障时最先要的三样东西。
 *
 * 1. **「这个口对面接的是谁」**(LLDP / CDP)。一个口 down 了对面是谁?
 *    一台机器失联了它挂在哪台交换机的哪个口上?这个口能不能停?
 * 2. **受管链路**:两端都在这个平台管着的链路,那些才画得成拓扑。
 * 3. **「这个 MAC / IP 在哪个口上」**:交换机排障问得最多的一句话。
 *
 * ## 三处「不知道」必须和「没有」分开
 *
 * - 走 API/SSH 通道的设备**采不到邻居**(那两张表是 SNMP MIB)。
 *   它的"0 条邻居"不等于"这些口没接线" —— 页面上标出通道
 * - LLDP 的本地口解析不出 ifIndex 时,那条邻居**不知道挂在哪个口**。
 *   标成「口未解析」,而不是挂到一个猜的口上
 * - MAC 查找里桥端口号没翻成 ifIndex 时,给出的是**桥端口号**,
 *   不是接口号。照着它去拔线会拔错 —— 所以那一行有红字
 *
 * ## 单向确认的链路要单独看
 *
 * 同一条物理链路两端各上报一次,合并成一条。只有一端确认时:可能是对端
 * 没开 LLDP,也可能是我们把邻居挂到了错误的本地口上 —— **后者是要去查的**。
 */

const message = useMessage()

const loading = ref(false)
const summary = ref<NeighborSummaryRow[]>([])
const selected = ref<number | null>(null)

const rows = ref<NeighborRow[]>([])
const rowsLoading = ref(false)
const total = ref(0)
const page = ref(1)
const keyword = ref('')
const managedOnly = ref(false)
const changedOnly = ref(false)
const busy = ref(0)

// 拓扑
const links = ref<TopologyLink[]>([])
const topoStats = ref<{ total: number; bidirectional: number; one_way: number; one_way_hint: string } | null>(null)

// 地址查找
const lookupOpen = ref(false)
const lookupQuery = ref('')
const lookupDevices = ref<number[]>([])
const lookupResult = ref<LookupResult | null>(null)
const lookupBusy = ref(false)
const allDevices = ref<DeviceRow[]>([])

const current = computed(() => summary.value.find((s) => s.device_id === selected.value) || null)
const totals = computed(() => {
  const list = summary.value
  return {
    devices: list.length,
    neighbors: list.reduce((a, b) => a + b.total, 0),
    managed: list.reduce((a, b) => a + b.managed, 0),
    changed: list.reduce((a, b) => a + b.changed, 0),
    unresolved: list.reduce((a, b) => a + b.unresolved, 0),
  }
})

async function loadSummary() {
  loading.value = true
  try {
    const [s, t, d] = await Promise.all([
      api.neighborSummary(), api.topology(), api.devices({ page_size: 200, ordering: 'order' }),
    ])
    summary.value = s.data.devices
    links.value = t.data.links
    topoStats.value = {
      total: t.data.total, bidirectional: t.data.bidirectional,
      one_way: t.data.one_way, one_way_hint: t.data.one_way_hint,
    }
    allDevices.value = d.data.results
    if (selected.value === null && summary.value.length) {
      selected.value = summary.value[0].device_id
    }
  } catch (e) {
    message.error(errText(e))
  } finally {
    loading.value = false
  }
}

async function loadRows() {
  if (selected.value === null) { rows.value = []; return }
  rowsLoading.value = true
  try {
    const { data } = await api.neighbors({
      device: selected.value, page: page.value, page_size: 50,
      keyword: keyword.value || undefined,
      managed_only: managedOnly.value ? false : undefined,
      changed: changedOnly.value ? false : undefined,
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
})

watch([selected, keyword, managedOnly, changedOnly], () => { page.value = 1; void loadRows() })
watch(page, () => void loadRows())

async function discover(deviceId: number) {
  busy.value = deviceId
  try {
    const { data } = await api.discoverNeighbors(deviceId)
    if (data.ok) message.success(data.detail, { duration: 9000 })
    else message.error(data.detail, { duration: 12000 })
    await loadSummary()
    await loadRows()
  } catch (e) {
    message.error(errText(e))
  } finally {
    busy.value = 0
  }
}

async function runLookup() {
  lookupBusy.value = true
  lookupResult.value = null
  try {
    const { data } = await api.macLookup(lookupQuery.value, lookupDevices.value)
    lookupResult.value = data
  } catch (e) {
    message.error(errText(e))
  } finally {
    lookupBusy.value = false
  }
}

const deviceOptions = computed(() =>
  allDevices.value.map((d) => ({ label: `${d.name}(${d.mgmt_ip})`, value: d.id })),
)

const summaryColumns: DataTableColumns<NeighborSummaryRow> = [
  { title: '设备', key: 'device_name', minWidth: 160,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, r.device_name),
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
        `${r.mgmt_ip} · ${r.model_label}`),
    ]) },
  { title: '状态', key: 'state', width: 82,
    render: (r) => h(StateDot, { state: r.state, label: true }) },
  { title: '邻居数', key: 'total', width: 118,
    render: (r) => {
      // **走 API/SSH 通道的设备采不到邻居**(那两张表是 SNMP MIB)。
      // 它的 0 条不等于"这些口没接线" —— 必须说出来
      if (!r.snmp_channel) {
        return h('span', {
          style: 'font-size:10.5px;color:var(--cy-ink-3)',
          title: `这台设备实际走 ${r.method.toUpperCase()} 通道,而 LLDP/CDP 是 SNMP MIB —— 采不到不等于没接线`,
        }, `— ${r.method.toUpperCase()} 通道`)
      }
      return h('div', { style: 'display:flex;gap:5px;align-items:baseline' }, [
        h('b', { style: 'font-size:13px;color:var(--cy-ink)' }, String(r.total)),
        h('span', { style: 'font-size:10px;color:var(--cy-ink-3)' },
          `LLDP ${r.lldp} / CDP ${r.cdp}`),
      ])
    } },
  { title: '受管对端', key: 'managed', width: 82, className: 'num',
    render: (r) => h('span', {
      style: `font-size:11.5px;color:${r.managed ? 'var(--cy-cyan)' : 'var(--cy-ink-3)'}`,
      title: '对端也是这个平台在管的设备 —— 这些能画成拓扑',
    }, r.managed ? String(r.managed) : '—') },
  { title: '口未解析', key: 'unresolved', width: 88, className: 'num',
    render: (r) => h('span', {
      style: `font-size:11.5px;color:${r.unresolved ? STATE.degraded : 'var(--cy-ink-3)'}`,
      title: 'LLDP 的本地口号没能翻成 ifIndex —— 这些邻居不知道挂在哪个口',
    }, r.unresolved ? String(r.unresolved) : '—') },
  { title: '曾变化', key: 'changed', width: 78, className: 'num',
    render: (r) => h('span', {
      style: `font-size:11.5px;color:${r.changed ? STATE.degraded : 'var(--cy-ink-3)'}`,
      title: '对端换过 —— 通常意味着有人动了线',
    }, r.changed ? String(r.changed) : '—') },
  { title: '最后采集', key: 'last_collected_at', width: 92,
    render: (r) => h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' },
      ago(r.last_collected_at)) },
  { title: '操作', key: 'act', width: 168, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', ghost: true,
        type: selected.value === r.device_id ? 'primary' : 'default',
        onClick: () => { selected.value = r.device_id } }, () => '看邻居'),
      h(NButton, { size: 'tiny', ghost: true, loading: busy.value === r.device_id,
        onClick: () => discover(r.device_id) }, () => '立即发现'),
    ]) },
]

const neighborColumns: DataTableColumns<NeighborRow> = [
  { title: '本端接口', key: 'local_if_name', minWidth: 168,
    render: (r) => h('div', [
      h('div', { style: "font-size:12px;color:var(--cy-ink);font-family:'JetBrains Mono',monospace" },
        r.local_if_name),
      // 解析不出 ifIndex 时说明"不知道挂在哪个口" —— 不能让人以为知道
      r.local_resolved
        ? h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' }, `ifIndex ${r.local_if_index}`)
        : h('div', {
            style: `font-size:10px;color:${STATE.degraded}`,
            title: 'LLDP 的本地口号没能翻成 ifIndex,也没在接口表里找到同名口 —— 这条邻居不确定挂在哪个口',
          }, '口未解析'),
    ]) },
  { title: '协议', key: 'protocol', width: 62,
    render: (r) => h(NTag, { size: 'tiny', bordered: false,
      type: r.protocol === 'lldp' ? 'info' : 'default' }, () => r.protocol.toUpperCase()) },
  { title: '对端设备', key: 'remote_device', minWidth: 175,
    render: (r) => h('div', [
      h('div', { style: 'display:flex;gap:5px;align-items:baseline;flex-wrap:wrap' }, [
        h('span', { style: 'font-size:12px;color:var(--cy-ink)' }, r.remote_device || '(未上报名字)'),
        r.matched_device
          ? h(NTag, { size: 'tiny', bordered: false, type: 'success',
              title: '对端也是这个平台在管的设备' }, () => '已纳管')
          : null,
      ]),
      r.remote_mgmt_ip
        ? h('div', { style: "font-size:10px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
            r.remote_mgmt_ip)
        : null,
    ]) },
  { title: '对端接口', key: 'remote_port', minWidth: 140,
    render: (r) => h('span', { style: "font-size:11.5px;font-family:'JetBrains Mono',monospace;color:var(--cy-ink-2)" },
      r.remote_port || '—') },
  { title: '对端平台', key: 'remote_platform', minWidth: 180,
    render: (r) => h('span', {
      style: 'font-size:10.5px;color:var(--cy-ink-3);line-height:1.45',
      title: r.remote_platform,
    }, r.remote_platform || '—') },
  { title: '最后确认', key: 'last_seen', width: 92,
    render: (r) => h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' }, ago(r.last_seen)) },
  { title: '变化', key: 'changed_at', width: 92,
    render: (r) => r.changed_at
      ? h('span', {
          style: `font-size:10.5px;color:${STATE.degraded}`,
          title: `对端换过,最后一次是 ${dateTimeOf(r.changed_at)} —— 通常意味着有人动了线`,
        }, ago(r.changed_at))
      : h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' }, '未变'),
  },
]

const linkColumns: DataTableColumns<TopologyLink> = [
  { title: 'A 端', key: 'a', minWidth: 200,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12px;color:var(--cy-ink)' }, r.a_device),
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
        r.a_port),
    ]) },
  { title: '', key: 'arrow', width: 52,
    render: (r) => h('span', {
      style: `font-size:14px;color:${r.bidirectional ? 'var(--cy-cyan)' : STATE.degraded}`,
      title: r.bidirectional ? '两端都确认了这条链路' : '只有一端确认',
    }, r.bidirectional ? '⇄' : '→') },
  { title: 'B 端', key: 'b', minWidth: 200,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12px;color:var(--cy-ink)' }, r.b_device),
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
        r.b_port),
    ]) },
  { title: '协议', key: 'protocol', width: 62,
    render: (r) => h(NTag, { size: 'tiny', bordered: false }, () => r.protocol.toUpperCase()) },
  { title: '确认', key: 'bidirectional', width: 128,
    render: (r) => r.bidirectional
      ? h('span', { style: `font-size:11px;color:${STATE.up}` }, '双向确认')
      : h('span', {
          style: `font-size:11px;color:${STATE.degraded}`,
          title: '只有 ' + r.confirmed_by.join('/') + ' 上报了这条链路 —— 可能对端没开 LLDP,'
            + '也可能邻居被挂到了错误的本地口上',
        }, `单向(${r.confirmed_by[0]})`),
  },
  { title: '变化', key: 'changed_at', width: 92,
    render: (r) => h('span', {
      style: `font-size:10.5px;color:${r.changed_at ? STATE.degraded : 'var(--cy-ink-3)'}`,
    }, r.changed_at ? ago(r.changed_at) : '未变') },
]
</script>

<template>
  <div class="topo">
    <div class="tiles">
      <StatTile label="设备" :value="totals.devices" unit="台" :dim-zero="false"
                foot="开了邻居发现的" />
      <StatTile label="邻居关系" :value="totals.neighbors" unit="条" :dim-zero="false"
                foot="LLDP + CDP 两套都采" />
      <StatTile label="受管链路" :value="topoStats?.total ?? null" unit="条"
                :dim-zero="false"
                :foot="topoStats ? `双向确认 ${topoStats.bidirectional} / 单向 ${topoStats.one_way}` : ''" />
      <StatTile label="曾变化" :value="totals.changed" unit="条" :color="STATE.degraded"
                foot="对端换过 —— 通常是有人动了线" />
      <StatTile label="口未解析" :value="totals.unresolved" unit="条" :color="STATE.degraded"
                foot="不确定挂在哪个口,不是挂在 0 口" />
    </div>

    <!-- ============ 地址查找 ============ -->
    <CyberPanel
      title="地址查找"
      subtitle="「这个 MAC / IP 在哪台交换机的哪个口上」—— 现场去设备上查,不是查本地缓存"
    >
      <template #actions>
        <NButton size="tiny" ghost @click="lookupOpen = !lookupOpen">
          {{ lookupOpen ? '收起' : '展开' }}
        </NButton>
      </template>
      <div v-if="lookupOpen" class="lookup">
        <div class="lk-form">
          <NInput
            v-model:value="lookupQuery" size="small" clearable style="width: 240px"
            placeholder="aa:bb:cc:dd:ee:ff 或 10.20.0.5"
            @keyup.enter="runLookup()"
          />
          <NSelect
            v-model:value="lookupDevices" :options="deviceOptions" multiple filterable
            size="small" style="min-width: 300px; flex: 1" placeholder="选要查的设备(可多选)"
          />
          <NButton size="small" type="primary" ghost :loading="lookupBusy"
                   :disabled="!lookupQuery || !lookupDevices.length" @click="runLookup()">
            查找
          </NButton>
        </div>
        <div class="lk-hint">
          MAC 表大而易变,所以这里是**现场查询**,一台设备 1~5 秒,要显式选设备。<br>
          查 IP 是两段式:先在选中的设备里找 ARP 拿到 MAC(**只有三层设备有** ——
          把网关那台选上),再拿 MAC 去找口。
        </div>

        <template v-if="lookupResult">
          <div class="lk-res">
            <div class="lk-line">
              查 <b class="cy-mono">{{ lookupResult.query }}</b>
              <template v-if="lookupResult.mac">
                → MAC <b class="cy-mono">{{ lookupResult.mac }}</b>
              </template>
              <span class="dim">· 查了 {{ lookupResult.searched }} 台</span>
            </div>
            <div v-for="a in lookupResult.arp" :key="`arp-${a.device_id}`" class="lk-arp">
              ARP:{{ a.device_name }} 的 {{ a.if_name || `ifIndex ${a.if_index}` }} 上学到了它
            </div>
            <div v-if="lookupResult.detail" class="lk-none">{{ lookupResult.detail }}</div>
            <div v-if="lookupResult.multi_note" class="lk-warn">{{ lookupResult.multi_note }}</div>
            <div v-for="(h, i) in lookupResult.hits" :key="i" class="lk-hit">
              <span class="lk-dev">{{ h.device_name }}</span>
              <span class="lk-port cy-mono">{{ h.if_name || `桥端口 ${h.bridge_port}` }}</span>
              <span v-if="h.vlan" class="lk-vlan cy-mono">VLAN {{ h.vlan }}</span>
              <span class="lk-src">{{ h.source }}</span>
              <span v-if="!h.port_resolved" class="lk-bad">{{ h.note }}</span>
            </div>
            <div v-for="(e, i) in lookupResult.errors" :key="`e-${i}`" class="lk-err">
              {{ e.device }}:{{ e.error }}
            </div>
          </div>
        </template>
      </div>
    </CyberPanel>

    <!-- ============ 设备汇总 ============ -->
    <CyberPanel title="邻居发现" subtitle="LLDP + CDP 两套都采 —— 纯 Cisco 环境里往往只开了 CDP" flush>
      <template #actions>
        <NButton size="small" ghost :loading="loading" @click="loadSummary()">刷新</NButton>
      </template>
      <NDataTable
        :columns="summaryColumns" :data="summary" :loading="loading"
        size="small" :bordered="false" :single-line="false" :scroll-x="1060"
      />
      <div v-if="!summary.length && !loading" class="cy-empty">
        没有设备在采邻居。到<b>配置中心 → 网络设备</b>打开「采集邻居(LLDP/CDP)」。<br>
        <b>只有 SNMP 通道采得到</b> —— LLDP-MIB 和 CISCO-CDP-MIB 都是 SNMP MIB,
        走 API/SSH 的设备拿不到。
      </div>
    </CyberPanel>

    <!-- ============ 受管链路 ============ -->
    <CyberPanel
      v-if="links.length"
      title="受管链路"
      :subtitle="`${topoStats?.total ?? 0} 条 · 两端都在这个平台管着的那些`"
      flush
    >
      <template #actions>
        <span v-if="topoStats?.one_way" class="warn-inline">⚠ {{ topoStats.one_way_hint }}</span>
      </template>
      <NDataTable
        :columns="linkColumns" :data="links" :loading="loading"
        size="small" :bordered="false" :single-line="false" :scroll-x="860"
        :pagination="{ pageSize: 15 }"
      />
    </CyberPanel>

    <!-- ============ 某台设备的邻居明细 ============ -->
    <CyberPanel
      v-if="current"
      :title="`${current.device_name} 的邻居`"
      :subtitle="`${total} 条 · 采集于 ${current.last_collected_at ? dateTimeOf(current.last_collected_at) : '从未'}`"
      flush
    >
      <template #actions>
        <a :href="api.neighborExportUrl({ device: selected })" class="csv-link" download>
          导出 CSV
        </a>
      </template>
      <div class="filters">
        <NInput v-model:value="keyword" size="small" clearable style="width: 220px"
                placeholder="搜本地口 / 对端 / 平台" />
        <label class="tgl">
          <NSwitch v-model:value="managedOnly" size="small" />
          <span>只看受管对端</span>
        </label>
        <label class="tgl">
          <NSwitch v-model:value="changedOnly" size="small" />
          <span>只看变化过的</span>
        </label>
      </div>
      <NDataTable
        :columns="neighborColumns" :data="rows" :loading="rowsLoading"
        size="small" :bordered="false" :single-line="false" :scroll-x="1080"
        :pagination="{
          page, pageSize: 50, itemCount: total,
          onUpdatePage: (p: number) => (page = p),
        }"
        remote
      />
      <div v-if="!rows.length && !rowsLoading" class="cy-empty">
        <template v-if="!current.snmp_channel">
          这台设备实际走 <b>{{ current.method.toUpperCase() }}</b> 通道,而 LLDP/CDP 是
          SNMP MIB —— <b>采不到不等于这些口没接线</b>。要邻居就给它配一条 SNMP 通道
          (主通道或降级通道都行)。
        </template>
        <template v-else>
          一条邻居都没有。可能是:对端没开 LLDP/CDP、community 的 view 没放开这两个 MIB、
          或者还没到第一个采集周期(点上面那台设备的「立即发现」现场试一次)。
        </template>
      </div>
    </CyberPanel>
  </div>
</template>

<style scoped>
.topo { display: flex; flex-direction: column; gap: 14px; }
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 10px;
}
.warn-inline { font-size: 10.5px; color: var(--cy-degraded); line-height: 1.5; max-width: 500px; }
.dim { color: var(--cy-ink-3); }

.lookup { display: flex; flex-direction: column; gap: 9px; }
.lk-form { display: flex; gap: 9px; align-items: center; flex-wrap: wrap; }
.lk-hint { font-size: 10.5px; color: var(--cy-ink-3); line-height: 1.6; }
.lk-res {
  margin-top: 4px;
  padding: 9px 11px;
  background: rgba(var(--cy-raised-rgb), 0.6);
  border-left: 2px solid rgba(var(--cy-cyan-rgb), 0.45);
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.lk-line { font-size: 12px; color: var(--cy-ink-2); }
.lk-arp { font-size: 11px; color: var(--cy-ink-2); }
.lk-hit {
  display: flex;
  gap: 10px;
  align-items: baseline;
  font-size: 11.5px;
  flex-wrap: wrap;
  padding: 2px 0;
  border-top: 1px solid rgba(var(--cy-cyan-rgb), 0.1);
}
.lk-dev { color: var(--cy-ink); font-weight: 600; }
.lk-port { color: var(--cy-cyan); font-size: 12px; }
.lk-vlan { color: var(--cy-ink-2); font-size: 10.5px; }
.lk-src { color: var(--cy-ink-3); font-size: 10px; }
.lk-bad { color: var(--cy-down); font-size: 10.5px; flex: 1 1 100%; line-height: 1.5; }
.lk-none { font-size: 11px; color: var(--cy-ink-3); line-height: 1.6; }
.lk-warn { font-size: 11px; color: var(--cy-degraded); line-height: 1.6; }
.lk-err { font-size: 10.5px; color: var(--cy-down); }

.filters { display: flex; gap: 9px; align-items: center; flex-wrap: wrap; padding: 9px 12px 3px; }
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
  transition: background 0.15s ease;
}
.csv-link:hover { background: rgba(var(--cy-cyan-rgb), 0.12); }
</style>
