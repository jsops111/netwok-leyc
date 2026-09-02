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
import type { PolicyRow, PolicySummaryRow } from '@/api'
import { useMetaStore } from '@/stores/meta'
import { ago, bytes, dateTimeOf, int } from '@/composables/useFormat'
import { STATE } from '@/theme'

/**
 * 防火墙策略页 —— 看设备上**现有**的规则。
 *
 * ## 三件必须在界面上说清楚的事
 *
 * 1. **顺序就是语义。**防火墙先匹配先生效,所以默认按设备上的顺序排,
 *    不按命中数排。要按命中数排得显式点那一列。
 *
 * 2. **命中数为空 ≠ 没命中过。**只有 API 通道拿得到命中计数(FortiOS 的
 *    monitor 端点);SSH 通道只有配置。所以"从未命中"这个筛选只在
 *    `has_hit_stats` 为真时才有意义 —— 把"不知道"当成"没命中"会让人
 *    删掉一条其实在用的规则。这一页把这件事显式写在顶部。
 *
 * 3. **数据是快照,有截止时间。**设备连不上的时候这一页还能看,
 *    但必须标明"数据截止于什么时候" —— 防火墙不通恰恰是最需要查规则的时候。
 */

const message = useMessage()
const meta = useMetaStore()

const loading = ref(false)
const summary = ref<PolicySummaryRow[]>([])
const selected = ref<number | null>(null)

const policies = ref<PolicyRow[]>([])
const policiesLoading = ref(false)
const total = ref(0)
const page = ref(1)
const pageSize = ref(25)
const busy = ref(0)

// 筛选
const keyword = ref('')
const actionFilter = ref<string | null>(null)
const enabledFilter = ref<boolean | null>(null)
const neverHitOnly = ref(false)
const ordering = ref('seq')

const detailOpen = ref(false)
const detail = ref<PolicyRow | null>(null)

const current = computed(() => summary.value.find((s) => s.device_id === selected.value) || null)
const totals = computed(() => {
  const list = summary.value
  return {
    devices: list.length,
    policies: list.reduce((a, b) => a + b.total, 0),
    disabled: list.reduce((a, b) => a + b.disabled, 0),
    // 各设备的"从未命中"求和时**跳过没有命中统计的设备** ——
    // 把它们当 0 会把这个数说小,而这个数是拿去清理规则的
    neverHit: list.some((s) => s.has_hit_stats)
      ? list.reduce((a, b) => a + (b.never_hit ?? 0), 0)
      : null,
  }
})

async function loadSummary() {
  loading.value = true
  try {
    const { data } = await api.policySummary()
    summary.value = data.devices
    if (selected.value === null && data.devices.length) {
      selected.value = data.devices[0].device_id
    }
  } catch (e) {
    message.error(errText(e))
  } finally {
    loading.value = false
  }
}

async function loadPolicies() {
  if (selected.value === null) {
    policies.value = []
    return
  }
  policiesLoading.value = true
  try {
    const { data } = await api.policies({
      device: selected.value,
      page: page.value,
      page_size: pageSize.value,
      ordering: ordering.value,
      keyword: keyword.value || undefined,
      action: actionFilter.value || undefined,
      enabled: enabledFilter.value === null ? undefined : enabledFilter.value,
      never_hit: neverHitOnly.value ? true : undefined,
    })
    policies.value = data.results
    total.value = data.count
  } catch (e) {
    message.error(errText(e))
  } finally {
    policiesLoading.value = false
  }
}

onMounted(async () => {
  await meta.load()
  await loadSummary()
  await loadPolicies()
})

// 换设备/换筛选都回到第一页 —— 停在第 7 页看另一台设备是没有意义的
watch([selected, keyword, actionFilter, enabledFilter, neverHitOnly, ordering], () => {
  page.value = 1
  void loadPolicies()
})
watch([page, pageSize], () => void loadPolicies())

async function syncNow(deviceId: number) {
  busy.value = deviceId
  try {
    const { data } = await api.syncPoliciesNow(deviceId)
    message.success(data.detail)
  } catch (e) {
    message.error(errText(e))
  } finally {
    busy.value = 0
  }
}

function openDetail(row: PolicyRow) {
  detail.value = row
  detailOpen.value = true
  // raw 只在 detail 接口里,列表接口不带 —— 单独取一次
  void api.policy(row.id).then(({ data }) => { detail.value = data }).catch(() => {})
}

const ACTION_COLORS: Record<string, string> = {
  accept: STATE.up,
  deny: STATE.down,
  ipsec: 'var(--cy-violet)',
  other: STATE.unknown,
}

const ORDER_OPTIONS = [
  { label: '按设备顺序(默认)', value: 'seq' },
  { label: '命中最多在前', value: '-hit_count' },
  { label: '命中最少在前', value: 'hit_count' },
  { label: '流量最多在前', value: '-bytes_count' },
  { label: '最近命中在前', value: '-last_hit_at' },
]

/** 地址/服务是数组,列表里挤不下,超过两项折起来。 */
function listCell(values: string[], emptyText = '—') {
  if (!values?.length) {
    return h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, emptyText)
  }
  const head = values.slice(0, 2)
  const rest = values.length - head.length
  return h('div', { style: 'display:flex;flex-direction:column;gap:1px' }, [
    ...head.map((v) =>
      h('span', {
        style: "font-size:10.5px;font-family:'JetBrains Mono',monospace;color:var(--cy-ink-2);"
          + 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap',
        title: values.join(', '),
      }, v),
    ),
    rest > 0
      ? h('span', { style: 'font-size:10px;color:var(--cy-ink-3)', title: values.join(', ') },
          `还有 ${rest} 项`)
      : null,
  ])
}

const summaryColumns: DataTableColumns<PolicySummaryRow> = [
  { title: '防火墙', key: 'device_name', minWidth: 150,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, r.device_name),
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
        `${r.mgmt_ip} · VDOM ${r.vdom}`),
    ]) },
  { title: '状态', key: 'state', width: 82,
    render: (r) => h(StateDot, { state: r.state, label: true }) },
  { title: '策略数', key: 'total', width: 78, className: 'num',
    render: (r) => h('span', { style: 'font-size:12px;font-weight:700' }, int(r.total)) },
  { title: '允许 / 拒绝', key: 'split', width: 108,
    render: (r) => h('span', { style: "font-size:11.5px;font-family:'JetBrains Mono',monospace" }, [
      h('span', { style: `color:${STATE.up}` }, String(r.accept)),
      h('span', { style: 'color:var(--cy-ink-3)' }, ' / '),
      h('span', { style: `color:${STATE.down}` }, String(r.deny)),
    ]) },
  { title: '已停用', key: 'disabled', width: 74, className: 'num',
    render: (r) => h('span', {
      style: `font-size:11.5px;color:${r.disabled ? STATE.degraded : 'var(--cy-ink-3)'}`,
    }, r.disabled ? int(r.disabled) : '—') },
  { title: '从未命中', key: 'never_hit', width: 96, className: 'num',
    render: (r) => {
      // **null = 没有命中统计**(SSH 通道)。显示"无统计"而不是 0 ——
      // 0 会被读成"所有规则都在用",而真相是我们不知道
      if (r.never_hit === null) {
        return h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' }, '无统计')
      }
      return h('span', {
        style: `font-size:11.5px;font-weight:700;color:${r.never_hit ? STATE.degraded : STATE.up}`,
      }, int(r.never_hit))
    } },
  { title: '同步', key: 'synced_at', minWidth: 150,
    render: (r) => h('div', [
      h('div', { style: 'font-size:11px;color:var(--cy-ink-2)' },
        r.synced_at ? ago(r.synced_at) : '从未同步'),
      h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' }, `每 ${r.interval_minutes} 分钟`),
      r.error
        ? h('div', { style: `font-size:10px;color:${STATE.down};line-height:1.5` }, r.error)
        : null,
    ]) },
  { title: '操作', key: 'act', width: 152, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', ghost: true,
        type: selected.value === r.device_id ? 'primary' : 'default',
        onClick: () => { selected.value = r.device_id } }, () => '看规则'),
      h(NButton, { size: 'tiny', ghost: true, loading: busy.value === r.device_id,
        onClick: () => syncNow(r.device_id) }, () => '立即同步'),
    ]) },
]

const policyColumns: DataTableColumns<PolicyRow> = [
  { title: '#', key: 'seq', width: 52, className: 'num',
    render: (r) => h('span', {
      style: "font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--cy-ink-3)",
      title: '设备上的先后顺序 —— 防火墙先匹配先生效',
    }, String(r.seq + 1)) },
  { title: 'ID', key: 'policy_id', width: 58, className: 'num',
    render: (r) => h('span', {
      style: "font-size:11px;font-family:'JetBrains Mono',monospace",
    }, String(r.policy_id)) },
  { title: '名称', key: 'name', minWidth: 132,
    render: (r) => h('div', [
      h('div', { style: 'font-size:11.5px;color:var(--cy-ink)' }, r.name || '(未命名)'),
      r.comments
        ? h('div', { style: 'font-size:10px;color:var(--cy-ink-3);line-height:1.4' }, r.comments)
        : null,
    ]) },
  { title: '源', key: 'src', minWidth: 130,
    render: (r) => h('div', [listCell(r.src_intf, 'any'), listCell(r.src_addr, 'any')]) },
  { title: '目的', key: 'dst', minWidth: 130,
    render: (r) => h('div', [listCell(r.dst_intf, 'any'), listCell(r.dst_addr, 'any')]) },
  { title: '服务', key: 'service', minWidth: 104,
    render: (r) => listCell(r.service, 'ALL') },
  { title: '动作', key: 'action', width: 76,
    render: (r) => h(NTag, {
      size: 'tiny', bordered: false,
      style: `color:${ACTION_COLORS[r.action] || STATE.unknown};`
        + `border:1px solid ${ACTION_COLORS[r.action] || STATE.unknown}`,
    }, () => r.action_label) },
  { title: 'NAT', key: 'nat', width: 54,
    render: (r) => h('span', {
      style: `font-size:11px;color:${r.nat ? 'var(--cy-cyan)' : 'var(--cy-ink-3)'}`,
    }, r.nat ? '开' : '—') },
  { title: '启用', key: 'enabled', width: 62,
    render: (r) => r.enabled
      ? h('span', { style: `font-size:11px;color:${STATE.up}` }, '启用')
      : h('span', { style: `font-size:11px;color:${STATE.degraded};font-weight:700` }, '已停用') },
  { title: '命中', key: 'hit_count', width: 112, className: 'num',
    render: (r) => {
      // 三态。**null 显示「未知」,不显示 0** —— 见文件头第 2 条
      if (r.hit_count === null) {
        return h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)', title: 'SSH 通道拿不到命中计数' }, '未知')
      }
      return h('div', [
        h('div', {
          style: `font-size:11.5px;font-family:'JetBrains Mono',monospace;font-weight:700;`
            + `color:${r.hit_count === 0 ? STATE.degraded : 'var(--cy-ink)'}`,
        }, r.hit_count === 0 ? '从未命中' : int(r.hit_count)),
        r.bytes_count
          ? h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' }, bytes(r.bytes_count))
          : null,
      ])
    } },
  { title: '最后命中', key: 'last_hit_at', width: 96,
    render: (r) => h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' },
      r.last_hit_at ? ago(r.last_hit_at) : '—') },
  { title: '', key: 'act', width: 62, fixed: 'right',
    render: (r) => h(NButton, { size: 'tiny', text: true, type: 'primary',
      onClick: () => openDetail(r) }, () => '详情') },
]

const actionOptions = computed(() => [
  { label: '全部动作', value: '' },
  ...meta.options('policy_action'),
])
</script>

<template>
  <div class="pol">
    <!-- ============ 顶部统计 ============ -->
    <div class="tiles">
      <StatTile label="防火墙" :value="totals.devices" unit="台" :dim-zero="false"
                foot="已开启策略同步的" />
      <StatTile label="策略总数" :value="totals.policies" unit="条" :dim-zero="false" />
      <StatTile label="已停用规则" :value="totals.disabled" unit="条" :color="STATE.degraded"
                foot="留在设备上但不生效" />
      <StatTile
        label="从未命中"
        :value="totals.neverHit"
        unit="条"
        :color="STATE.degraded"
        :foot="totals.neverHit === null
          ? '没有命中统计 —— 需要 API 通道'
          : '可以考虑清理的候选'"
      />
    </div>

    <!-- ============ 设备汇总 ============ -->
    <CyberPanel title="防火墙策略" subtitle="设备上现有的规则快照 —— 全量替换式同步,设备上删掉的这里也会消失" flush>
      <template #actions>
        <NButton size="small" ghost :loading="loading" @click="loadSummary()">刷新</NButton>
      </template>
      <NDataTable
        :columns="summaryColumns" :data="summary" :loading="loading"
        size="small" :bordered="false" :single-line="false" :scroll-x="1000"
      />
      <div v-if="!summary.length && !loading" class="cy-empty">
        还没有防火墙开启策略同步。到<b>配置中心 → 网络设备</b>编辑一台
        <b>类型为防火墙</b>的 FortiGate,打开「同步防火墙策略」。<br>
        <b>强烈建议配 API Token</b>:只有 REST API 拿得到命中计数,而
        「这条规则从来没命中过」是这一页最有价值的结论 —— SSH 通道只能看到配置。
      </div>
    </CyberPanel>

    <!-- ============ 规则表 ============ -->
    <CyberPanel
      v-if="current"
      :title="`${current.device_name} 的策略`"
      :subtitle="`${total} 条 · 数据截止于 ${current.synced_at ? dateTimeOf(current.synced_at) : '从未同步'}`"
      flush
    >
      <template #actions>
        <span v-if="!current.has_hit_stats" class="no-stats">
          ⚠ 这批数据没有命中统计(SSH 通道)—— 命中列显示「未知」,不要当成「没命中」
        </span>
      </template>

      <div class="filters">
        <NInput
          v-model:value="keyword" size="small" clearable placeholder="搜名称 / 地址 / 服务 / 备注"
          style="width: 240px"
        />
        <NSelect
          :value="actionFilter || ''" :options="actionOptions" size="small" style="width: 132px"
          @update:value="(v: string) => (actionFilter = v || null)"
        />
        <NSelect
          :value="enabledFilter === null ? '' : String(enabledFilter)"
          :options="[
            { label: '启用与停用', value: '' },
            { label: '仅启用', value: 'true' },
            { label: '仅已停用', value: 'false' },
          ]"
          size="small" style="width: 128px"
          @update:value="(v: string) => (enabledFilter = v === '' ? null : v === 'true')"
        />
        <NSelect v-model:value="ordering" :options="ORDER_OPTIONS" size="small" style="width: 180px" />
        <label class="never-toggle" :class="{ off: !current.has_hit_stats }">
          <NSwitch v-model:value="neverHitOnly" size="small" :disabled="!current.has_hit_stats" />
          <span>只看从未命中的</span>
        </label>
      </div>

      <NDataTable
        :columns="policyColumns" :data="policies" :loading="policiesLoading"
        size="small" :bordered="false" :single-line="false" :scroll-x="1300"
        :pagination="{
          page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [25, 50, 100],
          onUpdatePage: (p: number) => (page = p),
          onUpdatePageSize: (s: number) => { pageSize = s; page = 1 },
        }"
        remote
      />
      <div v-if="!policies.length && !policiesLoading" class="cy-empty">
        没有匹配的策略。清掉筛选条件,或者点「立即同步」拉一次 ——
        同步失败的原因会显示在上面那张表的「同步」列里。
      </div>
    </CyberPanel>

    <!-- ============ 详情 ============ -->
    <NModal
      v-model:show="detailOpen" preset="card" :bordered="false"
      :title="`策略 #${detail?.policy_id ?? ''} ${detail?.name || ''}`"
      style="width: min(860px, 95vw)"
    >
      <template v-if="detail">
        <div class="kv-grid">
          <div class="kv"><span>动作</span><b :style="{ color: ACTION_COLORS[detail.action] }">{{ detail.action_label }}</b></div>
          <div class="kv"><span>状态</span><b>{{ detail.enabled ? '启用' : '已停用' }}</b></div>
          <div class="kv"><span>NAT</span><b>{{ detail.nat ? '开' : '关' }}</b></div>
          <div class="kv"><span>生效时间</span><b>{{ detail.schedule || '—' }}</b></div>
          <div class="kv"><span>日志</span><b>{{ detail.log_traffic || '—' }}</b></div>
          <div class="kv"><span>VDOM</span><b>{{ detail.vdom }}</b></div>
          <div class="kv"><span>源接口</span><b class="cy-mono">{{ detail.src_intf.join(', ') || 'any' }}</b></div>
          <div class="kv"><span>目的接口</span><b class="cy-mono">{{ detail.dst_intf.join(', ') || 'any' }}</b></div>
          <div class="kv full"><span>源地址</span><b class="cy-mono">{{ detail.src_addr.join(', ') || 'any' }}</b></div>
          <div class="kv full"><span>目的地址</span><b class="cy-mono">{{ detail.dst_addr.join(', ') || 'any' }}</b></div>
          <div class="kv full"><span>服务</span><b class="cy-mono">{{ detail.service.join(', ') || 'ALL' }}</b></div>
          <div class="kv"><span>命中次数</span><b class="cy-mono">
            {{ detail.hit_count === null ? '未知(SSH 通道无统计)' : int(detail.hit_count) }}
          </b></div>
          <div class="kv"><span>字节 / 包</span><b class="cy-mono">
            {{ detail.bytes_count === null ? '未知' : bytes(detail.bytes_count) }}
            /
            {{ detail.packets === null ? '未知' : int(detail.packets) }}
          </b></div>
          <div class="kv"><span>活动会话</span><b class="cy-mono">
            {{ detail.sessions === null ? '未知' : int(detail.sessions) }}
          </b></div>
          <div class="kv"><span>最后命中</span><b class="cy-mono">
            {{ detail.last_hit_at ? dateTimeOf(detail.last_hit_at) : '—' }}
          </b></div>
          <div class="kv full"><span>UUID</span><b class="cy-mono">{{ detail.uuid || '—' }}</b></div>
          <div class="kv full"><span>备注</span><b>{{ detail.comments || '—' }}</b></div>
          <div class="kv full"><span>同步</span><b class="cy-mono">
            {{ dateTimeOf(detail.synced_at) }} · 通道 {{ detail.method.toUpperCase() }}
          </b></div>
        </div>

        <!-- FortiOS 的策略有上百个字段,上面只展示常看的十几个。
             剩下的原样放在这里 —— 丢掉它们会让"为什么这条规则不生效"
             这类问题查不下去 -->
        <div v-if="detail.raw" class="raw-head">设备返回的原始记录</div>
        <pre v-if="detail.raw" class="raw"><code>{{ JSON.stringify(detail.raw, null, 2) }}</code></pre>
      </template>
      <template #footer>
        <NSpace justify="end">
          <NButton size="small" @click="detailOpen = false">关闭</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.pol { display: flex; flex-direction: column; gap: 14px; }
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 10px;
}

.no-stats {
  font-size: 10.5px;
  color: var(--cy-degraded);
  line-height: 1.5;
  max-width: 480px;
}

.filters {
  display: flex;
  gap: 9px;
  align-items: center;
  flex-wrap: wrap;
  padding: 9px 12px 3px;
}
.never-toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11.5px;
  color: var(--cy-ink-2);
  cursor: pointer;
}
.never-toggle.off { color: var(--cy-ink-3); cursor: not-allowed; }

.kv-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
  gap: 4px 18px;
}
.kv {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  font-size: 11.5px;
  color: var(--cy-ink-3);
  padding: 3px 0;
  border-bottom: 1px solid rgba(var(--cy-cyan-rgb), 0.08);
  min-width: 0;
}
.kv.full { grid-column: 1 / -1; }
.kv b { color: var(--cy-ink-2); font-weight: 600; text-align: right; word-break: break-all; }

.raw-head {
  font-size: 11px;
  letter-spacing: 0.08em;
  color: var(--cy-cyan);
  margin: 14px 0 6px;
}
/* 数据区不加动画 —— 读 JSON 时底下在动会看错行 */
.raw {
  margin: 0;
  max-height: 40vh;
  overflow: auto;
  background: rgba(var(--cy-body-rgb), 0.6);
  border: 1px solid rgba(var(--cy-cyan-rgb), 0.14);
  padding: 9px 11px;
}
.raw code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  line-height: 1.6;
  color: var(--cy-ink-2);
  white-space: pre;
}
</style>
