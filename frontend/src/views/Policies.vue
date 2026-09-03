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
import type {
  AddressResolve, AddressRow, PolicyAudit, PolicyRow, PolicySummaryRow, VipSummary,
} from '@/api'
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

// 审计。**作为网络工程师真正要回答的问题**,不是展示字段:
// 有没有 any-any-any 放行、有没有规则永远匹配不到、有没有放行不记日志、
// 有没有从来没命中过的。前三项 SSH 通道也能判,最后一项要命中统计
const audit = ref<PolicyAudit | null>(null)
const auditLoading = ref(false)
const auditOpen = ref(false)
// 审计里点某条规则 → 把它筛到表格里
const permissiveOnly = ref(false)
const noLogOnly = ref(false)

// 映射(firewall vip)的**概览**。整张表在 /mappings 那一页 ——
// 这里只要那两个必须让人看见的数(整机映射 / 没有策略引用)
const vipsLoading = ref(false)
const vipSummary = ref<VipSummary | null>(null)

/**
 * 地址对象 / 地址组的**别名查询**。
 *
 * 策略表里的源/目的地址是一串**名字**(`内网服务器组`),
 * **它到底是哪几个网段完全不在策略表里** —— 这个框就是答案。
 * 地址组会递归展开(组能套组),给一棵树和一张拍平的叶子表。
 */
const addrQuery = ref('')
const addrResult = ref<AddressResolve | null>(null)
const addrLoading = ref(false)
const addrList = ref<AddressRow[]>([])
const addrListLoading = ref(false)
const addrOpen = ref(false)
const addrKeyword = ref('')
const groupOnly = ref(false)

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
    // 这两项不依赖命中统计 —— SSH 通道同步来的策略也能判
    wideOpen: list.reduce((a, b) => a + (b.wide_open ?? 0), 0),
    noLog: list.reduce((a, b) => a + (b.no_log ?? 0), 0),
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
      permissive: permissiveOnly.value ? true : undefined,
      no_log: noLogOnly.value ? true : undefined,
    })
    policies.value = data.results
    total.value = data.count
  } catch (e) {
    message.error(errText(e))
  } finally {
    policiesLoading.value = false
  }
}

async function loadAudit() {
  if (selected.value === null) { audit.value = null; return }
  auditLoading.value = true
  try {
    const { data } = await api.policyAudit(selected.value)
    audit.value = data
  } catch (e) {
    message.error(errText(e))
  } finally {
    auditLoading.value = false
  }
}

async function loadVips() {
  if (selected.value === null) { vipSummary.value = null; return }
  vipsLoading.value = true
  try {
    const { data } = await api.vipSummary(selected.value)
    vipSummary.value = data
  } catch (e) {
    message.error(errText(e))
  } finally {
    vipsLoading.value = false
  }
}

async function lookupAddress() {
  const name = addrQuery.value.trim()
  if (selected.value === null || !name) { addrResult.value = null; return }
  addrLoading.value = true
  try {
    const { data } = await api.resolveAddress(selected.value, name)
    addrResult.value = data
  } catch (e) {
    message.error(errText(e))
    addrResult.value = null
  } finally {
    addrLoading.value = false
  }
}

async function loadAddresses() {
  if (selected.value === null) { addrList.value = []; return }
  addrListLoading.value = true
  try {
    // 地址对象通常几十到几百条,一次取完在前端筛 —— 这一页要的是
    // "扫一眼全部",分页会让"有哪些组"这个问题要翻好几页
    const { data } = await api.addresses({
      device: selected.value, page_size: 1000, ordering: 'name',
    })
    addrList.value = data.results
  } catch (e) {
    message.error(errText(e))
  } finally {
    addrListLoading.value = false
  }
}

const shownAddresses = computed(() => {
  const kw = addrKeyword.value.trim().toLowerCase()
  return addrList.value.filter((a) => {
    if (groupOnly.value && !a.is_group) return false
    if (!kw) return true
    return [a.name, a.value, a.comment, ...(a.members || [])]
      .some((t) => (t || '').toLowerCase().includes(kw))
  })
})

/** 点策略表里的一个地址名 → 直接查它 */
function lookupFromPolicy(name: string) {
  addrQuery.value = name
  addrOpen.value = true
  void lookupAddress()
}

onMounted(async () => {
  await meta.load()
  await loadSummary()
  await loadPolicies()
  await loadAudit()
  await loadVips()
  await loadAddresses()
})

// 换设备/换筛选都回到第一页 —— 停在第 7 页看另一台设备是没有意义的
watch([selected, keyword, actionFilter, enabledFilter, neverHitOnly,
       permissiveOnly, noLogOnly, ordering], () => {
  page.value = 1
  void loadPolicies()
})
// 换设备要重算审计 —— 审计是按设备算的(影子规则要看那台设备的完整顺序)
watch(selected, () => {
  void loadAudit(); void loadVips(); void loadAddresses()
  addrResult.value = null
})
watch([page, pageSize], () => void loadPolicies())

async function syncNow(deviceId: number) {
  busy.value = deviceId
  try {
    const { data } = await api.syncPoliciesNow(deviceId)
    message.success(data.detail)
    // 同步是异步跑的,这里不立刻刷 —— 提示里已经说了"已排入队列"
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
  { title: '防火墙', key: 'device_name', sorter: 'default', minWidth: 150,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, r.device_name),
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
        `${r.mgmt_ip} · VDOM ${r.vdom}`),
    ]) },
  { title: '状态', key: 'state', sorter: 'default', width: 82,
    render: (r) => h(StateDot, { state: r.state, label: true }) },
  { title: '策略数', key: 'total', sorter: 'default', width: 78, className: 'num',
    render: (r) => h('span', { style: 'font-size:12px;font-weight:700' }, int(r.total)) },
  { title: '允许 / 拒绝', key: 'split', sorter: 'default', width: 108,
    render: (r) => h('span', { style: "font-size:11.5px;font-family:'JetBrains Mono',monospace" }, [
      h('span', { style: `color:${STATE.up}` }, String(r.accept)),
      h('span', { style: 'color:var(--cy-ink-3)' }, ' / '),
      h('span', { style: `color:${STATE.down}` }, String(r.deny)),
    ]) },
  { title: '已停用', key: 'disabled', sorter: 'default', width: 74, className: 'num',
    render: (r) => h('span', {
      style: `font-size:11.5px;color:${r.disabled ? STATE.degraded : 'var(--cy-ink-3)'}`,
    }, r.disabled ? int(r.disabled) : '—') },
  { title: '过宽', key: 'wide_open', sorter: 'default', width: 66, className: 'num',
    render: (r) => h('span', {
      style: `font-size:11.5px;font-weight:700;color:${r.wide_open ? STATE.down : 'var(--cy-ink-3)'}`,
      title: 'any-any-any 的放行规则',
    }, r.wide_open ? String(r.wide_open) : '—') },
  { title: '无日志', key: 'no_log', sorter: 'default', width: 72, className: 'num',
    render: (r) => h('span', {
      style: `font-size:11.5px;color:${r.no_log ? STATE.degraded : 'var(--cy-ink-3)'}`,
      title: '放行但不记日志',
    }, r.no_log ? String(r.no_log) : '—') },
  { title: '从未命中', key: 'never_hit', sorter: 'default', width: 96, className: 'num',
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
  { title: '同步', key: 'synced_at', sorter: 'default', minWidth: 150,
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

/**
 * 地址名那一格。每个名字做成可点的 —— 点一下查它是什么。
 *
 * **`all` 单独标出来**:它是"任意",而不是一个还没查的别名。
 * 混在一堆名字里看不出来,而那恰恰是最该看见的一个。
 */
function addrCell(names: string[] | null | undefined) {
  const list = names || []
  if (!list.length) {
    return h('div', { class: 'cell-line dim' }, 'any(没写 = 不限制)')
  }
  return h('div', { class: 'cell-line' }, list.map((n, i) => {
    const any = String(n).toLowerCase() === 'all'
    return h('button', {
      key: i,
      class: ['addr-chip', any ? 'any' : ''],
      title: any ? '任意地址(0.0.0.0/0)' : `点一下查「${n}」是哪些地址`,
      onClick: (e: Event) => { e.stopPropagation(); if (!any) lookupFromPolicy(String(n)) },
    }, String(n))
  }))
}

const policyColumns: DataTableColumns<PolicyRow> = [
  { title: '#', key: 'seq', sorter: 'default', width: 52, className: 'num',
    render: (r) => h('span', {
      style: "font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--cy-ink-3)",
      title: '设备上的先后顺序 —— 防火墙先匹配先生效',
    }, String(r.seq + 1)) },
  { title: 'ID', key: 'policy_id', sorter: 'default', width: 58, className: 'num',
    render: (r) => h('span', {
      style: "font-size:11px;font-family:'JetBrains Mono',monospace",
    }, String(r.policy_id)) },
  { title: '名称', key: 'name', sorter: 'default', minWidth: 132,
    render: (r) => h('div', [
      h('div', { style: 'font-size:11.5px;color:var(--cy-ink)' }, r.name || '(未命名)'),
      r.comments
        ? h('div', { style: 'font-size:10px;color:var(--cy-ink-3);line-height:1.4' }, r.comments)
        : null,
    ]) },
  { title: '源', key: 'src', minWidth: 148, sorter: (a, b) =>
      (a.src_addr?.join() || '').localeCompare(b.src_addr?.join() || ''),
    render: (r) => h('div', [
      listCell(r.src_intf, 'any'),
      // 地址名**点一下就能查它是什么** —— 策略表里只有名字,
      // 而"这条策略放开的到底是哪个网段"是看策略时最常问的一句
      addrCell(r.src_addr),
    ]) },
  { title: '目的', key: 'dst', sorter: 'default', minWidth: 178,
    render: (r) => h('div', [
      listCell(r.dst_intf, 'any'),
      addrCell(r.dst_addr),
      // **映射**。策略的目的地址里只有一个 `web-vip` 这样的名字,它指向内网
      // 哪台机器的哪个端口完全不在策略表里 —— 这一行就是答案。
      // mappings 为 null 是"这次没查映射表",空数组是"目的地址里没有映射",
      // 两者都不画,但含义不同(前端不该把它们说成同一件事,所以只在
      // 有内容时才渲染)
      ...(r.mappings || []).map((m) => h('div', {
        class: 'map-line',
        title: `映射 ${m.name}:${m.endpoint_text}`,
      }, [
        h('span', { class: 'map-arrow' }, '↳'),
        h('span', { class: 'map-text' }, m.endpoint_text),
        // 整机映射:外网地址的所有端口都通到那台机器上。它和一条只映射
        // 443 的规则在列表里长得几乎一样,不标出来看不见
        m.whole_host
          ? h(NTag, {
              size: 'tiny', bordered: false,
              style: `color:${STATE.degraded};border:1px solid ${STATE.degraded};margin-left:4px`,
              title: '整机映射 —— 外网地址的所有端口都通到内网那台机器上,暴露面比端口映射大得多',
            }, () => '整机')
          : null,
      ])),
    ]) },
  { title: '服务', key: 'service', sorter: 'default', minWidth: 104,
    render: (r) => listCell(r.service, 'ALL') },
  { title: '动作', key: 'action', sorter: 'default', width: 76,
    render: (r) => h(NTag, {
      size: 'tiny', bordered: false,
      style: `color:${ACTION_COLORS[r.action] || STATE.unknown};`
        + `border:1px solid ${ACTION_COLORS[r.action] || STATE.unknown}`,
    }, () => r.action_label) },
  { title: 'NAT', key: 'nat', sorter: 'default', width: 54,
    render: (r) => h('span', {
      style: `font-size:11px;color:${r.nat ? 'var(--cy-cyan)' : 'var(--cy-ink-3)'}`,
    }, r.nat ? '开' : '—') },
  { title: '启用', key: 'enabled', width: 62,
    render: (r) => r.enabled
      ? h('span', { style: `font-size:11px;color:${STATE.up}` }, '启用')
      : h('span', { style: `font-size:11px;color:${STATE.degraded};font-weight:700` }, '已停用') },
  { title: '风险', key: 'risk', width: 104,
    render: (r) => {
      // **只标"启用且放行"的规则**(判定在后端)。一条停用规则或者
      // any-any-any 的**拒绝**规则不是风险 —— 后者正是兜底该有的写法,
      // 把它也标红会让真正的问题淹在噪声里
      const tags = []
      if (r.permissive_level === 'critical') {
        tags.push(h(NTag, {
          size: 'tiny', bordered: false, style: `color:${STATE.down};border:1px solid ${STATE.down}`,
          title: '源/目的/服务都是任意的放行规则 —— 等于这对接口之间没有防火墙',
        }, () => '过宽'))
      } else if (r.permissive_level === 'warning') {
        tags.push(h(NTag, {
          size: 'tiny', bordered: false,
          style: `color:${STATE.degraded};border:1px solid ${STATE.degraded}`,
          title: '服务是任意,且源或目的之一是任意 —— 应该收窄',
        }, () => '偏宽'))
      }
      if (r.logging_off) {
        tags.push(h(NTag, {
          size: 'tiny', bordered: false,
          style: `color:${STATE.degraded};border:1px solid ${STATE.degraded}`,
          title: '放行但不记日志 —— 出事之后查不出来源',
        }, () => '无日志'))
      }
      if (!tags.length) {
        return h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, '—')
      }
      return h('div', { style: 'display:flex;gap:3px;flex-wrap:wrap' }, tags)
    } },
  { title: '命中', key: 'hit_count', sorter: 'default', width: 112, className: 'num',
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
  { title: '最后命中', key: 'last_hit_at', sorter: 'default', width: 96,
    render: (r) => h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' },
      r.last_hit_at ? ago(r.last_hit_at) : '—') },
  { title: '', key: 'act', width: 62, fixed: 'right',
    render: (r) => h(NButton, { size: 'tiny', text: true, type: 'primary',
      onClick: () => openDetail(r) }, () => '详情') },
]

const addrColumns: DataTableColumns<AddressRow> = [
  { title: '名称', key: 'name', minWidth: 150, sorter: 'default',
    render: (r) => h('div', [
      h('button', { class: 'addr-chip', onClick: () => lookupFromPolicy(r.name) }, r.name),
      r.comment
        ? h('div', { style: 'font-size:10px;color:var(--cy-ink-3);line-height:1.4' }, r.comment)
        : null,
    ]) },
  { title: '类型', key: 'addr_type', width: 108, sorter: 'default',
    render: (r) => h(NTag, {
      size: 'tiny', bordered: false,
      type: r.is_group ? 'info' : undefined,
    }, () => r.addr_type_label) },
  { title: '是什么', key: 'display', minWidth: 200, sorter: 'default',
    render: (r) => h('span', {
      style: "font-size:11.5px;font-family:'JetBrains Mono',monospace;color:var(--cy-ink)",
    }, r.display) },
  { title: '成员', key: 'member_count', width: 96, className: 'num',
    // **不是组时是 null 不是 0** —— 0 会被读成"这个组是空的"
    sorter: (a, b) => (a.member_count ?? -1) - (b.member_count ?? -1),
    render: (r) => r.member_count === null
      ? h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' }, '—')
      : h('span', {
          style: "font-size:11.5px;font-family:'JetBrains Mono',monospace",
          title: (r.members || []).join('、'),
        }, `${r.member_count} 个`) },
  { title: '绑定接口', key: 'interface', sorter: 'default', width: 100,
    render: (r) => h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' },
      r.interface || '—') },
]

const actionOptions = computed(() => [
  { label: '全部动作', value: '' },
  ...meta.options('policy_action'),
])

/** 导出 CSV 的地址 —— **带上当前所有筛选条件**,导出的就是你看到的那些行。 */
const exportUrl = computed(() => api.policyExportUrl({
  device: selected.value ?? undefined,
  ordering: ordering.value,
  keyword: keyword.value || undefined,
  action: actionFilter.value || undefined,
  enabled: enabledFilter.value === null ? undefined : enabledFilter.value,
  never_hit: neverHitOnly.value ? true : undefined,
  permissive: permissiveOnly.value ? true : undefined,
  no_log: noLogOnly.value ? true : undefined,
}))

/** 审计发现里点一条 → 清掉别的筛选,只筛这一类 */
function focusFinding(key: string) {
  keyword.value = ''
  actionFilter.value = null
  enabledFilter.value = null
  permissiveOnly.value = key === 'wide_open'
  noLogOnly.value = key === 'no_log'
  neverHitOnly.value = key === 'never_hit'
  auditOpen.value = false
}

const FINDING_COLORS: Record<string, string> = {
  wide_open: STATE.down,
  shadowed: 'var(--cy-violet)',
  no_log: STATE.degraded,
  never_hit: STATE.degraded,
}
</script>

<template>
  <div class="pol">
    <!-- ============ 顶部统计 ============ -->
    <div class="tiles">
      <StatTile label="防火墙" :value="totals.devices" unit="台" :dim-zero="false"
                foot="已开启策略同步的" />
      <StatTile label="策略总数" :value="totals.policies" unit="条" :dim-zero="false" />
      <StatTile label="过宽的放行规则" :value="totals.wideOpen" unit="条" :color="STATE.down"
                foot="any-any-any allow —— 等于没有防火墙" />
      <StatTile label="放行但不记日志" :value="totals.noLog" unit="条" :color="STATE.degraded"
                foot="出事之后查不出来源" />
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
        size="small" :bordered="false" :single-line="false" :scroll-x="1160"
      />
      <div v-if="!summary.length && !loading" class="cy-empty">
        还没有防火墙开启策略同步。到<b>配置中心 → 网络设备</b>编辑一台
        <b>类型为防火墙</b>的 FortiGate,打开「同步防火墙策略」。<br>
        <b>强烈建议配 API Token</b>:只有 REST API 拿得到命中计数,而
        「这条规则从来没命中过」是这一页最有价值的结论 —— SSH 通道只能看到配置。
      </div>
    </CyberPanel>

    <!-- ============ 规则审计 ============ -->
    <CyberPanel
      v-if="current"
      title="规则审计"
      :subtitle="`${current.device_name} · 防火墙评审要回答的四个问题`"
      :level="audit && audit.findings.some((f) => f.key === 'wide_open' && (f.count || 0) > 0)
        ? 'critical' : 'normal'"
    >
      <template #actions>
        <NButton size="tiny" ghost :loading="auditLoading" @click="loadAudit()">重新审计</NButton>
        <NButton size="tiny" ghost @click="auditOpen = !auditOpen">
          {{ auditOpen ? '收起明细' : '展开明细' }}
        </NButton>
      </template>

      <div v-if="auditLoading && !audit" class="modal-loading">审计中…</div>
      <template v-else-if="audit">
        <div class="findings">
          <button
            v-for="f in audit.findings" :key="f.key"
            class="finding"
            :class="{ hit: (f.count || 0) > 0, na: f.count === null }"
            :style="{ '--c': FINDING_COLORS[f.key] }"
            :disabled="f.count === null || f.count === 0 || f.key === 'shadowed'"
            :title="f.key === 'shadowed'
              ? '影子规则在下面的明细里看 —— 它依赖顺序,没法做成表格筛选'
              : '点一下把这一类筛到下面的规则表里'"
            @click="focusFinding(f.key)"
          >
            <span class="f-num cy-mono">{{ f.count === null ? '?' : f.count }}</span>
            <span class="f-label">{{ f.label }}</span>
            <span class="f-hint">{{ f.hint }}</span>
          </button>
        </div>

        <!-- 明细。影子规则只能在这里看:它依赖前后顺序,做不成表格里一列 -->
        <div v-if="auditOpen" class="finding-detail">
          <template v-for="f in audit.findings" :key="f.key">
            <div v-if="f.items.length" class="fd-block">
              <div class="fd-head" :style="{ color: FINDING_COLORS[f.key] }">
                {{ f.label }}({{ f.count }})
              </div>
              <div v-for="it in f.items" :key="`${f.key}-${it.id}`" class="fd-row">
                <span class="fd-seq cy-mono">#{{ it.seq + 1 }}</span>
                <span class="fd-name">{{ it.name || '(未命名)' }}</span>
                <span class="fd-addr cy-mono">
                  {{ it.src_addr.join(',') || 'any' }} → {{ it.dst_addr.join(',') || 'any' }}
                  · {{ it.service.join(',') || 'ALL' }}
                </span>
                <span v-if="it.reason" class="fd-reason">{{ it.reason }}</span>
                <span v-else-if="it.comments" class="fd-reason dim">{{ it.comments }}</span>
              </div>
            </div>
          </template>
        </div>

        <div v-if="!audit.has_hit_stats" class="audit-note">
          这批数据没有命中统计(SSH 通道),所以「从未命中」那一项**无法判断** ——
          不是"没有这种规则"。要它就给这台设备配 API Token。
        </div>
      </template>
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
        <label class="never-toggle">
          <NSwitch v-model:value="permissiveOnly" size="small" />
          <span>只看过宽的</span>
        </label>
        <label class="never-toggle">
          <NSwitch v-model:value="noLogOnly" size="small" />
          <span>只看无日志的</span>
        </label>
        <!-- 导出走普通链接:防火墙评审要把规则表交给安全/审计的人,而他们用 Excel。
             带 UTF-8 BOM,否则中文是乱码 -->
        <a :href="exportUrl" class="csv-link" download>导出 CSV(当前筛选)</a>
      </div>

      <NDataTable
        :columns="policyColumns" :data="policies" :loading="policiesLoading"
        size="small" :bordered="false" :single-line="false" :scroll-x="1420"
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

    <!-- ============ 地址对象 / 地址组:别名查询 ============ -->
    <CyberPanel
      title="地址对象" subtitle="策略里那些名字到底是哪几个网段"
    >
      <template #actions>
        <NButton size="tiny" ghost @click="addrOpen = !addrOpen">
          {{ addrOpen ? '收起清单' : `展开清单(${addrList.length})` }}
        </NButton>
      </template>

      <div class="addr-lead">
        策略表里的源/目的地址是一串<b>名字</b>(<code>内网服务器组</code>)——
        <b>它到底是哪几个网段完全不在策略表里</b>。在这儿查,或者直接点上面
        表格里的地址名。<b>地址组会递归展开</b>(组能套组)。
      </div>

      <div class="filters">
        <NInput
          v-model:value="addrQuery" size="small" clearable
          placeholder="输入别名,如 内网服务器组" style="width: 260px"
          @keyup.enter="lookupAddress"
        />
        <NButton size="small" type="primary" ghost :loading="addrLoading" @click="lookupAddress">
          查
        </NButton>
        <span class="dim small">
          共同步到 {{ addrList.length }} 个对象,其中
          {{ addrList.filter((a) => a.is_group).length }} 个是组
        </span>
      </div>

      <!-- ---- 查询结果 ---- -->
      <div v-if="addrResult" class="addr-res">
        <!-- 四种 kind 的说法完全不同,尤其是 unknown ——
             **「没同步到」不等于「不存在」** -->
        <template v-if="addrResult.result.kind === 'unknown'">
          <div class="addr-note warn">
            <b>没有同步到「{{ addrResult.query }}」这个对象。</b>
            这<b>不等于</b>它在设备上不存在 —— FortiOS 的
            <code>show</code> 只打印偏离默认值的项,<b>出厂自带的对象
            (all / none / FABRIC_DEVICE)根本不会出现在输出里</b>。
            <template v-if="addrResult.method === 'ssh'">
              这批数据走的是 <b>SSH</b> 通道,拿不到内置对象;
              配了 API Token 的话 API 通道能拿全。
            </template>
            也可能是名字打错了,或者这一批同步的时候它还没建。
          </div>
        </template>
        <template v-else-if="addrResult.result.kind === 'builtin'">
          <div class="addr-note">
            <b>{{ addrResult.query }}</b> 是 FortiOS 的<b>内置名</b> ——
            {{ addrResult.result.value }}。引用它的策略对<b>所有地址</b>开放。
          </div>
        </template>
        <template v-else>
          <div class="addr-head">
            <b class="cy-mono">{{ addrResult.result.name }}</b>
            <NTag size="tiny" :bordered="false">
              {{ addrResult.result.kind === 'group' ? '地址组' : '地址对象' }}
            </NTag>
            <span v-if="addrResult.result.kind === 'address'" class="cy-mono">
              = {{ addrResult.result.value || '—' }}
            </span>
            <span v-else class="dim">
              展开后 {{ addrResult.result.leaves.length }} 项
            </span>
            <span class="dim small">数据走 {{ (addrResult.method || '?').toUpperCase() }} 通道</span>
          </div>

          <!-- **环要标出来** —— 组 A 含组 B、组 B 含组 A,FortiOS 不拦 -->
          <div v-if="addrResult.result.cycle" class="addr-note warn">
            <b>这个组里有循环引用</b>(某个子组又把它自己包了回来)——
            那一支已经掐掉,下面的清单可能不全。这是设备上要修的配置。
          </div>
          <div v-if="addrResult.result.truncated" class="addr-note warn">
            嵌套层数超过上限,展开被截断了 —— 下面的清单不全。
          </div>

          <div v-if="addrResult.result.leaves.length" class="addr-leaves">
            <div v-for="(l, i) in addrResult.result.leaves" :key="i" class="addr-leaf">
              <span class="cy-mono l-name">{{ l.name }}</span>
              <span class="cy-mono l-val">{{ l.value || '—' }}</span>
            </div>
          </div>
          <div v-else class="dim small">这个组是空的(没有成员)。</div>
        </template>

        <!-- 谁在用它。**空数组 = 确实没有策略引用**,可以清理 -->
        <div class="addr-used">
          <template v-if="addrResult.used_by.length">
            <span class="dim">被 {{ addrResult.used_by.length }} 条策略引用:</span>
            <NTag
              v-for="u in addrResult.used_by.slice(0, 12)" :key="u.id"
              size="tiny" :bordered="false"
              :style="u.enabled ? '' : `color:${STATE.degraded};opacity:.85`"
              :title="`#${u.seq + 1} ${u.name || '(未命名)'} · 用在${u.where}${u.enabled ? '' : ' · 已停用'}`"
            >#{{ u.policy_id }} {{ u.where }}{{ u.enabled ? '' : '(停)' }}</NTag>
          </template>
          <span v-else class="dim">
            <b :style="{ color: STATE.degraded }">没有任何策略引用它</b> —— 配了但不生效,可以清理。
          </span>
        </div>
      </div>

      <!-- ---- 全部对象清单 ---- -->
      <template v-if="addrOpen">
        <div class="filters" style="margin-top: 12px">
          <NInput
            v-model:value="addrKeyword" size="small" clearable
            placeholder="搜名称 / 地址值 / 备注 / 组成员" style="width: 240px"
          />
          <label class="never-toggle">
            <NSwitch v-model:value="groupOnly" size="small" />
            <span>只看地址组</span>
          </label>
        </div>
        <NDataTable
          :columns="addrColumns" :data="shownAddresses" :loading="addrListLoading"
          size="small" :bordered="false" :single-line="false" :scroll-x="820"
          :pagination="{ pageSize: 20, showSizePicker: true, pageSizes: [20, 50, 100] }"
        />
        <div v-if="!addrList.length && !addrListLoading" class="cy-empty">
          没有同步到地址对象。<b>这不等于这台防火墙没有配</b> ——
          SSH 通道的 <code>show firewall address</code> 可能没跑成,
          API 通道可能权限不够。点上面那台的「立即同步」再看。
        </div>
      </template>
    </CyberPanel>

    <!-- 映射(firewall vip)搬到了 /mappings 独立一页 —— 它要被翻、被筛、
         被排序,和策略表挤在一页里两张表互相抢空间。这里只留一个入口 +
         那两个必须让人看见的数(整机映射 / 没有策略引用) -->
    <CyberPanel title="映射" subtitle="外面的地址端口进到内网哪台机器">
      <div class="vip-head">
        <div class="vip-tiles">
          <StatTile label="映射总数" :value="vipSummary?.total ?? 0" unit="条" :dim-zero="false" />
          <StatTile
            label="整机映射" :value="vipSummary?.whole_host.count ?? 0" unit="条"
            :color="STATE.degraded" foot="所有端口都通进去 —— 该收窄成端口映射"
          />
          <StatTile
            label="没有策略引用" :value="vipSummary?.unused.count ?? 0" unit="条"
            :color="STATE.degraded" foot="配了但不生效,可以清理"
          />
        </div>
        <div class="vip-notes">
          <div v-if="!vipsLoading && !vipSummary?.total" class="vip-note">
            这台防火墙<b>没有同步到映射</b>。这不等于"它没有配映射" ——
            SSH 通道的 <code>show firewall vip</code> 可能没跑成,API 通道可能权限不够。
          </div>
          <div class="vip-note">
            <RouterLink to="/mappings">到「防火墙映射」页看完整的映射表 →</RouterLink>
            策略表的「目的」列里也直接跟了一行 <code>↳</code> 显示它指向哪里。
          </div>
        </div>
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
          <!-- 映射:目的地址里的名字实际指向哪里。null 是"没查",空是"没有映射" -->
          <div v-if="detail.mappings === null" class="kv full">
            <span>映射</span><b class="dim">这次没有查映射表</b>
          </div>
          <div v-else-if="detail.mappings.length" class="kv full">
            <span>映射</span>
            <b class="cy-mono">
              <div v-for="m in detail.mappings" :key="m.id" class="map-detail">
                {{ m.name }} · {{ m.endpoint_text }}
                <NTag
                  v-if="m.whole_host" size="tiny" :bordered="false"
                  :style="`color:${STATE.degraded};border:1px solid ${STATE.degraded}`"
                >整机映射</NTag>
              </div>
            </b>
          </div>
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
/* 地址名做成可点的小片 —— 它是"这条策略放开了谁"的入口 */
.addr-chip {
  background: none;
  border: none;
  padding: 0 2px 0 0;
  font-size: 11px;
  font-family: 'JetBrains Mono', monospace;
  color: var(--cy-cyan);
  cursor: pointer;
  text-align: left;
}
.addr-chip:hover { text-decoration: underline; }
/* `all` 单独标出来:它是"任意"而不是一个还没查的别名 */
.addr-chip.any { color: var(--cy-degraded); cursor: default; }
.addr-chip.any:hover { text-decoration: none; }
.cell-line { display: flex; gap: 5px; flex-wrap: wrap; line-height: 1.6; }
.cell-line.dim { color: var(--cy-ink-3); font-size: 11px; }

.addr-lead {
  font-size: 11.5px;
  line-height: 1.7;
  color: var(--cy-ink-2);
  padding: 6px 11px;
  margin-bottom: 10px;
  border-left: 2px solid var(--cy-line);
  background: color-mix(in srgb, var(--cy-raised) 50%, transparent);
}
.addr-lead code, .addr-note code, .cy-empty code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10.5px;
  color: var(--cy-cyan);
}
.addr-res {
  border: 1px solid var(--cy-line-soft);
  padding: 9px 12px;
  margin-top: 10px;
}
.addr-head {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  font-size: 12px; margin-bottom: 7px;
}
.addr-note {
  font-size: 11.5px;
  line-height: 1.65;
  color: var(--cy-ink-2);
  padding: 6px 11px;
  margin-bottom: 8px;
  border-left: 2px solid var(--cy-line);
  background: color-mix(in srgb, var(--cy-raised) 55%, transparent);
}
.addr-note.warn {
  color: var(--cy-degraded);
  border-left-color: var(--cy-degraded);
  background: color-mix(in srgb, var(--cy-degraded) 7%, transparent);
}
.addr-leaves {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 2px 14px;
}
.addr-leaf { display: flex; gap: 10px; font-size: 11.5px; line-height: 1.7; }
.l-name { color: var(--cy-ink-2); min-width: 108px; }
.l-val { color: var(--cy-ink); }
.addr-used {
  margin-top: 9px;
  padding-top: 7px;
  border-top: 1px solid var(--cy-line-soft);
  display: flex; align-items: center; gap: 5px; flex-wrap: wrap;
  font-size: 11px;
}

/* 映射那一行 —— 缩进 + 箭头,让人一眼看出它是挂在目的地址下面的解释,
   不是又一个并列的地址 */
.map-line {
  display: flex;
  align-items: center;
  gap: 3px;
  font-size: 10px;
  line-height: 1.5;
  color: var(--cy-cyan);
  font-family: 'JetBrains Mono', monospace;
}
.map-arrow { color: var(--cy-ink-3); }
.map-text { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.map-detail { display: flex; align-items: center; gap: 6px; line-height: 1.7; }

.vip-head { display: flex; flex-direction: column; gap: 10px; margin-bottom: 10px; }
.vip-tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px;
}
.vip-notes { display: flex; flex-direction: column; gap: 6px; }
.vip-note {
  font-size: 11.5px;
  line-height: 1.6;
  color: var(--cy-ink-2);
  padding: 5px 10px;
  border-left: 2px solid var(--cy-line);
  background: rgba(var(--cy-raised-rgb), 0.5);
}
.vip-note.warn {
  color: var(--cy-degraded);
  border-left-color: var(--cy-degraded);
  background: rgba(var(--cy-degraded-rgb), 0.06);
}
.vip-note code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10.5px;
  color: var(--cy-cyan);
}

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

.findings {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: 9px;
}
/* 发现项是可点的(点了筛到下面的表里),所以用 button 而不是 div ——
   键盘能 tab 到、能回车触发,这是免费拿到的 */
.finding {
  display: grid;
  grid-template-columns: auto 1fr;
  grid-template-areas: 'num label' 'num hint';
  gap: 0 10px;
  align-items: center;
  padding: 8px 11px;
  text-align: left;
  background: rgba(var(--cy-raised-rgb), 0.5);
  border: 1px solid rgba(var(--cy-cyan-rgb), 0.14);
  border-left: 2px solid var(--cy-unknown);
  cursor: pointer;
  font: inherit;
  color: inherit;
  transition: background 0.15s ease, border-color 0.15s ease;
}
.finding:hover:not(:disabled) { background: rgba(var(--cy-cyan-rgb), 0.07); }
.finding:disabled { cursor: default; opacity: 0.75; }
.finding.hit { border-left-color: var(--c); }
.finding.na { opacity: 0.6; }
.f-num {
  grid-area: num;
  font-size: 21px;
  font-weight: 700;
  color: var(--cy-ink-3);
  min-width: 30px;
  text-align: right;
}
.finding.hit .f-num { color: var(--c); }
.f-label { grid-area: label; font-size: 12px; color: var(--cy-ink); }
.f-hint { grid-area: hint; font-size: 10px; color: var(--cy-ink-3); line-height: 1.45; }

.finding-detail {
  margin-top: 12px;
  padding-top: 10px;
  border-top: 1px solid rgba(var(--cy-cyan-rgb), 0.12);
}
.fd-block { margin-bottom: 12px; }
.fd-head { font-size: 11px; letter-spacing: 0.06em; margin-bottom: 4px; }
.fd-row {
  display: grid;
  grid-template-columns: 42px minmax(90px, 160px) minmax(140px, 1fr);
  gap: 4px 10px;
  font-size: 11px;
  padding: 2px 0;
  align-items: baseline;
}
.fd-seq { color: var(--cy-ink-3); }
.fd-name { color: var(--cy-ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.fd-addr { color: var(--cy-ink-2); font-size: 10.5px; word-break: break-all; }
.fd-reason {
  grid-column: 2 / -1;
  font-size: 10.5px;
  color: var(--cy-degraded);
  line-height: 1.5;
}
.fd-reason.dim { color: var(--cy-ink-3); }

.audit-note {
  margin-top: 10px;
  font-size: 10.5px;
  color: var(--cy-ink-3);
  line-height: 1.6;
  padding-left: 8px;
  border-left: 2px solid rgba(var(--cy-degraded-rgb), 0.5);
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
