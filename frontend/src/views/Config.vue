<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import {
  NButton, NDataTable, NInput, NModal, NPopconfirm, NSpace, NSwitch,
  NTabPane, NTabs, NTag, useMessage,
} from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StateDot from '@/components/cyber/StateDot.vue'
import SchemaForm from '@/components/SchemaForm.vue'
import type { FieldSpec } from '@/components/SchemaForm.vue'
import { api, errText } from '@/api'
import type {
  DeviceRow, IdracRow, NotifierRow, ProbeGroup, ProbeTarget, ServerRow,
} from '@/api'
import { useMetaStore } from '@/stores/meta'
import { ago, bytes, endpoint, ms, pct } from '@/composables/useFormat'
import { STATE } from '@/theme'

/**
 * 配置中心。六个 tab:检测线路 / 监控类 / 网络设备 / 服务器 / 带外硬件 / 通知渠道。
 *
 * 表单靠 SchemaForm 从 `fields` 数组生成 —— 手写四份表单模板的话,
 * 加一个字段要改四处而表单是最容易漏的那处(见 SchemaForm 的注释)。
 *
 * 「测试」按钮是这一页最有价值的东西:配错凭据是最常见的问题,
 * 而没有测试按钮的话人要等一个采集周期、再去大屏上看有没有数据,
 * 中间任何一环出错都分辨不出是哪儿的问题。
 */

const message = useMessage()
const meta = useMetaStore()

const tab = ref('probes')
const loading = ref(false)

// ---- 数据 ----
const groups = ref<ProbeGroup[]>([])
const probes = ref<ProbeTarget[]>([])
const devices = ref<DeviceRow[]>([])
const servers = ref<ServerRow[]>([])
const idracs = ref<IdracRow[]>([])
const notifiers = ref<NotifierRow[]>([])

async function loadAll() {
  loading.value = true
  try {
    const [g, p, d, s, i, n] = await Promise.all([
      api.groups({ page_size: 200 }),
      api.probes({ page_size: 500, ordering: 'group__order,order' }),
      api.devices({ page_size: 200, ordering: 'order' }),
      api.servers({ page_size: 200, ordering: 'order' }),
      api.idracHosts({ page_size: 200, ordering: 'order' }),
      api.notifiers({ page_size: 100 }),
    ])
    groups.value = g.data.results
    probes.value = p.data.results
    devices.value = d.data.results
    servers.value = s.data.results
    idracs.value = i.data.results
    notifiers.value = n.data.results
  } catch (e) {
    message.error(errText(e))
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await meta.load()
  await loadAll()
})

// ---- 编辑弹窗 ----
type EntityKind = 'group' | 'probe' | 'device' | 'server' | 'idrac' | 'notifier'
const modal = ref(false)
const editing = ref<EntityKind>('probe')
const form = ref<Record<string, any>>({})
const formErrors = ref<Record<string, string>>({})
const saving = ref(false)
const isNew = computed(() => !form.value.id)

const DEFAULTS: Record<EntityKind, Record<string, any>> = {
  group: { name: '', description: '', color: '', order: 0, enabled: true },
  probe: {
    group: null, name: '', host: '', protocol: 'icmp', port: null,
    interval_seconds: 10, timeout_ms: 2000, packets: 5,
    http_path: '/', http_method: 'GET', http_expect_code: 200, http_expect_keyword: '',
    http_verify_tls: false, dns_query: '', dns_expect: '',
    latency_warn_ms: 100, latency_crit_ms: 300,
    loss_warn_pct: 5, loss_crit_pct: 20,
    jitter_warn_ms: 30, jitter_crit_ms: 100,
    fail_threshold: 3, recover_threshold: 3, enabled: true, order: 0,
  },
  device: {
    name: '', kind: 'switch', vendor: 'cisco', model: 'c9300-48t', mgmt_ip: '', site: '',
    os_version: '', collect_method: 'snmp', fallback_method: '',
    interval_seconds: 60, timeout_ms: 5000,
    snmp_port: 161, snmp_version: '2c', snmp_community: '',
    snmp_v3_user: '', snmp_v3_level: '', snmp_v3_auth_proto: 'SHA', snmp_v3_auth_key: '',
    snmp_v3_priv_proto: 'AES', snmp_v3_priv_key: '',
    ssh_port: 22, ssh_username: '', ssh_password: '', ssh_private_key: '', ssh_enable_password: '',
    api_scheme: 'https', api_port: 443, api_token: '', api_vdom: 'root', api_verify_tls: false,
    cpu_warn_pct: 75, cpu_crit_pct: 90, mem_warn_pct: 80, mem_crit_pct: 92,
    temp_warn_c: 55, temp_crit_c: 68, session_warn: 0, if_util_warn_pct: 80,
    fail_threshold: 2, recover_threshold: 2,
    collect_interfaces: true, collect_neighbors: true, enabled: true, order: 0,
    backup_enabled: false, backup_interval_hours: 24, backup_keep: 20,
    backup_check_unsaved: true,
    policy_sync_enabled: false, policy_sync_interval_minutes: 30,
  },
  server: {
    name: '', host: '', os_type: 'linux', ssh_port: 22, ssh_username: '', ssh_password: '',
    ssh_private_key: '', ssh_key_passphrase: '', site: '', role: '',
    interval_seconds: 60, timeout_ms: 8000, net_interface: '',
    cpu_warn_pct: 80, cpu_crit_pct: 92, mem_warn_pct: 85, mem_crit_pct: 95,
    disk_warn_pct: 80, disk_crit_pct: 90, load_warn: 1.5, load_crit: 3,
    fail_threshold: 2, recover_threshold: 2,
    collect_processes: true, enabled: true, order: 0,
  },
  idrac: {
    name: '', host: '', port: 443, username: 'root', password: '',
    verify_tls: false, server: null, site: '', role: '',
    interval_seconds: 300, timeout_ms: 15000,
    temp_warn_c: 70, temp_crit_c: 85, temp_delta_warn_c: 15,
    ssd_life_warn_pct: 10, event_window_days: 7,
    fail_threshold: 2, recover_threshold: 2,
    collect_events: true, enabled: true, order: 0,
  },
  notifier: {
    name: '', kind: 'telegram', enabled: true,
    telegram_bot_token: '', telegram_chat_id: '',
    telegram_api_base: 'https://api.telegram.org', telegram_thread_id: '',
    webhook_url: '', webhook_method: 'POST', webhook_headers: {}, webhook_template: '',
    webhook_verify_tls: true,
    timeout_seconds: 10, on_alert: true, on_recover: true,
    min_severity: 'warning', kinds: [], groups: [], cooldown_seconds: 300,
  },
}

function openEdit(kind: EntityKind, row?: Record<string, any>) {
  editing.value = kind
  formErrors.value = {}
  // 凭据字段后端是 write_only,不会回传 —— 编辑时留空表示"不修改",
  // 这一点在 hint 里写给用户看
  form.value = row ? { ...DEFAULTS[kind], ...row } : { ...DEFAULTS[kind] }
  modal.value = true
}

// ---- 复制 ----
//
// **复制在后端做**(`netcheck/duplicate.py`)。理由只有一条但是决定性的:
// 凭据字段是 `write_only`,列表接口**根本不回传** —— 前端拼出来的"副本"
// 必然是一台没有密码的机器。后端拿得到解密后的值,所以点一下就是一条
// 能用的副本,名字自动编号(`xxx 复制1` / `复制2` / …)。
//
// 两种结果:
//   201            直接建好了(监控类 / 网络设备 / 通知渠道 —— 只有名字唯一)
//   400 + needs    线路 / 服务器 / 带外有端点唯一约束,先要一个新地址

const API_PATH: Record<EntityKind, string> = {
  group: 'probe-groups', probe: 'probes', device: 'devices',
  server: 'servers', idrac: 'idrac', notifier: 'notifiers',
}

/** 要新地址时弹的那个小框。**只问必须改的那一两项**,不是整张表单 */
const dupAsk = ref<{
  kind: EntityKind; id: number; name: string
  fields: string[]; values: Record<string, string>; source: Record<string, any>
} | null>(null)
const duplicating = ref(0)

const FIELD_LABEL: Record<string, string> = {
  host: '地址', mgmt_ip: '管理地址', port: '端口', ssh_port: 'SSH 端口',
}

async function copyFrom(kind: EntityKind, row: Record<string, any>,
                        overrides?: Record<string, any>) {
  duplicating.value = row.id
  try {
    const { data } = await api.duplicate(API_PATH[kind], row.id, overrides)
    dupAsk.value = null
    // **设备没有端点唯一约束**(多 VDOM 就是同一个管理地址配好几条),
    // 所以它能直接建成功 —— 而不改地址的话同一台设备会被采两遍。
    // 这句提醒放在这儿而不是拦在后端:拦住会打断多 VDOM 那个合法用法
    const extra = kind === 'device' && !overrides
      ? ' —— 地址和源那台一样,不改的话同一台设备会被采两遍,记得改'
      : ''
    message.success(`已复制为「${data.name}」${extra}`, { duration: extra ? 9000 : 4000 })
    await loadAll()
  } catch (e) {
    const body = (e as any)?.response?.data
    if (body?.needs) {
      // 这一类要先给新地址。**把源的值预填进去** —— 人通常只改最后一段
      dupAsk.value = {
        kind, id: row.id, name: row.name,
        fields: body.needs,
        values: Object.fromEntries(
          body.needs.map((f: string) => [f, String(body.source?.[f] ?? '')]),
        ),
        source: body.source || {},
      }
    } else {
      message.error(errText(e))
    }
  } finally {
    duplicating.value = 0
  }
}

function confirmDuplicate() {
  const ask = dupAsk.value
  if (!ask) return
  void copyFrom(ask.kind, { id: ask.id, name: ask.name }, { ...ask.values })
}

async function save() {
  saving.value = true
  formErrors.value = {}
  const kind = editing.value
  const body = { ...form.value }
  // 编辑时把留空的凭据字段删掉,否则会把已存的凭据清空
  if (!isNew.value) {
    for (const key of [
      'snmp_community', 'snmp_v3_auth_key', 'snmp_v3_priv_key',
      'ssh_password', 'ssh_private_key', 'ssh_enable_password',
      'ssh_key_passphrase', 'api_token', 'telegram_bot_token',
      // iDRAC 的 Redfish 密码。**漏掉这一项的话**,编辑一台带外主机时
      // 只改个名字就会把密码清空,而下一拍采集才会报认证失败
      'password',
    ]) {
      if (body[key] === '' || body[key] === undefined) delete body[key]
    }
  }
  try {
    if (kind === 'group') {
      isNew.value ? await api.createGroup(body) : await api.updateGroup(body.id, body)
    } else if (kind === 'probe') {
      isNew.value ? await api.createProbe(body) : await api.updateProbe(body.id, body)
    } else if (kind === 'device') {
      isNew.value ? await api.createDevice(body) : await api.updateDevice(body.id, body)
    } else if (kind === 'server') {
      isNew.value ? await api.createServer(body) : await api.updateServer(body.id, body)
    } else if (kind === 'idrac') {
      isNew.value ? await api.createIdrac(body) : await api.updateIdrac(body.id, body)
    } else {
      isNew.value ? await api.createNotifier(body) : await api.updateNotifier(body.id, body)
    }
    message.success(isNew.value ? '已创建,下一拍开始采集' : '已保存')
    modal.value = false
    await loadAll()
  } catch (e) {
    // 字段级错误标到对应输入框上,不只弹一句话 —— 四十个字段的表单里
    // 光说"参数错误"等于没说
    const data = (e as any)?.response?.data
    if (data && typeof data === 'object') {
      const errs: Record<string, string> = {}
      for (const [k, v] of Object.entries(data)) {
        errs[k] = Array.isArray(v) ? v.join('; ') : String(v)
      }
      formErrors.value = errs
    }
    message.error(errText(e))
  } finally {
    saving.value = false
  }
}

async function remove(kind: EntityKind, id: number) {
  try {
    if (kind === 'group') await api.deleteGroup(id)
    else if (kind === 'probe') await api.deleteProbe(id)
    else if (kind === 'device') await api.deleteDevice(id)
    else if (kind === 'server') await api.deleteServer(id)
    else if (kind === 'idrac') await api.deleteIdrac(id)
    else await api.deleteNotifier(id)
    message.success('已删除')
    await loadAll()
  } catch (e) {
    message.error(errText(e))
  }
}

async function toggleEnabled(kind: EntityKind, row: any) {
  try {
    const body = { enabled: !row.enabled }
    if (kind === 'probe') await api.updateProbe(row.id, body)
    else if (kind === 'device') await api.updateDevice(row.id, body)
    else if (kind === 'server') await api.updateServer(row.id, body)
    else if (kind === 'idrac') await api.updateIdrac(row.id, body)
    else if (kind === 'group') await api.updateGroup(row.id, body)
    else await api.updateNotifier(row.id, body)
    await loadAll()
  } catch (e) {
    message.error(errText(e))
  }
}

// ---- 测试 ----
const testResult = ref<{ title: string; ok: boolean; lines: string[] } | null>(null)
const testing = ref(0)

async function testProbe(row: ProbeTarget) {
  testing.value = row.id
  try {
    const { data } = await api.testProbe(row.id)
    testResult.value = {
      title: `${row.name} 拨测结果`,
      ok: data.ok,
      lines: [
        `判定状态:${data.state}`,
        `延迟:${ms(data.rtt_ms)}${data.rtt_min_ms !== null ? `(最小 ${ms(data.rtt_min_ms)} / 最大 ${ms(data.rtt_max_ms)})` : ''}`,
        `丢包率:${pct(data.loss_pct)}`,
        `抖动:${ms(data.jitter_ms)}`,
        ...(data.error ? [`错误(${data.error_kind}):${data.error}`] : []),
        ...(data.problems?.length
          ? [`触发的问题:${data.problems.map((p: any) => `${p.kind}/${p.severity}`).join(', ')}`]
          : ['未触发任何阈值']),
        ...(data.extra && Object.keys(data.extra).length
          ? [`附加信息:${JSON.stringify(data.extra)}`]
          : []),
      ],
    }
  } catch (e) {
    testResult.value = { title: `${row.name} 拨测失败`, ok: false, lines: [errText(e)] }
  } finally {
    testing.value = 0
  }
}

async function testDevice(row: DeviceRow, method?: string) {
  testing.value = row.id
  try {
    const { data } = await api.testDevice(row.id, method)
    testResult.value = {
      title: `${row.name} 连通性(${data.method.toUpperCase()})`,
      ok: data.ok,
      lines: [data.detail],
    }
  } catch (e) {
    testResult.value = { title: `${row.name} 测试失败`, ok: false, lines: [errText(e)] }
  } finally {
    testing.value = 0
  }
}

async function testServer(row: ServerRow) {
  testing.value = row.id
  try {
    const { data } = await api.testServer(row.id)
    testResult.value = { title: `${row.name} SSH 连通性`, ok: data.ok, lines: data.detail.split(' | ') }
  } catch (e) {
    testResult.value = { title: `${row.name} 测试失败`, ok: false, lines: [errText(e)] }
  } finally {
    testing.value = 0
  }
}

/**
 * 测带外通道。**只读、不写库、不开事件** —— 重点是报错要有指向性:
 * 401 说凭据、403 说角色权限不够、404 说固件太老或者这不是一台 Dell、
 * TLS 说把「校验 TLS 证书」关掉。
 *
 * 成功时**部件数是 0 的那一栏最能说明问题**(硬盘 0 块通常不是没有硬盘,
 * 而是这个账号读不到存储那一段)。
 */
async function testIdrac(row: IdracRow) {
  testing.value = row.id
  try {
    const { data } = await api.testIdrac(row.id)
    testResult.value = { title: `${row.name} 带外连通性`, ok: data.ok, lines: data.detail.split(' | ') }
  } catch (e) {
    testResult.value = { title: `${row.name} 测试失败`, ok: false, lines: [errText(e)] }
  } finally {
    testing.value = 0
  }
}

/**
 * 测备份通道。**取一份配置回来但不存版本** —— 存的话每点一次测试就多一个
 * 版本,而版本数有上限,连点五次就把真实的变更历史挤掉五个。
 */
async function testBackup(row: DeviceRow) {
  testing.value = row.id
  try {
    const { data } = await api.testDeviceBackup(row.id)
    testResult.value = { title: `${row.name} 备份通道`, ok: data.ok, lines: [data.detail] }
  } catch (e) {
    testResult.value = { title: `${row.name} 备份测试失败`, ok: false, lines: [errText(e)] }
  } finally {
    testing.value = 0
  }
}

async function testNotifier(row: NotifierRow) {
  testing.value = row.id
  try {
    const { data } = await api.testNotifier(row.id)
    testResult.value = {
      title: `${row.name} 推送测试`,
      ok: data.ok,
      lines: [data.detail],
    }
  } catch (e) {
    testResult.value = { title: `${row.name} 测试失败`, ok: false, lines: [errText(e)] }
  } finally {
    testing.value = 0
  }
}

// ---- 表单字段定义 ----

const groupFields: FieldSpec[] = [
  { key: 'name', label: '监控类名称', type: 'text', required: true,
    placeholder: '如:互联网出口 / 专线 / 内网核心', hint: '大屏上一个监控类就是一张大图' },
  { key: 'order', label: '排序', type: 'number', min: 0, hint: '数字小的排在前面' },
  { key: 'description', label: '说明', type: 'text', full: true },
  { key: 'color', label: '强调色', type: 'text', placeholder: 'var(--cy-cyan)(留空自动分配)',
    hint: '别填高饱和亮色 —— 深色底上会发晕' },
  { key: 'enabled', label: '启用', type: 'switch' },
]

const probeFields: FieldSpec[] = [
  { key: 'name', label: '线路名称', type: 'text', required: true, placeholder: '如:联通出口' },
  // options 在渲染时由下面那个 map 换成真实的监控类列表(它不是枚举,
  // 要从接口拿),这里给个空数组占位
  { key: 'group', label: '监控类', type: 'select', required: true, options: [] },
  { key: 'host', label: '目标地址', type: 'text', required: true,
    placeholder: 'IP 或域名', hint: 'DNS 检测时这里填 DNS 服务器地址' },
  { key: 'protocol', label: '协议', type: 'select', options: 'protocol', required: true },
  { key: 'port', label: '端口', type: 'number', min: 1, max: 65535,
    show: (m) => m.protocol !== 'icmp',
    hint: 'HTTP/HTTPS/DNS 留空则用协议默认端口' },
  { key: 'interval_seconds', label: '检测频率', type: 'number', min: 1, max: 86400, suffix: '秒',
    required: true, hint: '最小 1 秒。受 worker 数量约束,过密会导致采集迟到' },
  { key: 'timeout_ms', label: '单次超时', type: 'number', min: 100, max: 60000, suffix: '毫秒' },
  { key: 'packets', label: '每次发包数', type: 'number', min: 1, max: 50,
    show: (m) => ['icmp', 'tcp', 'udp', 'dns'].includes(m.protocol),
    hint: '丢包率和抖动都是从这一组包算出来的;填 1 就只有通断' },

  { key: 'http_path', label: 'HTTP 路径', type: 'text', show: (m) => ['http', 'https'].includes(m.protocol) },
  { key: 'http_method', label: 'HTTP 方法', type: 'select', show: (m) => ['http', 'https'].includes(m.protocol),
    options: [{ label: 'GET', value: 'GET' }, { label: 'HEAD', value: 'HEAD' }, { label: 'POST', value: 'POST' }] },
  { key: 'http_expect_code', label: '期望状态码', type: 'number', min: 100, max: 599,
    show: (m) => ['http', 'https'].includes(m.protocol) },
  { key: 'http_expect_keyword', label: '期望关键字', type: 'text',
    show: (m) => ['http', 'https'].includes(m.protocol),
    hint: '留空不校验;填了则响应体必须包含它' },
  { key: 'http_verify_tls', label: '校验 TLS 证书', type: 'switch', show: (m) => m.protocol === 'https' },

  { key: 'dns_query', label: '查询域名', type: 'text', show: (m) => m.protocol === 'dns', required: true },
  { key: 'dns_expect', label: '期望解析结果', type: 'text', show: (m) => m.protocol === 'dns',
    hint: '留空只要求解析成功;填了则结果必须包含它(可发现 DNS 劫持)' },

  { key: 'latency_warn_ms', label: '延迟警告线', type: 'number', min: 0, suffix: 'ms' },
  { key: 'latency_crit_ms', label: '延迟严重线', type: 'number', min: 0, suffix: 'ms' },
  { key: 'loss_warn_pct', label: '丢包警告线', type: 'number', min: 0, max: 100, suffix: '%' },
  { key: 'loss_crit_pct', label: '丢包严重线', type: 'number', min: 0, max: 100, suffix: '%' },
  { key: 'jitter_warn_ms', label: '抖动警告线', type: 'number', min: 0, suffix: 'ms' },
  { key: 'jitter_crit_ms', label: '抖动严重线', type: 'number', min: 0, suffix: 'ms' },
  { key: 'fail_threshold', label: '连续失败开事件', type: 'number', min: 1, suffix: '次',
    hint: '防抖:连续这么多次失败才记事件并告警' },
  { key: 'recover_threshold', label: '连续正常关事件', type: 'number', min: 1, suffix: '次' },
  { key: 'enabled', label: '启用', type: 'switch' },
  { key: 'order', label: '排序', type: 'number', min: 0 },
]

/**
 * SSH 凭据什么时候要显示。
 *
 * **不能只看采集通道。**备份走的是 SSH(`show running-config` /
 * FortiOS 的 `show`),而它和 collect_method 完全无关 —— 一台用 SNMP 采
 * 指标的交换机想备份配置,仍然需要 SSH 用户名和密码。只看采集通道的话,
 * 那台设备开了备份之后输入框是隐藏的,而后端强制要求填 → 保存永远失败,
 * 而页面上找不到能填的地方。策略同步同理(它可以退回 SSH 通道)。
 */
const needsSsh = (m: Record<string, any>) =>
  [m.collect_method, m.fallback_method].includes('ssh')
  || m.backup_enabled === true
  || (m.kind === 'firewall' && m.policy_sync_enabled === true)

/**
 * API Token 什么时候要显示。除了 api 采集通道,还有两种情况:
 * FortiGate 的备份优先走 API 的 config/backup 端点(那个端点给的是能直接
 * 回灌的备份文件,CLI 的 show 输出不是),策略同步也只有 API 才有命中计数。
 */
const needsApi = (m: Record<string, any>) =>
  [m.collect_method, m.fallback_method].includes('api')
  || (m.vendor === 'fortinet' && (m.backup_enabled === true || m.policy_sync_enabled === true))

const deviceFields: FieldSpec[] = [
  { key: 'name', label: '设备名称', type: 'text', required: true },
  { key: 'mgmt_ip', label: '管理地址', type: 'text', required: true, placeholder: '10.0.0.1' },
  { key: 'kind', label: '设备类型', type: 'select', options: 'device_kind', required: true },
  { key: 'vendor', label: '厂商', type: 'select', options: 'vendor', required: true },
  { key: 'model', label: '型号', type: 'select', options: 'device_model', required: true,
    hint: '型号决定采哪些 OID / 走哪条 CLI。不在册的选「通用」' },
  { key: 'site', label: '机房位置', type: 'text' },
  { key: 'os_version', label: '固件版本', type: 'text', hint: '留空则首次采集后自动回填' },

  { key: 'collect_method', label: '采集方式', type: 'select', options: 'collect_method', required: true,
    hint: 'FortiGate 推荐 API(会话数/HA/License 只有 API 能拿)' },
  { key: 'fallback_method', label: '降级通道', type: 'select', options: 'collect_method',
    hint: '主通道失败时改走这条。留空不降级' },
  { key: 'interval_seconds', label: '采集频率', type: 'number', min: 10, max: 86400, suffix: '秒',
    hint: '一次采集要走几十个 OID,最小 10 秒' },
  { key: 'timeout_ms', label: '超时', type: 'number', min: 500, max: 60000, suffix: '毫秒' },

  { key: 'snmp_version', label: 'SNMP 版本', type: 'select', options: 'snmp_version',
    show: (m) => [m.collect_method, m.fallback_method].includes('snmp') },
  { key: 'snmp_port', label: 'SNMP 端口', type: 'number', min: 1, max: 65535,
    show: (m) => [m.collect_method, m.fallback_method].includes('snmp') },
  { key: 'snmp_community', label: 'Community', type: 'password',
    show: (m) => [m.collect_method, m.fallback_method].includes('snmp') && m.snmp_version === '2c',
    hint: '编辑时留空表示不修改已存的值' },
  { key: 'snmp_v3_user', label: 'v3 用户名', type: 'text',
    show: (m) => [m.collect_method, m.fallback_method].includes('snmp') && m.snmp_version === '3' },
  { key: 'snmp_v3_level', label: 'v3 安全级别', type: 'select', options: 'snmp_sec_level',
    show: (m) => [m.collect_method, m.fallback_method].includes('snmp') && m.snmp_version === '3' },
  { key: 'snmp_v3_auth_proto', label: 'v3 认证算法', type: 'select',
    options: ['MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512'].map((v) => ({ label: v, value: v })),
    show: (m) => m.snmp_version === '3' && m.snmp_v3_level !== 'noAuthNoPriv'
      && [m.collect_method, m.fallback_method].includes('snmp') },
  { key: 'snmp_v3_auth_key', label: 'v3 认证口令', type: 'password',
    show: (m) => m.snmp_version === '3' && m.snmp_v3_level !== 'noAuthNoPriv'
      && [m.collect_method, m.fallback_method].includes('snmp') },
  { key: 'snmp_v3_priv_proto', label: 'v3 加密算法', type: 'select',
    options: ['DES', '3DES', 'AES', 'AES192', 'AES256'].map((v) => ({ label: v, value: v })),
    show: (m) => m.snmp_version === '3' && m.snmp_v3_level === 'authPriv'
      && [m.collect_method, m.fallback_method].includes('snmp') },
  { key: 'snmp_v3_priv_key', label: 'v3 加密口令', type: 'password',
    show: (m) => m.snmp_version === '3' && m.snmp_v3_level === 'authPriv'
      && [m.collect_method, m.fallback_method].includes('snmp') },

  { key: 'ssh_username', label: 'SSH 用户名', type: 'text', show: needsSsh,
    hint: '采集、配置备份、策略同步共用这一份凭据' },
  { key: 'ssh_port', label: 'SSH 端口', type: 'number', min: 1, max: 65535, show: needsSsh },
  { key: 'ssh_password', label: 'SSH 密码', type: 'password', show: needsSsh,
    hint: '密码和私钥填一个即可;编辑时留空表示不修改已存的值' },
  { key: 'ssh_enable_password', label: 'enable 密码', type: 'password',
    show: (m) => needsSsh(m) && m.vendor === 'cisco',
    // running-config 是特权命令,普通 exec 模式下直接报 Invalid input
    hint: '**开了配置备份的 Cisco 必须填** —— show running-config 需要进 enable' },
  { key: 'ssh_private_key', label: 'SSH 私钥', type: 'textarea', rows: 4, show: needsSsh },

  { key: 'api_token', label: 'API Token', type: 'password', show: needsApi,
    hint: 'FortiGate:系统 → 管理员 → REST API 管理员生成。'
      + '备份和策略同步也用它 —— 策略的**命中计数只有 API 拿得到**' },
  { key: 'api_scheme', label: 'API 协议', type: 'select',
    options: [{ label: 'https', value: 'https' }, { label: 'http', value: 'http' }],
    show: needsApi },
  { key: 'api_port', label: 'API 端口', type: 'number', min: 1, max: 65535, show: needsApi },
  { key: 'api_vdom', label: 'VDOM', type: 'text', show: needsApi, hint: '单 VDOM 填 root' },
  { key: 'api_verify_tls', label: '校验 API 证书', type: 'switch', show: needsApi },

  { key: 'cpu_warn_pct', label: 'CPU 警告线', type: 'number', min: 0, max: 100, suffix: '%' },
  { key: 'cpu_crit_pct', label: 'CPU 严重线', type: 'number', min: 0, max: 100, suffix: '%' },
  { key: 'mem_warn_pct', label: '内存警告线', type: 'number', min: 0, max: 100, suffix: '%' },
  { key: 'mem_crit_pct', label: '内存严重线', type: 'number', min: 0, max: 100, suffix: '%' },
  { key: 'temp_warn_c', label: '温度警告线', type: 'number', min: 0, suffix: '℃' },
  { key: 'temp_crit_c', label: '温度严重线', type: 'number', min: 0, suffix: '℃' },
  { key: 'session_warn', label: '会话数警告线', type: 'number', min: 0,
    show: (m) => m.kind === 'firewall', hint: '0 表示不判。401F 满配约 400 万并发' },
  { key: 'if_util_warn_pct', label: '接口带宽警告线', type: 'number', min: 0, max: 100, suffix: '%' },
  { key: 'fail_threshold', label: '连续失败开事件', type: 'number', min: 1, suffix: '次' },
  { key: 'recover_threshold', label: '连续正常关事件', type: 'number', min: 1, suffix: '次' },
  { key: 'collect_interfaces', label: '采集接口明细', type: 'switch',
    hint: '48 口设备一次要走近百个 OID;只看整机指标可以关掉' },
  { key: 'collect_neighbors', label: '采集邻居(LLDP/CDP)', type: 'switch',
    // 只有 SNMP 通道采得到 —— LLDP-MIB 和 CISCO-CDP-MIB 都是 SNMP MIB
    hint: '「这个口对面接的是谁」。**只有 SNMP 通道采得到**,'
      + '走 API/SSH 的设备会一直是 0 条 —— 那不等于没接线' },

  // ---- 配置备份 ----
  // **和采集通道无关**:采指标可以走 SNMP,但 SNMP 拿不到配置文本。
  // 备份走 SSH(FortiGate 有 API Token 时优先走 API 的 config/backup 端点)
  { key: 'backup_enabled', label: '启用配置备份', type: 'switch', full: true,
    hint: '打开后上面会出现「SSH 用户名 / 密码」——备份走 SSH,'
      + '和采集通道无关(SNMP 拿不到配置文本)。Cisco 还要填 enable 密码。'
      + 'FortiGate 也可以只填 API Token' },
  { key: 'backup_interval_hours', label: '备份间隔', type: 'number', min: 1, max: 8760, suffix: '小时',
    show: (m) => m.backup_enabled,
    hint: '配置不是时序数据,一天一次足够。改完配置想立刻留档用页面上的「立即备份」' },
  { key: 'backup_keep', label: '保留版本数', type: 'number', min: 1, max: 500, suffix: '个',
    show: (m) => m.backup_enabled,
    hint: '只数「变更过的版本」—— 配置没变不会新增版本,所以 20 个够回溯很久' },
  { key: 'backup_check_unsaved', label: '检查配置是否未保存', type: 'switch', full: true,
    // 只对 Cisco 有意义(比对 running-config 和 startup-config)。
    // FortiOS 改完即存,没有这个概念 —— 画像里 startup_cli 为空的型号
    // 这个开关打开也只会返回"未检查"
    show: (m) => m.backup_enabled && m.vendor === 'cisco',
    hint: '比对 running-config 和 startup-config,找出「改了但没 write memory」的配置'
      + ' —— 设备一重启那些改动就没了。**代价是每次备份多取一份配置,时间大约翻倍**' },

  // ---- 防火墙策略 ----
  { key: 'policy_sync_enabled', label: '同步防火墙策略', type: 'switch', full: true,
    show: (m) => m.kind === 'firewall',
    hint: '仅防火墙。**强烈建议配 API Token** —— 只有 REST API 拿得到命中计数,'
      + '而「这条规则从来没命中过」是策略页面最有价值的结论' },
  { key: 'policy_sync_interval_minutes', label: '策略同步间隔', type: 'number', min: 5, max: 1440,
    suffix: '分钟', show: (m) => m.kind === 'firewall' && m.policy_sync_enabled,
    hint: '策略表几百条起,一次同步要拉两个端点;5 分钟以下没有意义' },

  { key: 'enabled', label: '启用', type: 'switch' },
  { key: 'order', label: '排序', type: 'number', min: 0 },
]

/** ESXi 和 Linux 走两套完全不同的采集命令,表单里的提示也要跟着分 */
const isEsxi = (m: Record<string, any>) => m.os_type === 'esxi'

const serverFields: FieldSpec[] = [
  { key: 'name', label: '服务器名称', type: 'text', required: true, placeholder: '如:app-node-01' },
  { key: 'host', label: '地址', type: 'text', required: true, placeholder: 'IP 或域名' },
  { key: 'os_type', label: '系统类型', type: 'select', options: 'server_os', required: true,
    hint: '**选错了指标会全是空的而且不报错** —— ESXi 上没有 /proc/stat 也没有 '
      + '/proc/meminfo,但 shell 跑得通,采集器会认为"连上了、命令跑完了"' },
  { key: 'ssh_port', label: 'SSH 端口', type: 'number', min: 1, max: 65535 },
  { key: 'ssh_username', label: 'SSH 用户名', type: 'text', required: true,
    show: (m) => !isEsxi(m),
    hint: '不需要 root —— 采集只读 /proc 和跑 df / ps' },
  { key: 'ssh_username', label: 'SSH 用户名', type: 'text', required: true,
    show: isEsxi,
    hint: '要能跑 esxcli 和 vim-cmd。**ESXi 默认关着 SSH**,先在 '
      + '「主机 → 管理 → 服务」里把 TSM-SSH 起来,否则这里报的是连接被拒绝' },
  { key: 'ssh_password', label: 'SSH 密码', type: 'password',
    hint: '密码和私钥填一个即可;编辑时留空表示不修改' },
  { key: 'ssh_private_key', label: 'SSH 私钥', type: 'textarea', rows: 4,
    hint: '无人值守场景更适合私钥' },
  { key: 'ssh_key_passphrase', label: '私钥口令', type: 'password',
    hint: '私钥带口令时填。不填而私钥有口令的话,报错会指向"密钥格式不对",很难查' },
  { key: 'site', label: '机房位置', type: 'text' },
  { key: 'role', label: '用途', type: 'text', placeholder: '如 应用 / 数据库 / 网关',
    hint: '只用于展示分组' },

  { key: 'interval_seconds', label: '采集频率', type: 'number', min: 15, max: 86400, suffix: '秒',
    hint: '每次采集是一次完整的 SSH 握手,最小 15 秒' },
  { key: 'timeout_ms', label: '超时', type: 'number', min: 1000, max: 60000, suffix: '毫秒' },
  { key: 'net_interface', label: '流量统计网卡', type: 'text', full: true,
    show: (m) => !isEsxi(m),
    placeholder: '留空 = 自动取默认路由那块',
    hint: '**不要指望把所有网卡加起来** —— docker0 / veth / br- 这些虚拟口会把'
      + '同一份流量数两三遍。留空时取默认路由那块(虚拟机宿主机上常常是 br0,那是对的)' },
  { key: 'net_interface', label: '流量统计上行口', type: 'text', full: true,
    show: isEsxi,
    placeholder: '留空 = 自动挑;要指定就填 vmnic0 这种',
    hint: 'ESXi 上只有 vmnic 是物理上行口(vSwitch / portgroup / vmk 不在流量表里,'
      + '所以没有 Linux 上那种"同一份流量数几遍"的问题)。留空时自动挑**累计收发'
      + '字节最多的那块 Up 口** —— 不按 vmnic0 挑,那块在很多机器上是插着线的备口' },

  { key: 'cpu_warn_pct', label: 'CPU 警告线', type: 'number', min: 0, max: 100, suffix: '%' },
  { key: 'cpu_crit_pct', label: 'CPU 严重线', type: 'number', min: 0, max: 100, suffix: '%' },
  { key: 'mem_warn_pct', label: '内存警告线', type: 'number', min: 0, max: 100, suffix: '%',
    hint: '按 MemAvailable 算,页缓存不算已用 —— 否则任何一台干活的 Linux 都是 90%+' },
  { key: 'mem_crit_pct', label: '内存严重线', type: 'number', min: 0, max: 100, suffix: '%' },
  { key: 'disk_warn_pct', label: '磁盘警告线', type: 'number', min: 0, max: 100, suffix: '%',
    hint: 'Linux:判**占用率最高的那个挂载点**,不是根分区。'
      + 'ESXi:判**最满的那个数据存储**(bootbank 不算 —— 它天生就用到八九成,'
      + '算进来的话每台 ESXi 一加进来就撞穿严重线,而那不是个能行动的告警)' },
  { key: 'disk_crit_pct', label: '磁盘严重线', type: 'number', min: 0, max: 100, suffix: '%' },
  // ESXi 不提供 loadavg,这两项对它是死的 —— 藏起来而不是显示一个不生效的
  // 输入框:一个填了不起作用的阈值比没有这个输入框更容易让人误判
  { key: 'load_warn', label: '负载警告线', type: 'number', min: 0, step: 0.1, suffix: '/核',
    show: (m) => !isEsxi(m),
    hint: '判的是 load1 ÷ 核数。1.0 = 刚好跑满。绝对值没有可比性:'
      + '64 核的机器 load 8 很闲,2 核的 load 8 已经跑不动了' },
  { key: 'load_crit', label: '负载严重线', type: 'number', min: 0, step: 0.1, suffix: '/核',
    show: (m) => !isEsxi(m) },

  { key: 'fail_threshold', label: '连续失败开事件', type: 'number', min: 1, suffix: '次' },
  { key: 'recover_threshold', label: '连续正常关事件', type: 'number', min: 1, suffix: '次' },
  { key: 'collect_processes', label: '采集进程 Top', type: 'switch',
    show: (m) => !isEsxi(m),
    hint: '多一条 ps 命令,换来「是谁在吃 CPU」这个答案' },
  { key: 'collect_processes', label: '采集虚拟机清单', type: 'switch',
    show: isEsxi,
    hint: '多一条 `esxcli vm process list`,换来「这台宿主上正在跑哪些虚拟机」' },
  { key: 'enabled', label: '启用', type: 'switch' },
  { key: 'order', label: '排序', type: 'number', min: 0 },
]

const idracFields: FieldSpec[] = [
  { key: 'name', label: '名称', type: 'text', required: true, placeholder: '如:r740-idrac-09' },
  { key: 'host', label: 'iDRAC 地址', type: 'text', required: true,
    placeholder: 'BMC 的 IP',
    hint: '**带外管理口的地址,不是服务器自己的 IP** —— 两者是两个不同的地址,'
      + '拿服务器 IP 来填是这里最常见的错' },
  { key: 'port', label: '端口', type: 'number', min: 1, max: 65535 },
  { key: 'username', label: '用户名', type: 'text', required: true,
    hint: '要有 Read Only 及以上的角色。权限不够时报的是 403,不是密码错' },
  { key: 'password', label: '密码', type: 'password',
    hint: '编辑时留空表示不修改' },
  { key: 'verify_tls', label: '校验 TLS 证书', type: 'switch',
    hint: 'iDRAC 出厂是自签证书,所以默认关。打开而没换过正式证书的话,'
      + '报的是 TLS 握手失败' },
  { key: 'server', label: '对应的服务器', type: 'select', options: 'server_options',
    hint: '**可选。**只有 iDRAC 没有 SSH 账号的裸金属是常态,不填不影响采集。'
      + '填了的话两张卡片会连起来 —— 带内看"系统忙不忙",带外看"机器会不会坏"' },
  { key: 'site', label: '机房位置', type: 'text' },
  { key: 'role', label: '用途', type: 'text', hint: '只用于展示分组' },

  { key: 'interval_seconds', label: '采集频率', type: 'number', min: 60, max: 86400, suffix: '秒',
    hint: '**最小 60 秒。**BMC 是一颗很弱的处理器,打太勤会把它自己拖慢,'
      + '严重时管理界面登不进去 —— 而那正是出事时要用的东西。带外的东西本来变化就慢' },
  { key: 'timeout_ms', label: '超时', type: 'number', min: 2000, max: 120000, suffix: '毫秒',
    hint: 'BMC 响应慢是常态,别设太短' },

  { key: 'temp_warn_c', label: '温度警告线', type: 'number', min: 0, max: 150, suffix: '℃' },
  { key: 'temp_crit_c', label: '温度严重线', type: 'number', min: 0, max: 150, suffix: '℃',
    hint: '**这是平台自己的线,不是 iDRAC 的。**iDRAC 的严重线通常是 100℃(CPU 的绝对上限),'
      + '照抄它等于只在已经要坏了的时候才知道' },
  { key: 'temp_delta_warn_c', label: '同机温差警告', type: 'number', min: 0, max: 100, suffix: '℃',
    full: true,
    hint: '同一台机器上两颗 CPU 温度差这么多 = **那一颗的散热出了问题**,不是机房热'
      + '(风道堵了 / 硅脂干了)。这条判据 iDRAC 自己没有,而它比绝对温度更早发现问题。'
      + '0 = 不判' },
  { key: 'ssd_life_warn_pct', label: 'SSD 剩余寿命警告', type: 'number', min: 0, max: 100, suffix: '%',
    hint: '**机械盘没有这个概念,不参与判定** —— 它返回 0 不是"寿命耗尽"' },
  { key: 'event_window_days', label: '硬件日志回看', type: 'number', min: 1, max: 365, suffix: '天',
    hint: 'SEL(硬件事件日志)**不会自动清**,一台跑了几年的机器上留着很早以前的记录很正常。'
      + '只看这个窗口内的 —— **一条永远都在的红等于没有红**' },

  { key: 'fail_threshold', label: '连续失败开事件', type: 'number', min: 1, suffix: '次' },
  { key: 'recover_threshold', label: '连续正常关事件', type: 'number', min: 1, suffix: '次' },
  { key: 'collect_events', label: '采集硬件日志', type: 'switch',
    hint: '多一次请求。SEL 是「这台机器过去发生过什么」的唯一来源' },
  { key: 'enabled', label: '启用', type: 'switch' },
  { key: 'order', label: '排序', type: 'number', min: 0 },
]

const notifierFields: FieldSpec[] = [
  { key: 'name', label: '渠道名称', type: 'text', required: true },
  { key: 'kind', label: '类型', type: 'select', options: 'notifier_kind', required: true },

  { key: 'telegram_bot_token', label: 'Bot Token', type: 'password',
    show: (m) => m.kind === 'telegram', hint: '向 @BotFather 申请;编辑时留空表示不修改' },
  { key: 'telegram_chat_id', label: 'Chat ID', type: 'text',
    show: (m) => m.kind === 'telegram', hint: '个人是数字,群组是负数,频道可用 @channelname' },
  { key: 'telegram_api_base', label: 'API 地址', type: 'text',
    show: (m) => m.kind === 'telegram', hint: '内网无法直连 Telegram 时填反代地址' },
  { key: 'telegram_thread_id', label: '话题 ID', type: 'text',
    show: (m) => m.kind === 'telegram', hint: '群组开了话题(Topics)时填' },

  { key: 'webhook_url', label: 'Webhook 地址', type: 'text', full: true,
    show: (m) => m.kind === 'webhook', required: true },
  { key: 'webhook_method', label: 'HTTP 方法', type: 'select',
    options: [{ label: 'POST', value: 'POST' }, { label: 'PUT', value: 'PUT' }],
    show: (m) => m.kind === 'webhook' },
  { key: 'webhook_verify_tls', label: '校验 TLS 证书', type: 'switch', show: (m) => m.kind === 'webhook' },
  { key: 'webhook_headers', label: '自定义请求头', type: 'json', rows: 3,
    show: (m) => m.kind === 'webhook', placeholder: '{"Authorization": "Bearer xxx"}' },
  { key: 'webhook_template', label: '消息模板', type: 'textarea', rows: 5,
    show: (m) => m.kind === 'webhook',
    placeholder: '留空发平台标准 JSON。对接钉钉/企微/飞书时填它们要求的结构',
    hint: '占位符:{status} {severity} {kind_label} {title} {source} {message} {value} {threshold} {unit} {started_at} {resolved_at} {duration}' },

  { key: 'on_alert', label: '推送告警', type: 'switch' },
  { key: 'on_recover', label: '推送恢复', type: 'switch' },
  { key: 'min_severity', label: '最低级别', type: 'select', options: 'severity',
    hint: '低于这个级别的事件不推' },
  { key: 'kinds', label: '只推这些类型', type: 'select', options: 'event_kind', multiple: true, full: true,
    hint: '不选表示不限类型' },
  { key: 'groups', label: '只推这些监控类', type: 'select', multiple: true, full: true,
    options: [],
    hint: '不选表示全部。只对线路事件生效,设备事件不受此项过滤' },
  { key: 'cooldown_seconds', label: '静默窗口', type: 'number', min: 0, suffix: '秒',
    hint: '同一事件同一阶段在窗口内不重复推,防 flapping 轰炸' },
  { key: 'timeout_seconds', label: '请求超时', type: 'number', min: 1, max: 120, suffix: '秒' },
  { key: 'enabled', label: '启用', type: 'switch' },
]

const currentFields = computed(() => {
  const map = {
    group: groupFields, probe: probeFields, device: deviceFields,
    server: serverFields, idrac: idracFields, notifier: notifierFields,
  }
  return map[editing.value]
})

/** 表单里的动态选项:监控类列表要从接口来,不是枚举。 */
function resolveOptions(key: string) {
  if (key === 'protocol' || key === 'device_kind' || key === 'vendor' || key === 'device_model'
      || key === 'collect_method' || key === 'snmp_version' || key === 'snmp_sec_level'
      || key === 'notifier_kind' || key === 'severity' || key === 'event_kind'
      || key === 'server_os') {
    return meta.options(key)
  }
  // 「对应的服务器」不是枚举 —— 它是库里的行。**第一项是"不关联"**:
  // 只有 iDRAC 没有 SSH 账号的裸金属是常态,必须能选空
  if (key === 'server_options') {
    return [
      { label: '不关联(只有带外)', value: null },
      ...servers.value.map((s) => ({ label: `${s.name}(${s.host})`, value: s.id })),
    ]
  }
  return []
}

// group 字段的选项要单独注入(它不是枚举)
const groupOptions = computed(() =>
  groups.value.map((g) => ({ label: g.name, value: g.id })),
)

// ---- 表格列 ----

const groupColumns: DataTableColumns<ProbeGroup> = [
  { title: '名称', key: 'name', minWidth: 140 },
  { title: '说明', key: 'description', minWidth: 180,
    render: (r) => h('span', { style: 'color:var(--cy-ink-2);font-size:12px' }, r.description || '—') },
  { title: '线路数', key: 'target_count', width: 80, className: 'num' },
  { title: '排序', key: 'order', width: 62, className: 'num' },
  { title: '启用', key: 'enabled', width: 66,
    render: (r) => h(NSwitch, { value: r.enabled, size: 'small', onUpdateValue: () => toggleEnabled('group', r) }) },
  { title: '操作', key: 'act', width: 160,
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', ghost: true, loading: duplicating.value === r.id,
        onClick: () => copyFrom('group', r) }, () => '复制'),
      h(NButton, { size: 'tiny', ghost: true, onClick: () => openEdit('group', r) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => remove('group', r.id) }, {
        trigger: () => h(NButton, { size: 'tiny', text: true, type: 'error' }, () => '删除'),
        default: () => r.target_count > 0
          ? `这个监控类下还有 ${r.target_count} 条线路,要先删掉它们`
          : '确认删除?',
      }),
    ]) },
]

const probeColumns: DataTableColumns<ProbeTarget> = [
  { title: '状态', key: 'state', width: 78,
    render: (r) => h(StateDot, { state: r.state, label: true }) },
  { title: '线路', key: 'name', minWidth: 170,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, r.name),
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
        endpoint(r.host, r.protocol, r.port)),
    ]) },
  { title: '监控类', key: 'group_name', width: 110,
    render: (r) => h('span', { style: 'font-size:12px;color:var(--cy-ink-2)' }, r.group_name || '—') },
  { title: '频率', key: 'interval_seconds', width: 74, className: 'num',
    render: (r) => h('span', { style: 'font-size:11.5px' }, `${r.interval_seconds}s`) },
  { title: '延迟', key: 'last_rtt_ms', width: 84, className: 'num',
    render: (r) => h('span', { style: 'font-size:11.5px' }, ms(r.last_rtt_ms)) },
  { title: '丢包', key: 'last_loss_pct', width: 72, className: 'num',
    render: (r) => h('span', { style: 'font-size:11.5px' }, pct(r.last_loss_pct, 0)) },
  { title: '可用率', key: 'availability', width: 82, className: 'num',
    render: (r) => h('span', {
      style: `font-size:11.5px;color:${r.availability >= 99.9 ? STATE.up : r.availability >= 99 ? STATE.degraded : STATE.down}`,
    }, r.total_checks ? pct(r.availability, 2) : '—') },
  { title: '阈值', key: 'thresholds', width: 156,
    render: (r) => h('span', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
      `${r.latency_warn_ms}/${r.latency_crit_ms}ms · ${r.loss_warn_pct}/${r.loss_crit_pct}% · ${r.jitter_warn_ms}/${r.jitter_crit_ms}ms`) },
  { title: '最后检测', key: 'last_checked_at', width: 96,
    render: (r) => h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, ago(r.last_checked_at)) },
  { title: '启用', key: 'enabled', width: 66,
    render: (r) => h(NSwitch, { value: r.enabled, size: 'small', onUpdateValue: () => toggleEnabled('probe', r) }) },
  { title: '操作', key: 'act', width: 214, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', ghost: true, loading: testing.value === r.id,
        onClick: () => testProbe(r) }, () => '测试'),
      h(NButton, { size: 'tiny', ghost: true, loading: duplicating.value === r.id,
        onClick: () => copyFrom('probe', r) }, () => '复制'),
      h(NButton, { size: 'tiny', ghost: true, onClick: () => openEdit('probe', r) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => remove('probe', r.id) }, {
        trigger: () => h(NButton, { size: 'tiny', text: true, type: 'error' }, () => '删除'),
        default: () => '删除后历史样本和事件也会一起删掉,确认?',
      }),
    ]) },
]

const deviceColumns: DataTableColumns<DeviceRow> = [
  { title: '状态', key: 'state', width: 78,
    render: (r) => h(StateDot, { state: r.state, label: true }) },
  { title: '设备', key: 'name', minWidth: 165,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, r.name),
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" }, r.mgmt_ip),
    ]) },
  { title: '型号', key: 'model_label', width: 172,
    render: (r) => h('div', [
      h('div', { style: 'font-size:11.5px;color:var(--cy-ink-2)' }, r.model_label || r.model),
      h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' },
        `${r.kind_label || r.kind}${r.os_version ? ' · ' + r.os_version : ''}`),
    ]) },
  { title: '通道', key: 'collect_method', width: 118,
    render: (r) => h('div', { style: 'display:flex;gap:3px;flex-wrap:wrap' }, [
      h(NTag, { size: 'tiny', bordered: false, type: 'info' }, () => r.collect_method.toUpperCase()),
      r.fallback_method
        ? h(NTag, { size: 'tiny', bordered: false }, () => `降级 ${r.fallback_method.toUpperCase()}`)
        : null,
      // 实际用的通道和主通道不一样 = 正在降级运行,这个必须显眼
      r.last_method_used && r.last_method_used !== r.collect_method
        ? h(NTag, { size: 'tiny', bordered: false, type: 'warning' }, () => `实走 ${r.last_method_used.toUpperCase()}`)
        : null,
    ]) },
  { title: '凭据', key: 'creds', width: 116,
    render: (r) => h('div', { style: 'display:flex;gap:3px;flex-wrap:wrap' }, [
      r.has_snmp_community ? h(NTag, { size: 'tiny', bordered: false }, () => 'SNMP') : null,
      r.has_ssh_credential ? h(NTag, { size: 'tiny', bordered: false }, () => 'SSH') : null,
      r.has_api_token ? h(NTag, { size: 'tiny', bordered: false }, () => 'API') : null,
      !r.has_snmp_community && !r.has_ssh_credential && !r.has_api_token
        ? h('span', { style: 'font-size:10.5px;color:var(--cy-down)' }, '未配置') : null,
    ]) },
  { title: '接口', key: 'interface_count', width: 66, className: 'num' },
  { title: '备份 / 策略', key: 'extras', width: 138,
    render: (r) => h('div', { style: 'display:flex;flex-direction:column;gap:2px' }, [
      r.backup_enabled
        ? h('span', {
            // 备份结果三态:成功 / 失败 / 还没跑过。**失败必须显眼** ——
            // 一个悄悄坏掉的备份等于没有备份,而它没有任何别的症状
            style: 'font-size:10.5px;color:'
              + (r.last_backup_status === 'failed' ? STATE.down
                : r.last_backup_status === 'ok' ? STATE.up : STATE.unknown),
          }, `备份 ${meta.label('backup_status', r.last_backup_status)} · 每 ${r.backup_interval_hours}h`)
        : h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' }, '备份未开启'),
      r.kind === 'firewall'
        ? h('span', {
            style: `font-size:10.5px;color:${r.policy_sync_enabled ? 'var(--cy-ink-2)' : 'var(--cy-ink-3)'}`,
          }, r.policy_sync_enabled
            ? `策略 ${r.policy_count} 条 · ${ago(r.last_policy_sync_at)}`
            : '策略未同步')
        : null,
    ]) },
  { title: '频率', key: 'interval_seconds', width: 68, className: 'num',
    render: (r) => h('span', { style: 'font-size:11.5px' }, `${r.interval_seconds}s`) },
  { title: '最后采集', key: 'last_collected_at', width: 96,
    render: (r) => h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, ago(r.last_collected_at)) },
  { title: '启用', key: 'enabled', width: 66,
    render: (r) => h(NSwitch, { value: r.enabled, size: 'small', onUpdateValue: () => toggleEnabled('device', r) }) },
  { title: '操作', key: 'act', width: 316, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', ghost: true, loading: testing.value === r.id,
        onClick: () => testDevice(r) }, () => '测主通道'),
      r.fallback_method
        ? h(NButton, { size: 'tiny', ghost: true, onClick: () => testDevice(r, r.fallback_method) }, () => '测降级')
        : null,
      r.backup_enabled
        ? h(NButton, { size: 'tiny', ghost: true, loading: testing.value === r.id,
            onClick: () => testBackup(r) }, () => '测备份')
        : null,
      h(NButton, { size: 'tiny', ghost: true, loading: duplicating.value === r.id,
        onClick: () => copyFrom('device', r) }, () => '复制'),
      h(NButton, { size: 'tiny', ghost: true, onClick: () => openEdit('device', r) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => remove('device', r.id) }, {
        trigger: () => h(NButton, { size: 'tiny', text: true, type: 'error' }, () => '删除'),
        default: () => '确认删除?接口和历史样本会一起删掉',
      }),
    ]) },
]

const serverColumns: DataTableColumns<ServerRow> = [
  { title: '状态', key: 'state', width: 78,
    render: (r) => h(StateDot, { state: r.state, label: true }) },
  { title: '服务器', key: 'name', minWidth: 168,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, r.name),
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
        `${r.host}:${r.ssh_port} · ${r.ssh_username}`),
    ]) },
  { title: '系统', key: 'os_name', minWidth: 186,
    render: (r) => h('div', [
      h('div', { style: 'display:flex;align-items:center;gap:5px' }, [
        // 类型是**人选的**(决定走哪套采集命令),和下面那行采回来的版本号
        // 不是一回事 —— 两者不一致时(选了 ESXi 却采回 Ubuntu)一眼能看出来
        h(NTag, { size: 'tiny', bordered: false, type: r.os_type === 'esxi' ? 'warning' : 'default' },
          () => meta.label('server_os', r.os_type)),
        // 这几项是**首次采集后自动回填**的,新建时是空的 —— 显示"待采集"
        // 而不是空白,否则看着像采集出了问题
        h('span', { style: 'font-size:11.5px;color:var(--cy-ink-2)' }, r.os_name || '待采集'),
      ]),
      h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' },
        [r.kernel, r.cpu_cores ? `${r.cpu_cores} 核` : '',
         r.mem_total_bytes ? bytes(r.mem_total_bytes) : ''].filter(Boolean).join(' · ') || '—'),
    ]) },
  { title: '凭据', key: 'creds', width: 82,
    render: (r) => r.has_credential
      ? h(NTag, { size: 'tiny', bordered: false }, () => (r.uses_key ? '私钥' : '密码'))
      : h('span', { style: `font-size:10.5px;color:${STATE.down}` }, '未配置'),
  },
  { title: '网卡', key: 'primary_interface', width: 108,
    render: (r) => h('div', [
      h('div', { style: "font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--cy-ink-2)" },
        r.primary_interface || r.net_interface || '自动'),
      h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' }, `共 ${r.interface_count} 块`),
    ]) },
  { title: '频率', key: 'interval_seconds', width: 68, className: 'num',
    render: (r) => h('span', { style: 'font-size:11.5px' }, `${r.interval_seconds}s`) },
  { title: '阈值', key: 'thresholds', width: 176,
    render: (r) => h('span', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
      `CPU ${r.cpu_warn_pct}/${r.cpu_crit_pct}% · 内存 ${r.mem_warn_pct}/${r.mem_crit_pct}%`
      + ` · 盘 ${r.disk_warn_pct}/${r.disk_crit_pct}% · 载 ${r.load_warn}/${r.load_crit}`) },
  { title: '最后采集', key: 'last_collected_at', width: 96,
    render: (r) => h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, ago(r.last_collected_at)) },
  { title: '启用', key: 'enabled', width: 66,
    render: (r) => h(NSwitch, { value: r.enabled, size: 'small',
      onUpdateValue: () => toggleEnabled('server', r) }) },
  { title: '操作', key: 'act', width: 214, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', ghost: true, loading: testing.value === r.id,
        onClick: () => testServer(r) }, () => '测试'),
      h(NButton, { size: 'tiny', ghost: true, loading: duplicating.value === r.id,
        onClick: () => copyFrom('server', r) }, () => '复制'),
      h(NButton, { size: 'tiny', ghost: true, onClick: () => openEdit('server', r) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => remove('server', r.id) }, {
        trigger: () => h(NButton, { size: 'tiny', text: true, type: 'error' }, () => '删除'),
        default: () => '删除后历史样本和事件也会一起删掉,确认?',
      }),
    ]) },
]

const idracColumns: DataTableColumns<IdracRow> = [
  { title: '状态', key: 'state', width: 78,
    render: (r) => h(StateDot, { state: r.state, label: true }) },
  { title: '带外主机', key: 'name', minWidth: 168,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, r.name),
      // **地址后面标明"带外" ** —— 拿服务器自己的 IP 来填是这里最常见的错,
      // 而填错了的表现是连不上,人会去怀疑凭据
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
        `${r.host}:${r.port} · ${r.username} · 带外口`),
    ]) },
  { title: '硬件', key: 'model_name', minWidth: 168,
    render: (r) => h('div', [
      h('div', { style: 'font-size:11.5px;color:var(--cy-ink-2)' }, r.model_name || '待采集'),
      h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' },
        [r.service_tag ? `SN ${r.service_tag}` : '', r.idrac_firmware,
         r.power_state].filter(Boolean).join(' · ') || '—'),
    ]) },
  { title: '带内', key: 'server_name', width: 118,
    render: (r) => r.server_name
      ? h('span', { style: 'font-size:11px;color:var(--cy-ink-2)' }, r.server_name)
      // **没关联不是问题** —— 只有 iDRAC 没有 SSH 账号的裸金属是常态
      : h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' }, '未关联') },
  { title: '凭据', key: 'creds', width: 72,
    render: (r) => r.has_credential
      ? h(NTag, { size: 'tiny', bordered: false }, () => '已配置')
      : h('span', { style: `font-size:10.5px;color:${STATE.down}` }, '未配置') },
  { title: '频率', key: 'interval_seconds', width: 68, className: 'num',
    render: (r) => h('span', { style: 'font-size:11.5px' }, `${r.interval_seconds}s`) },
  { title: '阈值', key: 'thresholds', width: 190,
    render: (r) => h('span', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
      `温度 ${r.temp_warn_c}/${r.temp_crit_c}℃ · 温差 ${r.temp_delta_warn_c}℃`
      + ` · SSD ${r.ssd_life_warn_pct}% · 日志 ${r.event_window_days}d`) },
  { title: '最后采集', key: 'last_collected_at', width: 96,
    render: (r) => h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, ago(r.last_collected_at)) },
  { title: '启用', key: 'enabled', width: 66,
    render: (r) => h(NSwitch, { value: r.enabled, size: 'small',
      onUpdateValue: () => toggleEnabled('idrac', r) }) },
  { title: '操作', key: 'act', width: 224, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', ghost: true, loading: testing.value === r.id,
        onClick: () => testIdrac(r) }, () => '测试'),
      h(NButton, { size: 'tiny', ghost: true, loading: duplicating.value === r.id,
        onClick: () => copyFrom('idrac', r) }, () => '复制'),
      h(NButton, { size: 'tiny', ghost: true, onClick: () => openEdit('idrac', r) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => remove('idrac', r.id) }, {
        trigger: () => h(NButton, { size: 'tiny', text: true, type: 'error' }, () => '删除'),
        default: () => '删除后历史样本和事件也会一起删掉,确认?',
      }),
    ]) },
]

const notifierColumns: DataTableColumns<NotifierRow> = [
  { title: '渠道', key: 'name', minWidth: 140,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, r.name),
      h('div', { style: 'font-size:10.5px;color:var(--cy-ink-3)' }, r.kind_label || r.kind),
    ]) },
  { title: '目标', key: 'dest', minWidth: 180,
    render: (r) => h('span', { style: "font-size:11px;color:var(--cy-ink-2);font-family:'JetBrains Mono',monospace;word-break:break-all" },
      r.kind === 'telegram' ? `chat ${r.telegram_chat_id || '?'}` : r.webhook_url || '—') },
  { title: '推送', key: 'phases', width: 96,
    render: (r) => h('div', { style: 'display:flex;gap:3px' }, [
      r.on_alert ? h(NTag, { size: 'tiny', bordered: false, type: 'error' }, () => '告警') : null,
      r.on_recover ? h(NTag, { size: 'tiny', bordered: false, type: 'success' }, () => '恢复') : null,
    ]) },
  { title: '过滤', key: 'filters', minWidth: 150,
    render: (r) => h('div', { style: 'font-size:10.5px;color:var(--cy-ink-3);line-height:1.5' }, [
      h('div', null, `级别 ≥ ${meta.label('severity', r.min_severity)}`),
      r.kinds?.length ? h('div', null, `类型 ${r.kinds.length} 项`) : null,
      r.group_names?.length ? h('div', null, `监控类 ${r.group_names.join('/')}`) : null,
      h('div', null, `静默 ${r.cooldown_seconds}s`),
    ]) },
  { title: '发送', key: 'stats', width: 104, className: 'num',
    render: (r) => h('div', { style: 'font-size:11px;line-height:1.5' }, [
      h('div', { style: `color:${STATE.up}` }, `成功 ${r.total_sent}`),
      r.total_failed ? h('div', { style: `color:${STATE.down}` }, `失败 ${r.total_failed}`) : null,
      h('div', { style: 'color:var(--cy-ink-3);font-size:10px' }, ago(r.last_sent_at)),
    ]) },
  { title: '启用', key: 'enabled', width: 66,
    render: (r) => h(NSwitch, { value: r.enabled, size: 'small', onUpdateValue: () => toggleEnabled('notifier', r) }) },
  { title: '操作', key: 'act', width: 200, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', type: 'primary', ghost: true, loading: testing.value === r.id,
        onClick: () => testNotifier(r) }, () => '发测试'),
      h(NButton, { size: 'tiny', ghost: true, loading: duplicating.value === r.id,
        onClick: () => copyFrom('notifier', r) }, () => '复制'),
      h(NButton, { size: 'tiny', ghost: true, onClick: () => openEdit('notifier', r) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => remove('notifier', r.id) }, {
        trigger: () => h(NButton, { size: 'tiny', text: true, type: 'error' }, () => '删除'),
        default: () => '确认删除?',
      }),
    ]) },
]

const MODAL_TITLES: Record<EntityKind, string> = {
  group: '监控类', probe: '检测线路', device: '网络设备',
  server: '服务器', idrac: '带外硬件', notifier: '通知渠道',
}

/** 当前编辑的设备型号画像说明 —— 让人知道这款型号能采到什么。 */
const profileNote = computed(() => {
  if (editing.value !== 'device') return ''
  const row = devices.value.find((d) => d.id === form.value.id)
  return row?.profile_notes || ''
})
</script>

<template>
  <div class="cfg">
    <NTabs v-model:value="tab" type="line" animated>
      <!-- ============ 检测线路 ============ -->
      <NTabPane name="probes" tab="检测线路">
        <CyberPanel title="检测线路" :subtitle="`${probes.length} 条`" flush>
          <template #actions>
            <NButton size="small" type="primary" ghost @click="openEdit('probe')">新建线路</NButton>
            <NButton size="small" ghost :loading="loading" @click="loadAll()">刷新</NButton>
          </template>
          <NDataTable
            :columns="probeColumns" :data="probes" :loading="loading"
            size="small" :bordered="false" :single-line="false" :scroll-x="1340"
            :pagination="{ pageSize: 20, showSizePicker: true, pageSizes: [20, 50, 100] }"
          />
          <div v-if="!probes.length && !loading" class="cy-empty">
            还没有线路。先在「监控类」里建一个分组,再回来新建线路 ——
            大屏上一个监控类就是一张大图。
          </div>
        </CyberPanel>
      </NTabPane>

      <!-- ============ 监控类 ============ -->
      <NTabPane name="groups" tab="监控类">
        <CyberPanel title="监控类" :subtitle="`${groups.length} 个 · 一个监控类 = 大屏上一张大图`" flush>
          <template #actions>
            <NButton size="small" type="primary" ghost @click="openEdit('group')">新建监控类</NButton>
          </template>
          <NDataTable
            :columns="groupColumns" :data="groups" :loading="loading"
            size="small" :bordered="false" :single-line="false"
          />
        </CyberPanel>
      </NTabPane>

      <!-- ============ 网络设备 ============ -->
      <NTabPane name="devices" tab="网络设备">
        <CyberPanel
          title="网络设备"
          :subtitle="`${devices.length} 台 · 交换机 / 防火墙`"
          flush
        >
          <template #actions>
            <NButton size="small" type="primary" ghost @click="openEdit('device')">新建设备</NButton>
            <NButton size="small" ghost :loading="loading" @click="loadAll()">刷新</NButton>
          </template>
          <NDataTable
            :columns="deviceColumns" :data="devices" :loading="loading"
            size="small" :bordered="false" :single-line="false" :scroll-x="1330"
            :pagination="{ pageSize: 20 }"
          />
          <div v-if="!devices.length && !loading" class="cy-empty">
            还没有设备。在册型号:C9300-48T / C9300-24T / C9200L-24T-4G / FortiGate-401F,
            不在册的选「通用」画像也能采到通断、接口流量和运行时长。
          </div>
        </CyberPanel>
      </NTabPane>

      <!-- ============ 服务器 ============ -->
      <NTabPane name="servers" tab="服务器">
        <CyberPanel
          title="服务器"
          :subtitle="`${servers.length} 台 · 通过 SSH 采集,不装 agent`"
          flush
        >
          <template #actions>
            <NButton size="small" type="primary" ghost @click="openEdit('server')">新建服务器</NButton>
            <NButton size="small" ghost :loading="loading" @click="loadAll()">刷新</NButton>
          </template>
          <NDataTable
            :columns="serverColumns" :data="servers" :loading="loading"
            size="small" :bordered="false" :single-line="false" :scroll-x="1290"
            :pagination="{ pageSize: 20 }"
          />
          <div v-if="!servers.length && !loading" class="cy-empty">
            还没有服务器。只要一个能登录的 SSH 账号就行,<b>不用在机器上装任何东西</b>
            —— Linux 读的是 <code>/proc</code> 和 <code>df</code>,不解析 top/free 的输出
            (那些格式随发行版和 locale 变);<b>ESXi 走 <code>esxcli</code> / <code>vim-cmd</code></b>,
            加的时候<b>「系统类型」要选对</b> —— 选错了指标会全是空的而且不报错。<br>
            <b>只支持 Linux / 类 Unix。</b>Windows 要走 WinRM,那是另一条通道,这里没有实现。
          </div>
        </CyberPanel>
      </NTabPane>

      <!-- ============ 带外硬件 ============ -->
      <NTabPane name="idrac" tab="带外硬件">
        <CyberPanel
          title="带外硬件(iDRAC)"
          :subtitle="`${idracs.length} 台 · 走 Redfish,答「这台机器本身会不会坏」`"
          flush
        >
          <template #actions>
            <NButton size="small" type="primary" ghost @click="openEdit('idrac')">新建带外主机</NButton>
            <NButton size="small" ghost :loading="loading" @click="loadAll()">刷新</NButton>
          </template>
          <NDataTable
            :columns="idracColumns" :data="idracs" :loading="loading"
            size="small" :bordered="false" :single-line="false" :scroll-x="1240"
            :pagination="{ pageSize: 20 }"
          />
          <div v-if="!idracs.length && !loading" class="cy-empty">
            还没有带外主机。带外走 <b>Redfish</b>(HTTPS,只读),回答的是
            <b>「这台机器本身会不会坏」</b> —— 哪块盘、哪条内存、哪个电源、RAID 卷、
            风扇、逐点温度。<br>
            这些东西<b>在操作系统里通常一点症状都没有</b>:一块正在 SMART 预警的硬盘、
            一个已经掉了电的冗余电源,SSH 上去什么都看不出来 ——
            所以它不是「服务器」那一页的补充,而是另一半。<br>
            要填的是 <b>iDRAC 的地址(带外管理口,不是服务器自己的 IP)</b>
            和一个有 Read Only 及以上角色的账号。加完点「测试」——
            报错是指向性的。
          </div>
        </CyberPanel>
      </NTabPane>

      <!-- ============ 通知渠道 ============ -->
      <NTabPane name="notifiers" tab="通知渠道">
        <CyberPanel title="通知渠道" :subtitle="`${notifiers.length} 个 · Telegram / Webhook`" flush>
          <template #actions>
            <NButton size="small" type="primary" ghost @click="openEdit('notifier')">新建渠道</NButton>
          </template>
          <NDataTable
            :columns="notifierColumns" :data="notifiers" :loading="loading"
            size="small" :bordered="false" :single-line="false" :scroll-x="1060"
          />
          <div v-if="!notifiers.length && !loading" class="cy-empty">
            还没有通知渠道 —— 现在出了故障不会有人收到消息。
            建一个 Telegram 或 Webhook 渠道,建完记得点「发测试」确认能通。
          </div>
        </CyberPanel>
      </NTabPane>
    </NTabs>

    <!-- ============ 复制:要新地址的那几类 ============ -->
    <!-- **只问必须改的那一两项**,不是整张表单 —— 凭据和其它配置后端已经
         一起复制过去了,不用重填。这是"复制"和"照着新建一个"的全部区别 -->
    <NModal
      :show="!!dupAsk" preset="card" :bordered="false"
      :title="`复制「${dupAsk?.name ?? ''}」`"
      style="width: min(460px, 94vw)"
      @update:show="(v: boolean) => { if (!v) dupAsk = null }"
    >
      <template v-if="dupAsk">
        <div class="dup-hint">
          这一类<b>同一个地址只能加一台</b> —— 否则同一台机器会被采两遍,
          图上是两条一模一样的线、事件也开两条。给个新地址就行,
          <b>凭据和其它配置都会一起复制过去,不用重填</b>。
        </div>
        <div v-for="f in dupAsk.fields" :key="f" class="dup-row">
          <label>{{ FIELD_LABEL[f] || f }}</label>
          <NInput
            v-model:value="dupAsk.values[f]" size="small" clearable
            :placeholder="`源:${dupAsk.source[f] ?? ''}`"
            @keyup.enter="confirmDuplicate"
          />
        </div>
        <div class="dup-src">源那台是 {{ dupAsk.source[dupAsk.fields[0]] }}</div>
      </template>
      <template #footer>
        <NSpace justify="end">
          <NButton size="small" @click="dupAsk = null">取消</NButton>
          <NButton
            size="small" type="primary" :loading="duplicating > 0"
            :disabled="!dupAsk || dupAsk.fields.some((f) => !dupAsk!.values[f]?.trim())"
            @click="confirmDuplicate"
          >复制并保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- ============ 编辑弹窗 ============ -->
    <NModal
      v-model:show="modal" preset="card" :bordered="false"
      :title="`${isNew ? '新建' : '编辑'}${MODAL_TITLES[editing]}`"
      style="width: min(860px, 94vw)"
    >
      <div v-if="profileNote" class="profile-note">
        <b>型号采集特点:</b>{{ profileNote }}
      </div>
      <SchemaForm
        :model="form"
        :fields="currentFields.map((f) => (
          f.key === 'group' || f.key === 'groups' ? { ...f, options: groupOptions } : f
        ))"
        :errors="formErrors"
        :options-resolver="resolveOptions"
      />
      <template #footer>
        <NSpace justify="end">
          <NButton size="small" @click="modal = false">取消</NButton>
          <NButton size="small" type="primary" :loading="saving" @click="save">
            {{ isNew ? '创建' : '保存' }}
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- ============ 测试结果 ============ -->
    <NModal
      :show="!!testResult" preset="card" :bordered="false"
      :title="testResult?.title || ''"
      style="width: min(620px, 94vw)"
      @update:show="(v: boolean) => { if (!v) testResult = null }"
    >
      <div v-if="testResult" class="test-res">
        <div class="test-badge" :class="testResult.ok ? 'ok' : 'bad'">
          {{ testResult.ok ? '通' : '不通' }}
        </div>
        <div class="test-lines">
          <div v-for="(line, i) in testResult.lines" :key="i" class="test-line">{{ line }}</div>
        </div>
      </div>
      <template #footer>
        <NSpace justify="end">
          <NButton size="small" @click="testResult = null">关闭</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.cfg :deep(.n-tabs-nav) { margin-bottom: 12px; }

.dup-hint {
  font-size: 11.5px;
  line-height: 1.65;
  color: var(--cy-ink-2);
  padding: 6px 11px;
  margin-bottom: 12px;
  border-left: 2px solid var(--cy-line);
  background: color-mix(in srgb, var(--cy-raised) 60%, transparent);
}
.dup-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.dup-row label { font-size: 12px; color: var(--cy-ink-2); min-width: 56px; }
.dup-src { font-size: 10.5px; color: var(--cy-ink-3); font-family: 'JetBrains Mono', monospace; }

.profile-note {
  padding: 9px 12px;
  margin-bottom: 14px;
  font-size: 11.5px;
  line-height: 1.6;
  color: var(--cy-ink-2);
  background: rgba(var(--cy-cyan-rgb), 0.05);
  border-left: 2px solid rgba(var(--cy-cyan-rgb), 0.45);
}
.profile-note b { color: var(--cy-cyan); }

.test-res { display: flex; gap: 14px; align-items: flex-start; }
.test-badge {
  flex: none;
  padding: 4px 13px;
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.08em;
  clip-path: polygon(4px 0, 100% 0, calc(100% - 4px) 100%, 0 100%);
}
.test-badge.ok { background: var(--cy-up); color: var(--cy-on-state); }
.test-badge.bad { background: var(--cy-down); color: var(--cy-on-state); }
.test-lines { flex: 1; min-width: 0; }
.test-line {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11.5px;
  line-height: 1.75;
  color: var(--cy-ink-2);
  word-break: break-all;
}
</style>
