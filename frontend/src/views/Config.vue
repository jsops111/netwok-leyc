<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import {
  NButton, NDataTable, NInput, NModal, NPopconfirm, NSelect, NSpace, NSwitch,
  NTabPane, NTabs, NTag, useMessage,
} from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StateDot from '@/components/cyber/StateDot.vue'
import SchemaForm from '@/components/SchemaForm.vue'
import type { FieldSpec } from '@/components/SchemaForm.vue'
import { api, errText } from '@/api'
import type { DeviceRow, NotifierRow, ProbeGroup, ProbeTarget } from '@/api'
import { useMetaStore } from '@/stores/meta'
import { ago, endpoint, ms, pct, timeOf } from '@/composables/useFormat'
import { STATE } from '@/theme'

/**
 * 配置中心。四个 tab:监控类 / 检测线路 / 网络设备 / 通知渠道。
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
const notifiers = ref<NotifierRow[]>([])

async function loadAll() {
  loading.value = true
  try {
    const [g, p, d, n] = await Promise.all([
      api.groups({ page_size: 200 }),
      api.probes({ page_size: 500, ordering: 'group__order,order' }),
      api.devices({ page_size: 200, ordering: 'order' }),
      api.notifiers({ page_size: 100 }),
    ])
    groups.value = g.data.results
    probes.value = p.data.results
    devices.value = d.data.results
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
type EntityKind = 'group' | 'probe' | 'device' | 'notifier'
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
    collect_interfaces: true, enabled: true, order: 0,
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
      'api_token', 'telegram_bot_token',
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

  { key: 'ssh_username', label: 'SSH 用户名', type: 'text',
    show: (m) => [m.collect_method, m.fallback_method].includes('ssh') },
  { key: 'ssh_port', label: 'SSH 端口', type: 'number', min: 1, max: 65535,
    show: (m) => [m.collect_method, m.fallback_method].includes('ssh') },
  { key: 'ssh_password', label: 'SSH 密码', type: 'password',
    show: (m) => [m.collect_method, m.fallback_method].includes('ssh'),
    hint: '密码和私钥填一个即可' },
  { key: 'ssh_enable_password', label: 'enable 密码', type: 'password',
    show: (m) => [m.collect_method, m.fallback_method].includes('ssh') && m.vendor === 'cisco' },
  { key: 'ssh_private_key', label: 'SSH 私钥', type: 'textarea', rows: 4,
    show: (m) => [m.collect_method, m.fallback_method].includes('ssh') },

  { key: 'api_token', label: 'API Token', type: 'password',
    show: (m) => [m.collect_method, m.fallback_method].includes('api'),
    hint: 'FortiGate:系统 → 管理员 → REST API 管理员生成' },
  { key: 'api_scheme', label: 'API 协议', type: 'select',
    options: [{ label: 'https', value: 'https' }, { label: 'http', value: 'http' }],
    show: (m) => [m.collect_method, m.fallback_method].includes('api') },
  { key: 'api_port', label: 'API 端口', type: 'number', min: 1, max: 65535,
    show: (m) => [m.collect_method, m.fallback_method].includes('api') },
  { key: 'api_vdom', label: 'VDOM', type: 'text',
    show: (m) => [m.collect_method, m.fallback_method].includes('api'),
    hint: '单 VDOM 填 root' },
  { key: 'api_verify_tls', label: '校验 API 证书', type: 'switch',
    show: (m) => [m.collect_method, m.fallback_method].includes('api') },

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
  const map = { group: groupFields, probe: probeFields, device: deviceFields, notifier: notifierFields }
  return map[editing.value]
})

/** 表单里的动态选项:监控类列表要从接口来,不是枚举。 */
function resolveOptions(key: string) {
  if (key === 'protocol' || key === 'device_kind' || key === 'vendor' || key === 'device_model'
      || key === 'collect_method' || key === 'snmp_version' || key === 'snmp_sec_level'
      || key === 'notifier_kind' || key === 'severity' || key === 'event_kind') {
    return meta.options(key)
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
  { title: '操作', key: 'act', width: 118,
    render: (r) => h(NSpace, { size: 4 }, () => [
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
  { title: '操作', key: 'act', width: 172, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', ghost: true, loading: testing.value === r.id,
        onClick: () => testProbe(r) }, () => '测试'),
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
  { title: '频率', key: 'interval_seconds', width: 68, className: 'num',
    render: (r) => h('span', { style: 'font-size:11.5px' }, `${r.interval_seconds}s`) },
  { title: '最后采集', key: 'last_collected_at', width: 96,
    render: (r) => h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, ago(r.last_collected_at)) },
  { title: '启用', key: 'enabled', width: 66,
    render: (r) => h(NSwitch, { value: r.enabled, size: 'small', onUpdateValue: () => toggleEnabled('device', r) }) },
  { title: '操作', key: 'act', width: 208, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', ghost: true, loading: testing.value === r.id,
        onClick: () => testDevice(r) }, () => '测主通道'),
      r.fallback_method
        ? h(NButton, { size: 'tiny', ghost: true, onClick: () => testDevice(r, r.fallback_method) }, () => '测降级')
        : null,
      h(NButton, { size: 'tiny', ghost: true, onClick: () => openEdit('device', r) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => remove('device', r.id) }, {
        trigger: () => h(NButton, { size: 'tiny', text: true, type: 'error' }, () => '删除'),
        default: () => '确认删除?接口和历史样本会一起删掉',
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
  { title: '操作', key: 'act', width: 158, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', type: 'primary', ghost: true, loading: testing.value === r.id,
        onClick: () => testNotifier(r) }, () => '发测试'),
      h(NButton, { size: 'tiny', ghost: true, onClick: () => openEdit('notifier', r) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => remove('notifier', r.id) }, {
        trigger: () => h(NButton, { size: 'tiny', text: true, type: 'error' }, () => '删除'),
        default: () => '确认删除?',
      }),
    ]) },
]

const MODAL_TITLES: Record<EntityKind, string> = {
  group: '监控类', probe: '检测线路', device: '网络设备', notifier: '通知渠道',
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
