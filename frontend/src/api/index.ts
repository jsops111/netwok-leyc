import axios from 'axios'

/**
 * 后端 API 客户端。
 *
 * 大屏是**每几秒轮询一次**的,所以这里有两条和普通后台不一样的处理:
 *
 * 1. 请求失败不弹全局提示。轮询失败弹窗会在网络抖一下的时候堆出几十个框。
 *    错误交给调用方(usePolling)记录成一个"上次刷新失败"的状态,画在面板角上。
 * 2. 超时给得比较短(12s)。轮询间隔是 5s,一个挂了 30 秒的请求毫无价值,
 *    早点失败早点重试。
 */

export const http = axios.create({
  baseURL: '/api',
  timeout: 12000,
  headers: { 'Content-Type': 'application/json' },
  // 会话是 Django 的 session cookie,跨端口的 dev 环境要带上
  withCredentials: true,
})

function cookie(name: string): string {
  const hit = document.cookie.split('; ').find((c) => c.startsWith(`${name}=`))
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : ''
}

/**
 * CSRF。**自己读 cookie 塞进头里,不依赖 axios 的 xsrf 自动处理** ——
 * 后者在 withCredentials / 同源判断上有版本差异,而这条链路失效的症状是
 * 所有写操作返回 "CSRF Failed",指不到任何一行业务代码。
 *
 * csrftoken 由 GET /api/auth/session/ 种下(它带 @ensure_csrf_cookie),
 * 所以前端启动时那一次 session 请求是必须的,不是可有可无的探测。
 */
http.interceptors.request.use((config) => {
  const method = (config.method || 'get').toUpperCase()
  if (!['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method)) {
    const token = cookie('csrftoken')
    if (token) config.headers.set('X-CSRFToken', token)
  }
  return config
})

/** 收到 401 时被调用 —— 由 main.ts 注入,这里不 import router(会绕成循环依赖) */
let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

http.interceptors.response.use(
  (response) => response,
  (error) => {
    // 401 = 没登录(会话过期或从没登过)。403 是"登录了但权限不够",
    // 两者处置不同:前者跳登录页,后者原地提示 —— 后端专门把它们分开了
    // (见 accounts/exceptions.py),别在这里又合并回去
    if (error?.response?.status === 401) onUnauthorized?.()
    // 把 DRF 的字段级错误拍平成一句人能读的话,组件里直接展示
    const data = error?.response?.data
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      const parts: string[] = []
      for (const [key, value] of Object.entries(data)) {
        const text = Array.isArray(value) ? value.join('; ') : String(value)
        parts.push(key === 'detail' || key === 'non_field_errors' ? text : `${key}: ${text}`)
      }
      if (parts.length) error.friendlyMessage = parts.join('\n')
    }
    if (!error.friendlyMessage) {
      error.friendlyMessage = error?.message || '请求失败'
    }
    return Promise.reject(error)
  },
)

export function errText(error: unknown): string {
  const e = error as { friendlyMessage?: string; message?: string }
  return e?.friendlyMessage || e?.message || '未知错误'
}

// ---------------------------------------------------------------- 类型

export interface Paged<T> {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

export interface Choice {
  value: string
  label: string
}

export interface ProbeGroup {
  id: number
  name: string
  description: string
  color: string
  order: number
  enabled: boolean
  target_count: number
}

export interface ProbeTarget {
  id: number
  group: number
  group_name?: string
  name: string
  host: string
  protocol: string
  protocol_label?: string
  port: number | null
  interval_seconds: number
  timeout_ms: number
  packets: number
  http_path: string
  http_method: string
  http_expect_code: number
  http_expect_keyword: string
  http_verify_tls: boolean
  dns_query: string
  dns_expect: string
  latency_warn_ms: number
  latency_crit_ms: number
  loss_warn_pct: number
  loss_crit_pct: number
  jitter_warn_ms: number
  jitter_crit_ms: number
  fail_threshold: number
  recover_threshold: number
  enabled: boolean
  order: number
  state: string
  state_label?: string
  last_checked_at: string | null
  last_rtt_ms: number | null
  last_loss_pct: number | null
  last_jitter_ms: number | null
  last_error: string
  availability: number
  total_checks: number
  total_fail: number
  open_event_count: number
}

export interface DeviceRow {
  id: number
  name: string
  kind: string
  kind_label?: string
  vendor: string
  vendor_label?: string
  model: string
  model_label?: string
  mgmt_ip: string
  site: string
  os_version: string
  serial: string
  collect_method: string
  method_label?: string
  fallback_method: string
  interval_seconds: number
  timeout_ms: number
  snmp_port: number
  snmp_version: string
  snmp_v3_user: string
  snmp_v3_level: string
  snmp_v3_auth_proto: string
  snmp_v3_priv_proto: string
  ssh_port: number
  ssh_username: string
  api_scheme: string
  api_port: number | null
  api_vdom: string
  api_verify_tls: boolean
  cpu_warn_pct: number
  cpu_crit_pct: number
  mem_warn_pct: number
  mem_crit_pct: number
  temp_warn_c: number
  temp_crit_c: number
  session_warn: number
  if_util_warn_pct: number
  fail_threshold: number
  recover_threshold: number
  collect_interfaces: boolean
  collect_neighbors: boolean
  backup_enabled: boolean
  backup_interval_hours: number
  backup_keep: number
  last_backup_at: string | null
  last_backup_status: string
  last_backup_error: string
  backup_check_unsaved: boolean
  /** 三态:true=有未保存的改动 / false=已保存 / null=**没检查过或不支持** */
  config_unsaved: boolean | null
  config_unsaved_lines: number | null
  config_checked_at: string | null
  unsaved_diff: string[]
  profile_supports: { backup: boolean; policy: boolean; unsaved_check: boolean }
  policy_sync_enabled: boolean
  /** 仅 FortiGate。**开在别的厂商上不起作用**(后端 clean() 拦着) */
  collect_sdwan: boolean
  /** 平台自己的门限。**留空 = 只按设备自己的 SLA 判定** */
  sla_latency_warn_ms: number | null
  sla_loss_warn_pct: number | null
  policy_sync_interval_minutes: number
  last_policy_sync_at: string | null
  last_policy_error: string
  policy_count: number
  enabled: boolean
  order: number
  state: string
  state_label?: string
  last_collected_at: string | null
  last_method_used: string
  last_error: string
  has_snmp_community: boolean
  has_ssh_credential: boolean
  has_api_token: boolean
  interface_count: number
  profile_notes: string
}

export interface ServerRow {
  id: number
  name: string
  host: string
  /** 'linux' | 'esxi' —— 决定后端走哪一套采集命令,不是展示标签 */
  os_type: string
  ssh_port: number
  ssh_username: string
  site: string
  role: string
  net_interface: string
  interval_seconds: number
  timeout_ms: number
  cpu_warn_pct: number
  cpu_crit_pct: number
  mem_warn_pct: number
  mem_crit_pct: number
  disk_warn_pct: number
  disk_crit_pct: number
  load_warn: number
  load_crit: number
  fail_threshold: number
  recover_threshold: number
  collect_processes: boolean
  enabled: boolean
  order: number
  state: string
  state_label?: string
  last_collected_at: string | null
  last_error: string
  hostname: string
  os_name: string
  kernel: string
  cpu_cores: number | null
  mem_total_bytes: number | null
  has_credential: boolean
  uses_key: boolean
  interface_count: number
  primary_interface: string
  open_event_count: number
}

export interface ServerPoint {
  ts: string
  reachable?: boolean
  cpu_pct: number | null
  cpu_iowait_pct: number | null
  mem_pct: number | null
  swap_pct: number | null
  disk_pct: number | null
  load1: number | null
  load5: number | null
  load15: number | null
  net_in_bps: number | null
  net_out_bps: number | null
  tcp_established: number | null
  process_count: number | null
}

export interface ServerCard {
  /** 优先级(order)。**数字小的排在前面** —— 列表和大屏都按它排 */
  order: number
  id: number
  name: string
  host: string
  hostname: string
  site: string
  role: string
  os_name: string
  kernel: string
  cpu_cores: number | null
  mem_total_bytes: number | null
  state: string
  interval: number
  last_collected_at: string | null
  last_error: string
  open_events: number
  cpu: number | null
  mem: number | null
  disk: number | null
  load1: number | null
  net_in_bps: number | null
  net_out_bps: number | null
  load_per_core: number | null
  primary_interface: string
  thresholds: Record<string, number>
  trend: Array<{
    ts: string
    cpu: number | null
    mem: number | null
    disk: number | null
    load1: number | null
    net_in: number | null
    net_out: number | null
    up: boolean
  }>
}

export interface ServerMount {
  mount: string
  fs: string
  total_bytes: number
  used_bytes: number
  pct: number | null
}

export interface ServerInterfaceRow {
  id: number
  server: number
  if_name: string
  is_primary: boolean
  is_virtual: boolean
  in_bps: number | null
  out_bps: number | null
  in_err_delta: number | null
  out_err_delta: number | null
}

export interface ServerDetail {
  server: ServerRow
  ts: string | null
  reachable: boolean | null
  uptime_s: number | null
  mounts: ServerMount[]
  top_processes: Array<{ cpu: number; mem: number; name: string }>
  primary_interface: string
  interfaces: ServerInterfaceRow[]
  current: {
    cpu: number | null
    iowait: number | null
    mem: number | null
    swap: number | null
    disk: number | null
    load1: number | null
    load5: number | null
    load15: number | null
    net_in_bps: number | null
    net_out_bps: number | null
    tcp_established: number | null
    process_count: number | null
  }
  error: string
  cpu_pending: string
  notes: string[]
  /**
   * ESXi 专有,Linux 主机上是 null。
   *
   * ⚠ `vm_registered` / `vm_running` 为 **null 是"没采到",0 才是"这台空着"** ——
   * 混成 0 会让一台跑着三十台虚拟机、只是 vim-cmd 没权限的宿主显示成空宿主。
   */
  esxi: {
    vm_registered: number | null
    vm_running: number | null
    vm_names: string[]
    hw_platform: string
    cpu_total_mhz: number | null
    cpu_used_mhz: number | null
    cpu_threads: number | null
    cpu_packages: number | null
    maintenance_mode: boolean | null
  } | null
}

export interface BackupVersion {
  id: number
  device: number
  device_name?: string
  ts: string
  last_seen_at: string
  seen_count: number
  method: string
  size_bytes: number
  line_count: number
  content_hash: string
  short_hash: string
  lines_added: number | null
  lines_removed: number | null
  is_first: boolean
  content?: string
}

export interface DeviceBackupInfo {
  device: string
  enabled: boolean
  interval_hours: number
  keep: number
  last_backup_at: string | null
  last_backup_status: string
  last_backup_error: string
  versions: BackupVersion[]
}

export interface BackupDiff {
  detail?: string
  from: number | null
  to: number
  from_ts?: string
  to_ts?: string
  lines_added?: number | null
  lines_removed?: number | null
  lines: string[]
}

export interface PolicyRow {
  id: number
  device: number
  device_name: string
  vdom: string
  policy_id: number
  seq: number
  name: string
  src_intf: string[]
  dst_intf: string[]
  src_addr: string[]
  dst_addr: string[]
  service: string[]
  schedule: string
  action: string
  action_label: string
  enabled: boolean
  nat: boolean
  log_traffic: string
  comments: string
  uuid: string
  hit_count: number | null
  bytes_count: number | null
  packets: number | null
  sessions: number | null
  first_hit_at: string | null
  last_hit_at: string | null
  /** 三态:true=从未命中 / false=命中过 / null=**不知道**(SSH 通道没有计数) */
  never_hit: boolean | null
  /** 过宽规则:'critical'(any-any-any 放行)/ 'warning'(服务任意)/ ''(不算) */
  permissive_level: string
  /** 放行但不记日志 —— 出事之后查不出来源 */
  logging_off: boolean
  /** Cisco 才有:这条 ACE 属于哪个 ACL。FortiGate 上是空串 */
  acl_name: string
  /** 这个 ACL 绑在哪些接口的哪个方向。**空 = 完全不生效** */
  bindings: Array<{ interface: string; direction: string }>
  binding_text: string
  /**
   * 这一条是**我们补出来的隐含 `deny ip any any`**,设备的 show 里没有。
   * 不补的话人看着一张全是 permit 的表会以为没写到的流量是放行的;
   * 但必须标出来,否则人会去设备上找这一行然后找不到。
   */
  implicit: boolean
  is_acl: boolean
  /**
   * 目的地址里那几个名字中,哪些其实是**映射**(VIP)。
   *
   * 策略表里 `dst_addr` 只有一个 `web-vip` 这样的名字,**它指向内网哪台机器
   * 的哪个端口完全不在策略表里** —— 这个字段就是把同一次同步拿回来的映射表
   * 接上去的结果。
   *
   * ⚠ `null` 是「这次没查映射表」,`[]` 是「目的地址里没有映射」。
   * 混成一个空数组会让人以为这条策略直接指向一个真实地址。
   */
  mappings: PolicyMapping[] | null
  synced_at: string
  method: string
  raw?: Record<string, any>
}

/** 策略的目的地址上接出来的一条映射,字段是 VipRow 的子集 */
export interface PolicyMapping {
  id: number
  name: string
  /** `tcp/1.2.3.4:443 → 10.0.0.5:8443` —— 端口为空时说「所有端口」,由后端拼好 */
  endpoint_text: string
  ext_ip: string
  ext_port_text: string
  mapped_ip: string
  mapped_port_text: string
  protocol: string
  vip_type: string
  /** 整机映射:外网地址的**所有端口**都通到内网那台机器上 */
  whole_host: boolean
}

export interface VipRow {
  id: number
  device: number
  device_name: string
  vdom: string
  name: string
  seq: number
  vip_type: string
  vip_type_label: string
  ext_intf: string[]
  ext_ip: string
  ext_port: string
  /** 端口为空时是「所有端口」而不是空串 —— 后端算好,前端不要再判一遍 */
  ext_port_text: string
  mapped_ip: string
  mapped_port: string
  mapped_port_text: string
  protocol: string
  port_forward: boolean
  endpoint_text: string
  whole_host: boolean
  comment: string
  uuid: string
  /**
   * 引用这条映射的策略。**空数组 = 没有策略引用它 = 这条映射不生效**(可以清理);
   * `null` = 这次没查引用关系。两者不能混 —— 后者拿去删规则会删掉在用的。
   */
  used_by: Array<{
    id: number; policy_id: number; seq: number
    name: string; enabled: boolean; action: string
  }> | null
  synced_at: string
  method: string
}

// ------------------------------------------------- 端口面板图

/**
 * 面板上的一个口。**继承 InterfaceRow 的全部字段** —— 点一个口弹出来的信息
 * 必须和 `/interfaces` 那张表对得上,否则同一个口在两个地方显示不同的速率,
 * 而看不出哪个是对的。
 */
export interface FacePort extends InterfaceRow {
  row: number
  col: number
  /** 面板上印的那个号。`renumbered` 为真时它只是顺序,以接口名为准 */
  port_no: number
  /**
   * `up` 通 / `down` **admin up 但链路 down**(该通没通)/
   * `admin_down` 人为关掉的 / `unknown` 没采到。
   *
   * ⚠ `admin_down` **不是红色**:48 口交换机上一半的口是人为关掉的,
   * 全画红的话真正断掉的那一个就淹在里面了。
   */
  state: 'up' | 'down' | 'admin_down' | 'unknown'
}

export interface FaceBank {
  label: string
  /**
   * 堆叠成员号(StackWise)。**两台堆叠 = 两块面板** ——
   * `Gi1/0/30` 和 `Gi2/0/30` 是两台不同机器上的口,画成一排的话
   * 人照着数第 30 个格子会落在另一台上。
   * 不是堆叠时为 null。
   */
  member: number | null
  rows: number
  cols: number
  shape: string
  /** 面板号重新编过 —— 那时位置只表示顺序,和实物对不上 */
  renumbered: boolean
  ports: FacePort[]
}

export interface Faceplate {
  device: {
    id: number; name: string; mgmt_ip: string
    model: string; model_label: string
    vendor: string; kind: string; state: string
    last_collected_at: string | null
  }
  /** 这个布局在实机上核对过吗 */
  verified: boolean
  /** 没有这款型号的面板几何 —— 位置只表示顺序 */
  schematic: boolean
  label: string
  banks: FaceBank[]
  /** 没落到面板上的口(Vlan / Port-channel / Loopback)。**必须显示** */
  unplaced: FacePort[]
  /** 页面上要**原样显示**的那句话 —— 画错的面板比没有面板危险 */
  note: string
  counts: { up: number; down: number; admin_down: number; unknown: number; total: number }
}

// ------------------------------------------------- 防火墙地址对象 / 地址组

export interface AddressRow {
  id: number
  device: number
  device_name: string
  vdom: string
  name: string
  seq: number
  addr_type: string
  addr_type_label: string
  is_group: boolean
  value: string
  /** 「这一行是什么」,后端拼好 —— 前端各拼一遍总有一处会把点分掩码原样显示 */
  display: string
  members: string[]
  /** **不是组时是 null,不是 0** —— 0 会被读成"这个组是空的" */
  member_count: number | null
  comment: string
  interface: string
  uuid: string
  synced_at: string
  method: string
}

/** 展开结果的一个节点。组会递归带 members */
export interface AddressNode {
  name: string
  /** `address` 单个对象 / `group` 地址组 / `builtin` 内置名(all、none)/ `unknown` **没同步到** */
  kind: 'address' | 'group' | 'builtin' | 'unknown'
  value: string
  members: AddressNode[]
  /** 拍平后的叶子 —— 人问"这个别名是哪些地址",要的就是这张表 */
  leaves: Array<{ name: string; value: string; addr_type: string }>
  /** 这一支被环检测掐掉了(组 A 含组 B、组 B 含组 A) */
  cycle: boolean
  truncated: boolean
}

export interface AddressResolve {
  device: number
  query: string
  /** api / ssh —— **API 能拿到内置对象,SSH 拿不到**,同一个别名结果会不一样 */
  method: string
  synced_at: string | null
  total_objects: number
  result: AddressNode
  used_by: Array<{
    id: number; policy_id: number; seq: number; name: string
    enabled: boolean; action: string
    /** 引用在「源」还是「目的」 */
    where: string
  }>
}

export interface AddressSummaryRow {
  device_id: number
  device_name: string
  mgmt_ip: string
  vdom: string
  state: string
  total: number
  groups: number
  method: string
  synced_at: string | null
  /** 0 个对象**不等于**这台没有配 —— 这句话由后端给 */
  note: string
}

export interface ServiceRow {
  id: number
  device: number
  device_name: string
  vdom: string
  name: string
  seq: number
  is_group: boolean
  /** `TCP/443, UDP/53` —— 后端拼好。FortiOS 的 `443:1024-65535` 里
   *  冒号后面那半是**源端口**,不是目的端口,解错会显示成六万个端口 */
  value: string
  display: string
  protocol: string
  members: string[]
  member_count: number | null
  category: string
  comment: string
  predefined: boolean
  synced_at: string
  method: string
}

// ------------------------------------------------- Cisco 访问控制(ACL)

export interface AclBoard {
  generated_at: string
  totals: {
    devices: number; acls: number; rules: number
    /** **一个接口都没绑的 ACL = 完全不生效**,这一页最该先看见的数 */
    unbound_acls: number
    wide_open: number; no_log: number
  }
  devices: Array<{
    device_id: number; device_name: string; mgmt_ip: string
    model_label: string; kind: string; state: string
    synced_at: string; last_error: string
    acls: Array<{
      name: string
      bindings: Array<{ interface: string; direction: string }>
      /** 不含补出来的隐含规则 */
      rule_count: number
      permit: number; deny: number
      /** 一个接口都没绑 —— 这个 ACL 不生效 */
      unbound: boolean
      wide_open: number; no_log: number; never_hit: number
      has_hit_stats: boolean
      rules: PolicyRow[]
    }>
  }>
  /** 开了同步但一条 ACL 都没拿到的 Cisco 设备 —— **"没同步到"不是"没有 ACL"** */
  devices_without_data: Array<{ device_id: number; device_name: string; last_error: string }>
  /**
   * **开关根本没开的 Cisco 设备。**这是这一页空着时最常见的原因 ——
   * 泛泛说一句"到配置中心打开"人不知道该去开哪一台,所以把名字点出来。
   */
  devices_not_enabled: Array<{
    device_id: number; device_name: string; model_label: string
    kind: string
    /** Cisco 同步只能走 SSH,缺凭据的话开了也跑不起来 */
    has_ssh: boolean
  }>
}

// ------------------------------------------------- SD-WAN 性能 SLA

export interface SdwanLinkRow {
  id: number
  device: number
  device_name: string
  vdom: string
  health_check: string
  member: string
  server: string
  protocol: string
  /** `alive` / `dead` / **`unknown`(这一拍没读到,不等于它是通的)** */
  state: string
  state_label: string
  latency_ms: number | null
  jitter_ms: number | null
  loss_pct: number | null
  /**
   * 达标了吗。**三态**:true 达标 / false 未达标 /
   * **null = 设备没报**(没配 SLA 目标,或这个固件不给这一项)。
   * null 显示成"达标"就是替设备做一个它没做的判断。
   */
  sla_met: boolean | null
  sla_targets_met: number | null
  sla_targets_total: number | null
  /** 三态各自的说法,后端拼好 */
  sla_text: string
  /**
   * 设备上配的 SLA 门限(**最严的那一档**,多档时每个指标各取最小的非空值)。
   * 来自 `config system sdwan`,monitor 端点只给实测值不给门限 ——
   * 没有它的话"延迟 186ms"这个数没法判断算不算超。
   *
   * ⚠ `null` = 那一档没配这个指标(FortiOS 里配 0 就是"不看这一项"),
   * **不是"要求 0"**。
   */
  sla_latency_threshold: number | null
  sla_jitter_threshold: number | null
  sla_loss_threshold: number | null
  tx_bps: number | null
  rx_bps: number | null
  session_count: number | null
  last_change: string | null
  synced_at: string
  method: string
  series?: Array<{
    ts: string; latency: number | null; jitter: number | null
    loss: number | null; state: string
  }>
}

export interface SdwanBoard {
  generated_at: string
  hours: number
  verdict: 'ok' | 'warn' | 'crit' | 'unknown'
  totals: {
    devices: number; links: number
    alive: number; dead: number; unknown: number
    sla_ok: number; sla_bad: number
    /** **设备没报 SLA 判定的单独一栏** */
    sla_unknown: number
    latency_max: number | null
    latency_avg: number | null
    /** 最慢那条**点名** */
    latency_max_link: string | null
  }
  devices: Array<{
    device_id: number; device_name: string; mgmt_ip: string; vdom: string
    state: string; method: string; synced_at: string; last_error: string
    /** 平台自己的门限 —— **不是设备的 SLA**,页面上要说清楚 */
    sla_latency_warn_ms: number | null
    sla_loss_warn_pct: number | null
    links: SdwanLinkRow[]
    alerts: Array<{
      kind: string; kind_label: string; severity: string
      message: string; started_at: string
    }>
  }>
  /** 开了开关但一条链路都没采到的设备 —— **"没采到"不是"没配"** */
  devices_without_data: Array<{ device_id: number; device_name: string; last_error: string }>
}

// ------------------------------------------------- 带外硬件(iDRAC)

export interface IdracRow {
  id: number
  name: string
  host: string
  port: number
  username: string
  site: string
  role: string
  server: number | null
  server_name?: string
  interval_seconds: number
  timeout_ms: number
  verify_tls: boolean
  temp_warn_c: number
  temp_crit_c: number
  temp_delta_warn_c: number
  ssd_life_warn_pct: number
  event_window_days: number
  fail_threshold: number
  recover_threshold: number
  collect_events: boolean
  enabled: boolean
  order: number
  state: string
  state_label?: string
  last_collected_at: string | null
  last_error: string
  model_name: string
  manufacturer: string
  service_tag: string
  bios_version: string
  idrac_firmware: string
  system_hostname: string
  power_state: string
  has_credential?: boolean
  open_event_count?: number
}

/**
 * 一个部件的三元组 `[总数, 异常数, 未知数]`。
 *
 * ⚠ **未知不并进任何一边。**并进异常会天天误报,并进正常会在真出事时闭嘴
 * ——「读不到这块盘的状态」和「这块盘是好的」是两个结论。
 * 某一项整个是 `[null,null,null]` 表示这台还没采过。
 */
export type PartTriple = [number | null, number | null, number | null]

export interface IdracBoardHost {
  id: number
  name: string
  host: string
  site: string
  role: string
  model: string
  service_tag: string
  power_state: string
  server_id: number | null
  server_name: string
  /**
   * 大屏上的档位。**六档,每台只落一档**:
   * `pending` 还没轮到采(不是故障)/ `down` 带外连不上 /
   * `crit` 有严重告警 / `warn` 有警告 / `unknown` 部件状态读不到 / `ok`
   */
  level: 'ok' | 'warn' | 'crit' | 'unknown' | 'down' | 'pending'
  state: string
  health: string | null
  reachable: boolean | null
  ts: string | null
  last_error: string
  interval: number
  metrics: {
    power_watts: number | null
    inlet_temp_c: number | null
    max_temp_c: number | null
    /** 同机两颗 CPU 的温差 —— iDRAC 自己没有这条判据 */
    temp_delta_c: number | null
    fan_max_rpm: number | null
  }
  parts: {
    disk: PartTriple; psu: PartTriple; memory: PartTriple
    fan: PartTriple; vdisk: PartTriple
  }
  hottest: string
  sel_recent: number | null
  alerts: IdracAlert[]
}

export interface IdracAlert {
  host_id?: number
  host?: string
  kind: string
  kind_label: string
  severity: string
  message: string
  started_at: string
}

export interface IdracBoard {
  generated_at: string
  verdict: 'ok' | 'warn' | 'crit' | 'unknown'
  totals: {
    hosts: number; ok: number; warn: number; crit: number
    unknown: number; pending: number; down: number
    disk_total: number; disk_bad: number; disk_unknown: number; ssd_worn: number
    /** SMART 预警**单独一栏**:盘还在跑、Health 还是绿的,但它快坏了 */
    disk_smart: number
    psu_total: number; psu_bad: number; psu_redundancy_lost: number
    memory_total: number; memory_bad: number
    fan_total: number; fan_bad: number
    vdisk_total: number; vdisk_bad: number
    power_watts: number | null
    sel_recent_critical: number
    /** 告警**条数**(不是台数) */
    alert_crit: number; alert_warn: number
    temp_max: number | null
    temp_avg: number | null
    /** 最热那台**点名** —— 只给数字的话人还得自己去表里找 */
    temp_max_host: string | null
  }
  /**
   * 四张大卡画的**分布**,不是趋势 —— X 轴是「N 台按高低排好序」。
   * 排序在后端做完(逐块盘的明细不在大屏 payload 里)。
   */
  distributions: {
    temps: number[]
    deltas: number[]
    /** **只有 SSD**。机械盘没有这个概念,升序 —— 最该看的排最前 */
    lives: number[]
    fans: number[]
  }
  hosts: IdracBoardHost[]
  alerts: IdracAlert[]
}

export interface IdracDisk {
  name: string; health: string; media: string
  capacity_gb: number | null; model: string; serial: string
  /** SMART 预警:还在跑,但快坏了。等 health 变红时盘通常已经掉了 */
  smart_alert: boolean
  /** **只有 SSD 有。**机械盘一律 null —— 它返回 0 不是"寿命耗尽",是"没有这个概念" */
  life_pct: number | null
  is_ssd: boolean
  slot: string
}

export interface IdracDetail {
  host: IdracRow
  ts: string | null
  reachable: boolean | null
  health: string | null
  error: string
  disks: IdracDisk[]
  volumes: Array<{ name: string; health: string; raid_type: string
                   capacity_gb: number | null; remaining_redundancy: number | null }>
  memory: Array<{ name: string; health: string; size_mib: number | null
                  speed_mhz: number | null; manufacturer: string; serial: string }>
  psus: Array<{ name: string; health: string; capacity_w: number | null
                input_voltage: number | null; model: string }>
  fans: Array<{ name: string; rpm: number | null; units: string; health: string }>
  temps: Array<{ name: string; celsius: number | null; warn_c: number | null
                 crit_c: number | null; health: string
                 is_inlet: boolean; is_exhaust: boolean }>
  sel: {
    entries: Array<{ id: string; severity: string; message: string
                     at: string | null; in_window: boolean }>
    total: number; window_days: number
    recent_critical: number; recent_warning: number
    /** 时间戳解不出来的条数 —— 它们不计入窗口计数,单独报 */
    undated: number
  } | null
  notes: string[]
  /** 哪一段没取到、为什么。**没有它,"硬盘 0 块"看着像这台机器没有硬盘** */
  endpoint_errors: Record<string, string>
  current: {
    power_watts: number | null; inlet_temp_c: number | null
    max_temp_c: number | null; temp_delta_c: number | null; hottest: string
  }
}

export interface IdracSamplePoint {
  ts: string; reachable: boolean
  power_watts: number | null; inlet_temp_c: number | null
  max_temp_c: number | null; temp_delta_c: number | null
  fan_max_rpm: number | null
  disk_bad: number | null; psu_bad: number | null
  health: string
}

export interface VipSummary {
  generated_at: string
  total: number
  whole_host: { count: number; hint: string; items: VipBrief[] }
  unused: { count: number; hint: string; items: VipBrief[] }
  /** 这批数据里一条映射都没有的防火墙。**不等于"这几台没有映射"** —— 见后端注释 */
  devices_without_vips: string[]
}

export interface VipBrief {
  id: number
  device_id: number
  device_name: string
  vdom: string
  name: string
  endpoint_text: string
  vip_type: string
  whole_host: boolean
  comment: string
}

export interface PolicySummaryRow {
  device_id: number
  device_name: string
  mgmt_ip: string
  vdom: string
  state: string
  synced_at: string | null
  error: string
  interval_minutes: number
  total: number
  accept: number
  deny: number
  disabled: number
  has_hit_stats: boolean
  never_hit: number | null
  /** 过宽的放行规则条数。不依赖命中统计,SSH 通道也能判 */
  wide_open: number
  /** 放行但不记日志的条数 */
  no_log: number
}

export interface PolicyAuditItem {
  id: number
  device_id: number
  device_name: string
  vdom: string
  policy_id: number
  seq: number
  name: string
  action: string
  enabled: boolean
  src_addr: string[]
  dst_addr: string[]
  service: string[]
  hit_count: number | null
  comments: string
  level?: string
  reason?: string
  shadowed_by?: { id: number; policy_id: number; seq: number; name: string; action: string }
}

export interface PolicyAudit {
  generated_at: string
  total: number
  has_hit_stats: boolean
  findings: Array<{
    key: string
    label: string
    hint: string
    /** null = 无法判断(没有命中统计时的「从未命中」) */
    count: number | null
    items: PolicyAuditItem[]
  }>
}

export interface InterfaceRow {
  id: number
  device: number
  device_name: string
  if_index: number
  if_name: string
  if_alias: string
  if_type: string
  mac: string
  speed_bps: number | null
  admin_up: boolean | null
  oper_up: boolean | null
  last_change: string | null
  monitored: boolean
  in_bps: number | null
  out_bps: number | null
  in_err_delta: number | null
  out_err_delta: number | null
  util_in_pct: number | null
  util_out_pct: number | null
  /** 退回了 32 位计数器 → **这一行的速率不可信** */
  counter_32bit: boolean
  /** admin up 但链路 down —— 真正要看的那一类口 */
  link_problem: boolean
  updated_at: string
}

export interface InterfaceSummaryRow {
  /**
   * **几个数要加得起来**:`total = up + admin_down + problem + unknown`。
   * 原来只有 total 和 up,人一减发现少了一批口、不知道去哪了 ——
   * 那些是人为关掉的(48 口交换机上一半是关着的很正常)。
   */
  admin_down: number
  /** 状态没采到。**单独一档**,不并进通也不并进不通 */
  unknown: number
  /**
   * **实体口**(能在机柜前面数出来的那些)。逻辑口(Vlan / Port-channel /
   * Loopback / Tunnel)不算 —— 混在一个「接口数」里的话页面上的数字和
   * 实物对不上,而"对不上"本身会让人怀疑整个采集。
   */
  physical: number
  physical_up: number
  logical: number
  device_id: number
  device_name: string
  mgmt_ip: string
  kind: string
  state: string
  model_label: string
  collect_interfaces: boolean
  last_collected_at: string | null
  total: number
  up: number
  problem: number
  errors: number
  unmonitored: number
  counter_32bit: number
}

export interface NeighborRow {
  id: number
  device: number
  device_name: string
  protocol: string
  local_if_index: number | null
  local_if_name: string
  /** false = 本地口没解析出 ifIndex,**不知道挂在哪个口** */
  local_resolved: boolean
  remote_device: string
  remote_port: string
  remote_platform: string
  remote_mgmt_ip: string
  remote_chassis_id: string
  matched_device: number | null
  matched_device_name: string
  first_seen: string
  last_seen: string
  changed_at: string | null
}

export interface NeighborSummaryRow {
  device_id: number
  device_name: string
  mgmt_ip: string
  kind: string
  state: string
  model_label: string
  last_collected_at: string | null
  method: string
  total: number
  lldp: number
  cdp: number
  managed: number
  changed: number
  unresolved: number
  /** 邻居只有 SNMP 通道采得到 —— false 时"0 条"不等于"没接线" */
  snmp_channel: boolean
}

export interface TopologyLink {
  a_device_id: number
  a_device: string
  a_port: string
  b_device_id: number
  b_device: string
  b_port: string
  protocol: string
  confirmed_by: string[]
  bidirectional: boolean
  last_seen: string
  changed_at: string | null
}

export interface ComplianceFinding {
  key: string
  label: string
  severity: string
  why: string
  fix: string
  kind: string
  hit_count: number
  hits: Array<{ line: number; text: string }>
}

export interface ComplianceRow {
  device_id: number
  device_name: string
  mgmt_ip: string
  vendor: string
  vendor_label: string
  model_label: string
  kind: string
  rule_count: number
  backup_at: string | null
  backup_hash: string
  supported: boolean
  /** false = **没检查**(没规则或没备份),不等于合规 */
  checked: boolean
  reason: string
  findings: ComplianceFinding[]
  critical: number
  warning: number
  info: number
  passed: number
}

export interface LookupResult {
  query: string
  kind: string
  mac: string
  arp: Array<{ device_id: number; device_name: string; if_index: number | null; if_name: string; mac: string }>
  hits: Array<{
    device_id: number
    device_name: string
    mgmt_ip: string
    vlan: string
    bridge_port: string
    if_index: number | null
    if_name: string
    /** false = 桥端口号没翻成 ifIndex,**不要照着它拔线** */
    port_resolved: boolean
    note: string
    source: string
  }>
  errors: Array<{ device: string; error: string }>
  searched: number
  detail?: string
  multi_note?: string
}

export interface EventRow {
  id: number
  source_type: string
  source_type_label: string
  source_name: string
  group_name: string
  target: number | null
  device: number | null
  interface: number | null
  kind: string
  kind_label: string
  severity: string
  severity_label: string
  title: string
  message: string
  started_at: string
  resolved_at: string | null
  duration_s: number | null
  live_duration_s: number
  trigger_value: number | null
  threshold: number | null
  unit: string
  fail_count: number
  notified_alert: boolean
  notified_recover: boolean
  acknowledged_at: string | null
  acknowledged_by: string
  note: string
  is_open: boolean
}

export interface NotifierRow {
  id: number
  name: string
  kind: string
  kind_label?: string
  enabled: boolean
  telegram_chat_id: string
  telegram_api_base: string
  telegram_thread_id: string
  webhook_url: string
  webhook_method: string
  webhook_headers: Record<string, string>
  webhook_template: string
  webhook_verify_tls: boolean
  timeout_seconds: number
  on_alert: boolean
  on_recover: boolean
  min_severity: string
  kinds: string[]
  groups: number[]
  group_names: string[]
  cooldown_seconds: number
  last_sent_at: string | null
  last_error: string
  total_sent: number
  total_failed: number
  has_token: boolean
}

export interface SeriesPoint {
  ts: string
  rtt: number | null
  rtt_max?: number | null
  loss: number | null
  jitter: number | null
  ok?: boolean
}

export interface ChartGroup {
  group: { id: number; name: string; color: string; description: string }
  granularity: string
  lines: Array<{
    id: number
    name: string
    host: string
    protocol: string
    port: number | null
    state: string
    interval: number
    /** 优先级(order)。**数字小的排在前面** —— 这一屏的排序就是按它 */
    order: number
    last_rtt: number | null
    last_loss: number | null
    last_jitter: number | null
    last_error: string
    availability: number
    open_events: number
    thresholds: Record<string, number>
    series: SeriesPoint[]
  }>
  summary: { total: number; down: number; degraded: number; truncated: boolean }
}

export interface Overview {
  window_hours: number
  generated_at: string
  tiles: Array<{ kind: string; label: string; count: number; open: number }>
  events: { total: number; open: number; critical_open: number; device_total: number }
  probes: {
    total: number; up: number; degraded: number; down: number; unknown: number
    availability: number | null; total_checks: number
  }
  devices: {
    total: number; up: number; degraded: number; down: number
    switches: number; firewalls: number
  }
  servers: { total: number; up: number; degraded: number; down: number; unknown: number }
  backup: { enabled: number; failed: number; never: number }
  scheduler: Record<string, any>
}

export interface DeviceCard {
  /** 优先级(order)。**数字小的排在前面** —— 列表和大屏都按它排 */
  order: number
  id: number
  name: string
  kind: string
  vendor: string
  model: string
  model_label: string
  mgmt_ip: string
  site: string
  os_version: string
  serial: string
  state: string
  method: string
  last_collected_at: string | null
  last_error: string
  open_events: number
  cpu: number | null
  mem: number | null
  temp: number | null
  sessions: number | null
  thresholds: Record<string, number>
  absent_metrics: string[]
  optional_metrics: string[]
  trend: Array<{ ts: string; cpu: number | null; mem: number | null; temp: number | null; sessions: number | null; up: boolean }>
  interfaces: Array<{
    name: string; alias: string; in_bps: number | null; out_bps: number | null
    speed_bps: number; util_in: number | null; util_out: number | null; errors: number
  }>
}

export interface Me {
  id: number
  username: string
  display_name: string
  email: string
  is_staff: boolean
  is_superuser: boolean
  last_login: string | null
  two_factor: boolean
  recovery_left: number
}

export interface UserRow extends Me {
  is_active: boolean
  date_joined: string
  last_login_ip: string
  password?: string
}

export interface LoginAuditRow {
  id: number
  username: string
  user: number | null
  result: string
  result_label: string
  used_2fa: boolean
  ip: string | null
  user_agent: string
  detail: string
  created_at: string
}

export interface RetentionPolicy {
  raw_hours: number
  rollup_1m_days: number
  rollup_5m_days: number
  rollup_1h_days: number
  event_days: number
  notify_log_days: number
  login_audit_days: number
  updated_at?: string
  updated_by?: string
}

export interface SystemInfo {
  version: string
  time: string
  timezone: string
  debug: boolean
  tick_seconds: number
  raw_retention_hours: number
  session_days: number
  retention: RetentionPolicy
  disk: {
    ok: boolean
    path?: string
    total?: number
    used?: number
    free?: number
    percent?: number | null
    error?: string
  }
  growth: {
    rows_per_day?: number
    bytes_per_row?: number | null
    bytes_per_day?: number | null
    steady_bytes?: number | null
    error?: string
  }
  database: { ok: boolean; version?: string; error?: string }
  scheduler: Record<string, any>
  counts: Record<string, number> & { error?: string; samples_estimated?: any }
  tables: Array<{ name: string; bytes: number; pretty: string }>
}

// ---------------------------------------------------------------- 接口

export const api = {
  // 大屏
  overview: (hours = 24) => http.get<Overview>('/dashboard/overview/', { params: { hours } }),
  charts: (minutes = 30, maxLines = 12) =>
    http.get<{ groups: ChartGroup[]; generated_at: string }>('/dashboard/charts/', {
      params: { minutes, max_lines: maxLines },
    }),
  deviceCards: (hours = 3) =>
    http.get<{ switches: DeviceCard[]; firewalls: DeviceCard[]; others: DeviceCard[] }>(
      '/dashboard/devices/', { params: { hours } },
    ),
  choices: () => http.get<Record<string, Choice[]>>('/meta/choices/'),
  health: () => http.get('/health/'),

  // 监控类
  groups: (params?: object) => http.get<Paged<ProbeGroup>>('/probe-groups/', { params }),
  createGroup: (body: Partial<ProbeGroup>) => http.post<ProbeGroup>('/probe-groups/', body),
  updateGroup: (id: number, body: Partial<ProbeGroup>) => http.patch<ProbeGroup>(`/probe-groups/${id}/`, body),
  deleteGroup: (id: number) => http.delete(`/probe-groups/${id}/`),

  // 线路
  probes: (params?: object) => http.get<Paged<ProbeTarget>>('/probes/', { params }),
  createProbe: (body: Partial<ProbeTarget>) => http.post<ProbeTarget>('/probes/', body),
  updateProbe: (id: number, body: Partial<ProbeTarget>) => http.patch<ProbeTarget>(`/probes/${id}/`, body),
  deleteProbe: (id: number) => http.delete(`/probes/${id}/`),
  testProbe: (id: number) => http.post(`/probes/${id}/test/`),
  probeNow: (id: number) => http.post(`/probes/${id}/probe_now/`),
  probeSeries: (id: number, hours = 1) =>
    http.get<{ granularity: string; points: number; series: SeriesPoint[] }>(
      `/probes/${id}/series/`, { params: { hours } },
    ),

  // 设备
  devices: (params?: object) => http.get<Paged<DeviceRow>>('/devices/', { params }),
  createDevice: (body: Partial<DeviceRow>) => http.post<DeviceRow>('/devices/', body),
  updateDevice: (id: number, body: Partial<DeviceRow>) => http.patch<DeviceRow>(`/devices/${id}/`, body),
  deleteDevice: (id: number) => http.delete(`/devices/${id}/`),
  testDevice: (id: number, method?: string) => http.post(`/devices/${id}/test/`, { method }),
  collectNow: (id: number) => http.post(`/devices/${id}/collect_now/`),
  deviceProfiles: () => http.get('/devices/profiles/'),
  deviceInterfaces: (id: number, active = false) =>
    http.get(`/devices/${id}/interfaces/`, { params: { active: active ? 'true' : undefined } }),
  interfaces: (params?: object) => http.get<Paged<InterfaceRow>>('/interfaces/', { params }),
  interfaceSummary: () =>
    http.get<{ generated_at: string; devices: InterfaceSummaryRow[] }>('/interfaces/summary/'),
  toggleInterfaceMonitor: (id: number) =>
    http.post<{ id: number; monitored: boolean }>(`/interfaces/${id}/toggle_monitor/`),
  // 邻居 / 拓扑
  neighbors: (params?: object) => http.get<Paged<NeighborRow>>('/neighbors/', { params }),
  neighborSummary: () =>
    http.get<{ generated_at: string; devices: NeighborSummaryRow[] }>('/neighbors/summary/'),
  topology: () =>
    http.get<{
      generated_at: string; links: TopologyLink[]
      total: number; bidirectional: number; one_way: number; one_way_hint: string
    }>('/neighbors/topology/'),
  discoverNeighbors: (id: number) =>
    http.post<{ ok: boolean; detail: string }>(`/devices/${id}/discover_neighbors/`),
  neighborExportUrl: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
    }
    const qs = q.toString()
    return `/api/neighbors/export/${qs ? `?${qs}` : ''}`
  },

  // 配置合规基线
  compliance: (deviceId?: number) =>
    http.get<{
      generated_at: string; rule_total: number; supported_vendors: string[]
      devices: ComplianceRow[]
      totals: {
        devices: number; checked: number; not_checked: number
        critical: number; warning: number; info: number; clean: number
      }
    }>('/devices/compliance/', { params: { device: deviceId } }),

  // MAC / IP 查找
  macLookup: (query: string, devices: number[]) =>
    http.post<LookupResult>('/devices/lookup/', { query, devices }),

  interfaceExportUrl: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
    }
    const qs = q.toString()
    return `/api/interfaces/export/${qs ? `?${qs}` : ''}`
  },
  deviceSeries: (id: number, hours = 6) => http.get(`/devices/${id}/series/`, { params: { hours } }),

  // 服务器(SSH 采集)
  servers: (params?: object) => http.get<Paged<ServerRow>>('/servers/', { params }),
  createServer: (body: Partial<ServerRow>) => http.post<ServerRow>('/servers/', body),
  updateServer: (id: number, body: Partial<ServerRow>) => http.patch<ServerRow>(`/servers/${id}/`, body),
  deleteServer: (id: number) => http.delete(`/servers/${id}/`),
  testServer: (id: number) => http.post<{ ok: boolean; detail: string }>(`/servers/${id}/test/`),
  collectServerNow: (id: number) => http.post(`/servers/${id}/collect_now/`),
  serverSeries: (id: number, hours = 6) =>
    http.get<{ points: number; interval: number; series: ServerPoint[] }>(
      `/servers/${id}/series/`, { params: { hours } },
    ),
  serverDetail: (id: number) => http.get<ServerDetail>(`/servers/${id}/detail_info/`),
  serverCards: (hours = 3) =>
    http.get<{
      total: number; up: number; degraded: number; down: number
      generated_at: string; servers: ServerCard[]
    }>('/dashboard/servers/', { params: { hours } }),

  // 配置备份
  deviceBackupInfo: (id: number) => http.get<DeviceBackupInfo>(`/devices/${id}/backups/`),
  backupNow: (id: number) => http.post<{ detail: string }>(`/devices/${id}/backup_now/`),
  testDeviceBackup: (id: number) => http.post<{ ok: boolean; detail: string }>(`/devices/${id}/test_backup/`),
  backupVersion: (id: number) => http.get<BackupVersion>(`/backups/${id}/`),
  backupDiff: (id: number, against?: number) =>
    http.get<BackupDiff>(`/backups/${id}/diff/`, { params: { against } }),
  /**
   * 下载是**一个普通链接**,不走 axios。
   *
   * 走 axios 的话要把整份配置读进内存、造一个 Blob、再造一个隐藏的 <a> 点它 ——
   * 一份几 MB 的配置这么走一遍毫无必要,而且丢掉了后端设的文件名。
   * 会话是 cookie,浏览器直接开这个地址就带上了。
   */
  backupDownloadUrl: (id: number) => `/api/backups/${id}/download/`,

  // 防火墙策略
  policies: (params?: object) => http.get<Paged<PolicyRow>>('/firewall-policies/', { params }),
  policy: (id: number) => http.get<PolicyRow>(`/firewall-policies/${id}/`),
  policySummary: () =>
    http.get<{ generated_at: string; devices: PolicySummaryRow[] }>('/firewall-policies/summary/'),
  syncPoliciesNow: (id: number) => http.post<{ detail: string }>(`/devices/${id}/sync_policies_now/`),
  policyAudit: (deviceId?: number) =>
    http.get<PolicyAudit>('/firewall-policies/audit/', { params: { device: deviceId } }),

  /**
   * 复制一条配置。**在后端做** —— 凭据是 write_only、前端拿不到,
   * 前端拼出来的副本必然是一台没有密码的机器。
   *
   * 201 = 直接建好了(监控类 / 网络设备 / 通知渠道);
   * 400 + `needs` = 这一类有端点唯一约束,要先给一个新地址。
   */
  duplicate: (path: string, id: number, overrides?: Record<string, any>) =>
    http.post<any>(`/${path}/${id}/duplicate/`, overrides ?? {}),

  // 端口面板图 —— 几何来自型号画像,口的名字和状态来自设备
  deviceFaceplate: (id: number) => http.get<Faceplate>(`/devices/${id}/faceplate/`),

  // 防火墙地址对象 / 地址组 —— 和策略同一次同步拿回来
  addresses: (params?: object) =>
    http.get<Paged<AddressRow>>('/firewall-addresses/', { params }),
  addressSummary: () =>
    http.get<{ devices: AddressSummaryRow[] }>('/firewall-addresses/summary/'),
  /** 别名查询:名字 → 它到底是哪几个网段(地址组递归展开) */
  resolveAddress: (deviceId: number, name: string) =>
    http.get<AddressResolve>('/firewall-addresses/resolve/',
      { params: { device: deviceId, name } }),

  // 服务对象 / 服务组 —— 「这条策略放开了什么」的第三维:哪个端口
  services: (params?: object) =>
    http.get<Paged<ServiceRow>>('/firewall-services/', { params }),
  /** 服务名查询。**走 SSH 通道时预定义服务查不到**(show 只打印被改过的) */
  resolveService: (deviceId: number, name: string) =>
    http.get<AddressResolve>('/firewall-services/resolve/',
      { params: { device: deviceId, name } }),

  // Cisco 访问控制(ACL / object-group / 静态 NAT)
  aclBoard: (deviceId?: number) =>
    http.get<AclBoard>('/cisco-acl/board/', { params: { device: deviceId } }),

  // SD-WAN 性能 SLA —— 防火墙自己从出口探出来的延迟/抖动/丢包
  /** `hours = 0` → **不返回趋势点**(大屏那几张小卡只要当前值) */
  sdwanBoard: (hours = 6) =>
    http.get<SdwanBoard>('/sdwan/board/', { params: { hours } }),
  sdwanLinks: (params?: object) =>
    http.get<Paged<SdwanLinkRow>>('/sdwan/', { params }),

  // 带外硬件(iDRAC)
  idracHosts: (params?: object) => http.get<Paged<IdracRow>>('/idrac/', { params }),
  createIdrac: (body: Partial<IdracRow>) => http.post<IdracRow>('/idrac/', body),
  updateIdrac: (id: number, body: Partial<IdracRow>) =>
    http.patch<IdracRow>(`/idrac/${id}/`, body),
  deleteIdrac: (id: number) => http.delete(`/idrac/${id}/`),
  idracBoard: () => http.get<IdracBoard>('/idrac/board/'),
  idracDetail: (id: number) => http.get<IdracDetail>(`/idrac/${id}/detail_info/`),
  idracSeries: (id: number, hours = 24) =>
    http.get<{ host: string; hours: number; points: IdracSamplePoint[] }>(
      `/idrac/${id}/series/`, { params: { hours } }),
  testIdrac: (id: number) =>
    http.post<{ ok: boolean; detail: string }>(`/idrac/${id}/test/`),
  collectIdracNow: (id: number) =>
    http.post<{ detail: string }>(`/idrac/${id}/collect_now/`),

  // 映射(firewall vip)—— 和策略同一次同步拿回来的
  vips: (params?: object) => http.get<Paged<VipRow>>('/firewall-vips/', { params }),
  vipSummary: (deviceId?: number) =>
    http.get<VipSummary>('/firewall-vips/summary/', { params: { device: deviceId } }),
  /** CSV 导出走普通链接,不经过 axios —— 同 backupDownloadUrl 的理由 */
  policyExportUrl: (params: Record<string, any> = {}) => {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
    }
    const qs = q.toString()
    return `/api/firewall-policies/export/${qs ? `?${qs}` : ''}`
  },

  // 事件
  events: (params?: object) => http.get<Paged<EventRow>>('/events/', { params }),
  eventReport: (hours = 24) => http.get('/events/report/', { params: { hours } }),
  ackEvent: (id: number, by?: string, note?: string) => http.post(`/events/${id}/acknowledge/`, { by, note }),
  renotify: (id: number) => http.post(`/events/${id}/renotify/`),

  // 通知
  notifiers: (params?: object) => http.get<Paged<NotifierRow>>('/notifiers/', { params }),
  createNotifier: (body: Partial<NotifierRow>) => http.post<NotifierRow>('/notifiers/', body),
  updateNotifier: (id: number, body: Partial<NotifierRow>) => http.patch<NotifierRow>(`/notifiers/${id}/`, body),
  deleteNotifier: (id: number) => http.delete(`/notifiers/${id}/`),
  testNotifier: (id: number) => http.post(`/notifiers/${id}/test/`),
  notifyLogs: (params?: object) => http.get('/notify-logs/', { params }),

  // 会话与自助
  session: () => http.get<{ authenticated: boolean; user: Me | null }>('/auth/session/'),
  login: (username: string, password: string, otp?: string) =>
    http.post<{ authenticated?: boolean; user?: Me; status?: string; recovery_left?: number }>(
      '/auth/login/', { username, password, otp },
    ),
  logout: () => http.post('/auth/logout/'),
  changePassword: (old_password: string, new_password: string) =>
    http.post('/auth/password/', { old_password, new_password }),
  totpSetup: () =>
    http.post<{ secret: string; uri: string; qr_svg: string; issuer: string }>('/auth/2fa/setup/'),
  totpConfirm: (code: string) =>
    http.post<{ detail: string; recovery_codes: string[] }>('/auth/2fa/confirm/', { code }),
  totpDisable: (password: string) => http.post('/auth/2fa/disable/', { password }),
  totpRecovery: (password: string) =>
    http.post<{ recovery_codes: string[] }>('/auth/2fa/recovery/', { password }),

  // 管理后台(仅管理员)
  users: (params?: object) => http.get<Paged<UserRow>>('/manage/users/', { params }),
  createUser: (body: Partial<UserRow>) => http.post<UserRow>('/manage/users/', body),
  updateUser: (id: number, body: Partial<UserRow>) => http.patch<UserRow>(`/manage/users/${id}/`, body),
  deleteUser: (id: number) => http.delete(`/manage/users/${id}/`),
  resetUserPassword: (id: number, password: string) =>
    http.post(`/manage/users/${id}/reset_password/`, { password }),
  disableUser2fa: (id: number) => http.post(`/manage/users/${id}/disable_2fa/`),
  unlockUser: (id: number) => http.post(`/manage/users/${id}/unlock/`),
  loginAudit: (params?: object) => http.get<Paged<LoginAuditRow>>('/manage/login-audit/', { params }),
  systemInfo: () => http.get<SystemInfo>('/manage/system/'),
  retention: () => http.get<RetentionPolicy>('/manage/retention/'),
  updateRetention: (body: Partial<RetentionPolicy>) =>
    http.patch<RetentionPolicy>('/manage/retention/', body),
}
