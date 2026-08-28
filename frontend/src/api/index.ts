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
  scheduler: Record<string, any>
}

export interface DeviceCard {
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
  deviceSeries: (id: number, hours = 6) => http.get(`/devices/${id}/series/`, { params: { hours } }),

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
