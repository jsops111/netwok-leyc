/**
 * 显示格式化。集中在一处 —— 同一个数在大屏、表格、卡片上必须长得一样,
 * 各处自己 toFixed 是不一致的开始。
 */

/** null / undefined 一律显示破折号,**不显示 0**。见 CLAUDE.md「缺失与零」。 */
export const DASH = '—'

export function num(value: number | null | undefined, digits = 1, unit = ''): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH
  return `${value.toFixed(digits)}${unit}`
}

export function int(value: number | null | undefined, unit = ''): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH
  return `${Math.round(value).toLocaleString('zh-CN')}${unit}`
}

/** 延迟。亚毫秒的值保留两位 —— 内网线路常年在 0.0x ms,一位小数全是 0.0 */
export function ms(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH
  if (value < 1) return `${value.toFixed(2)}ms`
  if (value < 100) return `${value.toFixed(1)}ms`
  return `${Math.round(value)}ms`
}

export function pct(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH
  return `${value.toFixed(digits)}%`
}

/** 带宽。bps → Kbps/Mbps/Gbps。用 1000 进制,网络设备都是这么标的。 */
export function bps(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps']
  let v = value
  let i = 0
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000
    i += 1
  }
  return `${v.toFixed(v < 10 && i > 0 ? 2 : v < 100 && i > 0 ? 1 : 0)} ${units[i]}`
}

/**
 * 字节。磁盘和表占用用它。
 *
 * **用 1024 进制**,和 `bps()` 的 1000 进制不一样 —— 这不是不一致:
 * 网络设备标带宽用 1000,而 `df` / Postgres 报磁盘用 1024,
 * 页面上的数字要能和运维在终端里看到的对上。
 */
export function bytes(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let v = value
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`
}

/** 时长。事件表里的"持续"列用它。 */
export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return DASH
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return `${s}秒`
  if (s < 3600) return `${Math.floor(s / 60)}分${s % 60}秒`
  if (s < 86400) {
    const h = Math.floor(s / 3600)
    return `${h}小时${Math.floor((s % 3600) / 60)}分`
  }
  const d = Math.floor(s / 86400)
  return `${d}天${Math.floor((s % 86400) / 3600)}小时`
}

export function uptime(seconds: number | null | undefined): string {
  if (!seconds) return DASH
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  return d > 0 ? `${d}天${h}小时` : `${h}小时${Math.floor((seconds % 3600) / 60)}分`
}

export function timeOf(iso: string | null | undefined): string {
  if (!iso) return DASH
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? DASH : d.toLocaleTimeString('zh-CN', { hour12: false })
}

export function dateTimeOf(iso: string | null | undefined): string {
  if (!iso) return DASH
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return DASH
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/** "多久以前"。大屏上"上次刷新"用它。 */
export function ago(date: Date | string | null | undefined): string {
  if (!date) return DASH
  const t = typeof date === 'string' ? new Date(date).getTime() : date.getTime()
  if (Number.isNaN(t)) return DASH
  const s = Math.max(0, Math.round((Date.now() - t) / 1000))
  if (s < 5) return '刚刚'
  if (s < 60) return `${s} 秒前`
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`
  return `${Math.floor(s / 86400)} 天前`
}

/** 协议 + 端口的紧凑写法,列表里省地方。 */
export function endpoint(host: string, protocol: string, port: number | null): string {
  const upper = protocol.toUpperCase()
  if (protocol === 'icmp') return `${host} · ICMP`
  if (port) return `${host}:${port} · ${upper}`
  return `${host} · ${upper}`
}
