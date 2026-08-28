import type { GlobalThemeOverrides } from 'naive-ui'

/**
 * 赛博朋克主题(深色专用)。
 *
 * **这个项目只有深色。**它是挂在墙上的监控大屏,不是白天办公用的后台 ——
 * 隔壁 ops-ai-cmdb 那套亮色覆盖(九十多处令牌逐个算对比度)在这里是纯负担。
 * 需要亮色的话是一次单独的改动,不要临时给某个组件加 @media 判断:
 * 半套亮色比没有亮色更糟。
 *
 * 配色分三套,各管各的,不要混用:
 *
 * 1. NEON        UI 霓虹(主色、边框、发光、强调文字)。都过了 WCAG 4.5:1
 *                (vs 面板底 #0e1220),所以敢用在文字上。
 * 2. STATUS      状态语义色(正常/劣化/中断/未知)。保留色,不参与分类着色。
 * 3. CATEGORICAL 图表刻度色(线条、进度条这类"数据本身")。这套刻意比 NEON 暗
 *                —— 大面积高饱和色在深色底上会发晕、彼此干扰。它是用配色
 *                校验器跑过的:OKLCH 明度落在深色带 [0.48, 0.67],色度 ≥0.1,
 *                全对色盲分离度 ΔE 8.1,对底色对比度全部 ≥3:1。
 *                **别凭手感改这四个值。**
 */

// ---------------------------------------------------------------- 色板

export const NEON = {
  cyan: '#22e0e8', // 主色。11.45:1
  magenta: '#ff3d8b', // 次强调。5.59:1
  violet: '#b18aff', // 7.06:1
  lime: '#a3e635', // 图表辅助高亮
} as const

/** 线路/设备状态色。四档,和后端 LinkState 一一对应。 */
export const STATE = {
  up: '#2ee6a8', // 正常 11.55:1
  degraded: '#ffb224', // 劣化 10.34:1
  down: '#ff5470', // 中断 6.00:1
  unknown: '#7a8fa0', // 未知 4.52:1
} as const

export const STATUS = {
  success: STATE.up,
  warning: STATE.degraded,
  error: STATE.down,
  info: '#38d9f7', // 11.04:1
} as const

/** 事件级别色,和后端 Severity 对应。 */
export const SEVERITY = {
  info: '#38d9f7',
  warning: '#ffb224',
  critical: '#ff5470',
} as const

/**
 * 图表刻度色,固定顺序。多于 8 条线时循环 —— 循环是有意的:
 * 一张图上超过 8 条线,靠颜色已经分不出来了,那时候该做的是筛选,
 * 不是再加第 9 个颜色。
 */
export const CATEGORICAL = [
  '#009aa8',
  '#e6247a',
  '#d9631a',
  '#8757e6',
  '#0f8f6b',
  '#b8860b',
  '#2563eb',
  '#c026d3',
] as const

export const SURFACE = {
  body: '#050710', // 大屏底色,比隔壁更深 —— 霓虹在更暗的底上才有"发光"感
  card: '#0e1220',
  raised: '#141a2c',
  popover: '#161d31',
  grid: 'rgba(34, 224, 232, 0.055)', // 背景网格线
} as const

const HOVER = '#0f1d2b' // 不透明:固定列悬停时半透明会透出底下横向滚动的内容

export const INK = {
  base: '#e8f4f8', // 16.63:1
  strong: '#f6fdff',
  secondary: '#a8bcc8', // 9.50:1
  muted: '#7a8fa0', // 4.52:1 —— 刚好过正文线,别再压暗
} as const

/** 组件内联样式从这里取色,不要到处硬编码。 */
export const cyber = { NEON, STATE, STATUS, SEVERITY, SURFACE, INK, CATEGORICAL }

const FONTS = {
  fontFamily:
    '"Rajdhani", -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif',
  fontFamilyMono:
    '"JetBrains Mono", ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
}

/** 状态 → 颜色。模板里到处要用,收在一处。 */
export function stateColor(state?: string | null): string {
  return STATE[(state || 'unknown') as keyof typeof STATE] ?? STATE.unknown
}

export function severityColor(severity?: string | null): string {
  return SEVERITY[(severity || 'info') as keyof typeof SEVERITY] ?? SEVERITY.info
}

/** 按序号取图表色,超过色板长度就循环。 */
export function seriesColor(index: number): string {
  return CATEGORICAL[index % CATEGORICAL.length]
}

/**
 * 指标值 → 状态色。三档阈值的通用判定。
 * 图上的点、仪表条、数字都用它上色,保证"同一个数在哪儿都是同一个颜色"。
 */
export function valueColor(
  value: number | null | undefined,
  warn?: number | null,
  crit?: number | null,
): string {
  if (value === null || value === undefined) return STATE.unknown
  if (crit && value >= crit) return STATE.down
  if (warn && value >= warn) return STATE.degraded
  return STATE.up
}

export const darkOverrides: GlobalThemeOverrides = {
  common: {
    ...FONTS,
    fontSize: '14px',
    // 切角靠 clip-path 做,圆角保持很小 —— 赛博朋克不用圆润的东西
    borderRadius: '2px',
    borderRadiusSmall: '2px',

    primaryColor: NEON.cyan,
    primaryColorHover: '#5cf0f6',
    primaryColorPressed: '#12b8bf',
    primaryColorSuppl: '#0f9aa2',

    infoColor: STATUS.info,
    infoColorHover: '#6ae6ff',
    infoColorPressed: '#1fb4d0',
    successColor: STATUS.success,
    successColorHover: '#5ff0c0',
    successColorPressed: '#1fbe8a',
    warningColor: STATUS.warning,
    warningColorHover: '#ffc456',
    warningColorPressed: '#d99312',
    errorColor: STATUS.error,
    errorColorHover: '#ff7d93',
    errorColorPressed: '#d93a56',

    bodyColor: SURFACE.body,
    cardColor: SURFACE.card,
    modalColor: SURFACE.raised,
    popoverColor: SURFACE.popover,
    tableColor: SURFACE.card,
    tableColorHover: HOVER,
    tableHeaderColor: '#101728',
    inputColor: 'rgba(6, 10, 20, 0.72)',
    inputColorDisabled: 'rgba(6, 10, 20, 0.4)',
    actionColor: '#101728',
    hoverColor: 'rgba(34, 224, 232, 0.08)',

    // 边框统一带一点青,整个界面才像是同一块电路板上的
    borderColor: 'rgba(34, 224, 232, 0.17)',
    dividerColor: 'rgba(34, 224, 232, 0.12)',

    textColorBase: INK.base,
    textColor1: INK.strong,
    textColor2: INK.base,
    textColor3: INK.secondary,
    textColorDisabled: INK.muted,
    placeholderColor: INK.muted,
    iconColor: INK.secondary,
    closeIconColor: INK.secondary,

    scrollbarColor: 'rgba(34, 224, 232, 0.22)',
    scrollbarColorHover: 'rgba(34, 224, 232, 0.4)',
  },
  Card: {
    // 面板的辉光边框由 CyberPanel 自己画,naive 的 Card 只在表单区域用
    borderColor: 'rgba(34, 224, 232, 0.17)',
    titleTextColor: INK.strong,
  },
  DataTable: {
    thTextColor: NEON.cyan,
    thFontWeight: '600',
    borderColor: 'rgba(34, 224, 232, 0.14)',
    tdColorHover: HOVER,
  },
  Tabs: {
    tabTextColorActiveLine: NEON.cyan,
    tabTextColorHoverLine: NEON.cyan,
    barColor: NEON.cyan,
  },
  Tag: {
    // 标签的字色按底色亮度算,不写死白色 —— 见 SeverityTag 组件的 ink 计算
    borderRadius: '1px',
  },
  Input: { borderHover: `1px solid ${NEON.cyan}` },
  Select: { peers: { InternalSelection: { borderHover: `1px solid ${NEON.cyan}` } } },
}
