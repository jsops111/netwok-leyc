import type { GlobalThemeOverrides } from 'naive-ui'

/**
 * 主题。**两套:深色(默认)和亮色。**
 *
 * 深色是这个平台的本来面目 —— 它是挂在墙上的监控大屏。亮色是后加的,
 * 给白天在工位上看的人用。两套都是**整套**的:不存在"某个组件加个
 * @media 判断"这种半套做法(半套亮色比没有亮色更糟)。
 *
 * ## 颜色住在哪儿
 *
 * **真正的颜色值在 `styles/cyber.css` 的 CSS 变量里**,不在这个文件里。
 * 这个文件导出的是 `var(--cy-xxx)` 形式的**引用**,所以:
 *
 *     组件里写 `:style="{ color: STATE.down }"` → 换主题自动跟着变
 *
 * 例外是两处必须拿到**具体颜色值**的地方:
 *
 *   1. **ECharts / canvas**:它不认 `var()`,要用 `resolveColor()` 取算出来的值,
 *      并且在主题切换时重画(图表组件里 watch 了 themeStore.mode)
 *   2. **naive-ui 的主题覆盖**:它要基于主色算出 hover/pressed 等派生色,
 *      拿到 `var()` 会算出 NaN。所以下面 DARK/LIGHT 两份具体值是给它用的
 *
 * ## 三套颜色各管各的,不要混用
 *
 * | 集合 | 用途 | 约束 |
 * |---|---|---|
 * | `NEON` | 边框、辉光、强调文字 | 对各自底色 ≥4.5:1 |
 * | `STATE` / `SEVERITY` | 状态和级别 | 保留色,不参与分类着色 |
 * | `CATEGORICAL` | 图表线条、进度条 | **两套都用配色校验器验过** |
 *
 * ## 图表色板是算出来的,不是挑出来的
 *
 * 亮色那八个值是在"对白底和页面底都 ≥3:1、OKLCH 明度 [0.40,0.70]、色度 ≥0.10、
 * 八个色相扇区各一个"的约束下,以**最大化色盲分离度**为目标搜出来的:
 * 正常/红色盲/绿色盲三种视觉下,两两 ΔE2000 最差 15.8。
 *
 * ⚠ **深色那八个值没有达到同样的标准。**实测:正常视觉最差 ΔE 11.9,但
 * protan(红色盲)下 #8757e6 与 #2563eb 只有 0.7,deutan(绿色盲)下
 * #d9631a 与 #b8860b 只有 1.4 —— 也就是说色盲用户看那两对线是分不开的。
 * 这是这套配色的已知缺陷,改它会改变所有人已经熟悉的大屏观感,
 * 所以留作一次单独的决定。**别把"深色也验过了"这句话写回来。**
 *
 * 校验器在 CLAUDE.md 里有说明,改任何一套配色都要重跑。
 */

// ---------------------------------------------------------------- 具体色值
//
// 这两份**只给 naive-ui 的主题覆盖用**(它要算派生色,不认 var())。
// 组件里请用下面的 `var()` 引用版本,那样才会跟着主题切换。
// 改这里的值必须同时改 `styles/cyber.css` 里对应的 CSS 变量 —— 两边是一份东西。

const DARK = {
  cyan: '#22e0e8', magenta: '#ff3d8b', violet: '#b18aff',
  up: '#2ee6a8', degraded: '#ffb224', down: '#ff5470', unknown: '#7a8fa0',
  info: '#38d9f7',
  body: '#050710', card: '#0e1220', raised: '#141a2c', popover: '#161d31',
  ink: '#e8f4f8', inkStrong: '#f6fdff', ink2: '#a8bcc8', ink3: '#7a8fa0',
  hover: '#0f1d2b', header: '#101728',
} as const

const LIGHT = {
  cyan: '#007a89', magenta: '#c8175f', violet: '#6a3fd0',
  up: '#0e7a56', degraded: '#9a5b00', down: '#c8283f', unknown: '#5f7082',
  info: '#0a6f9e',
  body: '#eef2f7', card: '#ffffff', raised: '#f6f9fc', popover: '#ffffff',
  ink: '#101a26', inkStrong: '#000000', ink2: '#3d4d5e', ink3: '#5c7183',
  hover: '#e8f1f5', header: '#f2f6fa',
} as const

// ---------------------------------------------------------------- 引用版(组件用)

/** UI 霓虹。深色下是发光的青/品红,亮色下是压深的同色相。 */
export const NEON = {
  cyan: 'var(--cy-cyan)',
  magenta: 'var(--cy-magenta)',
  violet: 'var(--cy-violet)',
  lime: 'var(--cy-cat-3)',
} as const

/** 线路/设备状态色。四档,和后端 LinkState 一一对应。 */
export const STATE = {
  up: 'var(--cy-up)',
  degraded: 'var(--cy-degraded)',
  down: 'var(--cy-down)',
  unknown: 'var(--cy-unknown)',
} as const

export const STATUS = {
  success: STATE.up,
  warning: STATE.degraded,
  error: STATE.down,
  info: 'var(--cy-info)',
} as const

/** 事件级别色,和后端 Severity 对应。 */
export const SEVERITY = {
  info: 'var(--cy-info)',
  warning: 'var(--cy-degraded)',
  critical: 'var(--cy-down)',
} as const

/**
 * 图表刻度色,固定顺序。多于 8 条线时循环 —— 循环是有意的:
 * 一张图上超过 8 条线,靠颜色已经分不出来了,那时候该做的是筛选,
 * 不是再加第 9 个颜色。
 */
export const CATEGORICAL = [
  'var(--cy-cat-1)', 'var(--cy-cat-2)', 'var(--cy-cat-3)', 'var(--cy-cat-4)',
  'var(--cy-cat-5)', 'var(--cy-cat-6)', 'var(--cy-cat-7)', 'var(--cy-cat-8)',
] as const

export const SURFACE = {
  body: 'var(--cy-body)',
  card: 'var(--cy-card)',
  raised: 'var(--cy-raised)',
  popover: 'var(--cy-popover)',
  grid: 'var(--cy-line-soft)',
} as const

export const INK = {
  base: 'var(--cy-ink)',
  strong: 'var(--cy-ink)',
  secondary: 'var(--cy-ink-2)',
  muted: 'var(--cy-ink-3)',
} as const

/**
 * `var(--x)` → 算出来的具体颜色。
 *
 * **只在 canvas / ECharts 里用** —— 那里不认 CSS 变量。用完的值不会随主题
 * 更新,所以调用方必须在主题切换时重新取一次(图表组件 watch 了主题)。
 */
export function resolveColor(value: string): string {
  const match = /^var\((--[\w-]+)\)$/.exec(value.trim())
  if (!match) return value
  if (typeof window === 'undefined') return value
  const resolved = getComputedStyle(document.documentElement)
    .getPropertyValue(match[1])
    .trim()
  return resolved || value
}

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

/**
 * naive-ui 主题覆盖。**深浅两套走同一个工厂** —— 手写两份的话,
 * 加一个组件覆盖只改了一边,另一套主题下那个组件就是 naive 的默认样式,
 * 而这种不一致往往到上线才被看见。
 *
 * 这里必须用**具体色值**(DARK / LIGHT),不能用 var():naive 要基于主色
 * 算 hover/pressed 等派生色,拿到 `var(--x)` 会算出 NaN。
 */
function buildOverrides(c: typeof DARK | typeof LIGHT, dark: boolean): GlobalThemeOverrides {
  const a = (hex: string, alpha: number) => {
    const n = parseInt(hex.slice(1), 16)
    return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${alpha})`
  }
  // 深色靠"提亮"做 hover,亮色靠"压暗" —— 同一个方向在另一套里是看不见的
  const shift = (hex: string, amount: number) => {
    const n = parseInt(hex.slice(1), 16)
    const f = (v: number) => Math.max(0, Math.min(255, Math.round(v + (dark ? amount : -amount))))
    return `#${((1 << 24) + (f((n >> 16) & 255) << 16) + (f((n >> 8) & 255) << 8) + f(n & 255))
      .toString(16).slice(1)}`
  }

  return {
    common: {
      ...FONTS,
      fontSize: '14px',
      // 切角靠 clip-path 做,圆角保持很小 —— 赛博朋克不用圆润的东西
      borderRadius: '2px',
      borderRadiusSmall: '2px',

      primaryColor: c.cyan,
      primaryColorHover: shift(c.cyan, 26),
      primaryColorPressed: shift(c.cyan, -20),
      primaryColorSuppl: shift(c.cyan, -12),

      infoColor: c.info,
      infoColorHover: shift(c.info, 26),
      infoColorPressed: shift(c.info, -20),
      successColor: c.up,
      successColorHover: shift(c.up, 26),
      successColorPressed: shift(c.up, -20),
      warningColor: c.degraded,
      warningColorHover: shift(c.degraded, 26),
      warningColorPressed: shift(c.degraded, -20),
      errorColor: c.down,
      errorColorHover: shift(c.down, 26),
      errorColorPressed: shift(c.down, -20),

      bodyColor: c.body,
      cardColor: c.card,
      modalColor: c.raised,
      popoverColor: c.popover,
      tableColor: c.card,
      // 不透明:固定列悬停时半透明会透出底下横向滚动的内容
      tableColorHover: c.hover,
      tableHeaderColor: c.header,
      inputColor: dark ? 'rgba(6, 10, 20, 0.72)' : '#ffffff',
      inputColorDisabled: dark ? 'rgba(6, 10, 20, 0.4)' : '#f0f3f7',
      actionColor: c.header,
      hoverColor: a(c.cyan, dark ? 0.08 : 0.07),

      // 边框统一带一点青,整个界面才像是同一块电路板上的
      borderColor: a(c.cyan, dark ? 0.17 : 0.26),
      dividerColor: a(c.cyan, dark ? 0.12 : 0.2),

      textColorBase: c.ink,
      textColor1: c.inkStrong,
      textColor2: c.ink,
      textColor3: c.ink2,
      textColorDisabled: c.ink3,
      placeholderColor: c.ink3,
      iconColor: c.ink2,
      closeIconColor: c.ink2,

      scrollbarColor: a(c.cyan, dark ? 0.22 : 0.3),
      scrollbarColorHover: a(c.cyan, dark ? 0.4 : 0.5),
    },
    Card: {
      // 面板的辉光边框由 CyberPanel 自己画,naive 的 Card 只在表单区域用
      borderColor: a(c.cyan, dark ? 0.17 : 0.26),
      titleTextColor: c.inkStrong,
    },
    DataTable: {
      thTextColor: c.cyan,
      thFontWeight: '600',
      borderColor: a(c.cyan, dark ? 0.14 : 0.22),
      tdColorHover: c.hover,
    },
    Tabs: {
      tabTextColorActiveLine: c.cyan,
      tabTextColorHoverLine: c.cyan,
      barColor: c.cyan,
    },
    Tag: {
      // 标签的字色按底色亮度算,不写死白色 —— 见 SeverityTag 组件的 ink 计算
      borderRadius: '1px',
    },
    Input: { borderHover: `1px solid ${c.cyan}` },
    Select: { peers: { InternalSelection: { borderHover: `1px solid ${c.cyan}` } } },
  }
}

export const darkOverrides = buildOverrides(DARK, true)
export const lightOverrides = buildOverrides(LIGHT, false)
