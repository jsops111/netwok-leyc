<script setup lang="ts">
import { computed } from 'vue'

/**
 * 一条发光的面积曲线。
 *
 * ## ⚠ 它画的是**分布**,不是趋势 —— 这一点必须由调用方在标题上写明
 *
 * 这里的 X 轴是「N 台机器按高低排好序」,**不是时间**。带外那一屏画的
 * 是"这一批机器的分布长什么样",不是"某一台随时间怎么变"(后者在
 * `/idrac` 的明细里)。曲线这个形状天生会被读成「随时间变化」,所以:
 *   * 组件里**没有**任何时间字样;
 *   * 调用方必须在标题或副标题里写「按…降序的分布,不是时间曲线」。
 * 少了那句话,一条从高到低的曲线会被看成「在往下掉」,而它只是排过序 ——
 * 那是这一屏最容易造成的误读。
 *
 * ## 为什么自己画而不用图表库
 *
 * 只要一条 polyline + 一块渐变面积 + 一个端点圆点,几十行 SVG 就够;
 * 引一个图表库换来的是几百 KB 和一套要重新对齐的配色。项目里
 * `Sparkline.vue` 也是这么做的(一个大屏上有几十个,每个 init 一个
 * echarts 实例会让首屏卡好几秒)。
 */
const props = withDefaults(
  defineProps<{
    /** 每个点的值。**`null` 表示这一台没采到** —— 断开而不是补 0 */
    values: (number | null)[]
    /** 描边和填充色。传 CSS 变量(`var(--m-cpu)`)以便和这块屏的族色一致 */
    color: string
    /** Y 轴上限。不传按数据最大值,并留一成余量 */
    max?: number | null
    /** 高度(px)。宽度撑满容器 */
    height?: number
    /** 右上角那个数字后面的单位 */
    unit?: string
  }>(),
  { max: null, height: 74, unit: '' },
)

/** viewBox 用固定坐标系,再靠 CSS 拉伸 —— 这样不用测容器宽度 */
const W = 300
const H = 100

const scaled = computed(() => {
  const vals = props.values
  const top = props.max ?? Math.max(1, ...vals.map((v) => v ?? 0)) * 1.1
  const step = vals.length > 1 ? W / (vals.length - 1) : W
  return vals.map((v, i) => ({
    x: i * step,
    // null 不参与画线 —— 补 0 会画出一个"掉到底"的假谷底
    y: v === null ? null : H - (Math.max(0, Math.min(top, v)) / top) * H,
    v,
  }))
})

/** 折线。遇到 null 就断开(M 重新起笔),不跨过去连一条直线 */
const line = computed(() => {
  let d = ''
  let pen = false
  for (const p of scaled.value) {
    if (p.y === null) {
      pen = false
      continue
    }
    d += `${pen ? 'L' : 'M'}${p.x.toFixed(1)} ${p.y.toFixed(1)} `
    pen = true
  }
  return d.trim()
})

/** 面积:折线 + 落到底边。只在有连续段时闭合 */
const area = computed(() => {
  const pts = scaled.value.filter((p) => p.y !== null)
  if (pts.length < 2) return ''
  const first = pts[0]
  const last = pts[pts.length - 1]
  let d = `M${first.x.toFixed(1)} ${H} `
  for (const p of pts) d += `L${p.x.toFixed(1)} ${(p.y as number).toFixed(1)} `
  d += `L${last.x.toFixed(1)} ${H} Z`
  return d
})

/** 端点。参考图里那个发光圆点 —— 它标的是**排在最后那一台**,不是"现在" */
const endPoint = computed(() => {
  const pts = scaled.value.filter((p) => p.y !== null)
  return pts.length ? pts[pts.length - 1] : null
})
const headPoint = computed(() => {
  const pts = scaled.value.filter((p) => p.y !== null)
  return pts.length ? pts[0] : null
})
/** 渐变要唯一 id,否则同一页多条曲线会互相抢定义 */
const gid = computed(() => `hc-${Math.abs(hashOf(props.color + props.values.length))}`)
function hashOf(s: string): number {
  let h = 0
  for (let i = 0; i < s.length; i += 1) h = (h * 31 + s.charCodeAt(i)) | 0
  return h
}
</script>

<template>
  <div class="hc" :style="{ height: `${height}px`, '--c': color }">
    <svg :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none" class="hc-svg">
      <defs>
        <linearGradient :id="gid" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" :stop-color="color" stop-opacity="0.55" />
          <stop offset="100%" :stop-color="color" stop-opacity="0.02" />
        </linearGradient>
      </defs>
      <!-- 基线网格:三条很淡的横线。**不标数值** —— 数值在卡片的读数行上,
           这里只要看得出高低起伏 -->
      <line v-for="f in [0.25, 0.5, 0.75]" :key="f" x1="0" :y1="H * f" :x2="W" :y2="H * f" class="hc-grid" />
      <path v-if="area" :d="area" :fill="`url(#${gid})`" />
      <path v-if="line" :d="line" class="hc-line" />
    </svg>
    <!-- 两个端点用绝对定位的 div 而不是 SVG circle:`preserveAspectRatio="none"`
         会把圆拉成椭圆(实测),而 div 不受 viewBox 拉伸影响 -->
    <i
      v-if="headPoint"
      class="hc-dot"
      :style="{ left: '0%', top: `${((headPoint.y as number) / H) * 100}%` }"
    />
    <i
      v-if="endPoint"
      class="hc-dot hc-dot-end"
      :style="{ left: '100%', top: `${((endPoint.y as number) / H) * 100}%` }"
    />
  </div>
</template>

<style scoped>
.hc {
  position: relative;
  width: 100%;
}
.hc-svg {
  width: 100%;
  height: 100%;
  display: block;
  overflow: visible;
}
.hc-grid {
  stroke: color-mix(in srgb, var(--c) 16%, transparent);
  stroke-width: 1;
  vector-effect: non-scaling-stroke;
  stroke-dasharray: 3 5;
}
.hc-line {
  fill: none;
  stroke: var(--c);
  stroke-width: 2;
  /* `preserveAspectRatio="none"` 会连线宽一起拉,不加这个的话
     横向拉伸后线会变成粗细不均的一条 */
  vector-effect: non-scaling-stroke;
  stroke-linejoin: round;
  filter: drop-shadow(0 0 5px color-mix(in srgb, var(--c) 75%, transparent));
}
.hc-dot {
  position: absolute;
  width: 7px;
  height: 7px;
  margin: -3.5px 0 0 -3.5px;
  border-radius: 50%;
  background: var(--c);
  box-shadow: 0 0 10px var(--c);
}
.hc-dot-end {
  width: 9px;
  height: 9px;
  margin: -4.5px 0 0 -4.5px;
  box-shadow: 0 0 14px var(--c), 0 0 26px color-mix(in srgb, var(--c) 60%, transparent);
}
</style>
