<script setup lang="ts">
import { computed } from 'vue'
import { STATE } from '@/theme'

/**
 * 迷你趋势线。设备卡片和线路列表里用。
 *
 * **颜色走 :style 绑定而不是 SVG 的 stroke / fill 属性** —— 颜色现在是
 * `var(--cy-x)`,而 presentation 属性对 var() 的支持在各浏览器上不一致,
 * style 是稳的。
 *
 * **手写 SVG,不用 echarts** —— 一个大屏上可能有几十个 sparkline,
 * 每个都 init 一个 echarts 实例会让首屏卡住好几秒。这里是一条 path,
 * 没有实例、没有事件监听。
 */
const props = withDefaults(
  defineProps<{
    values: Array<number | null | undefined>
    color?: string
    height?: number
    /** 有断点时在断处画红色竖线 */
    showGaps?: boolean
  }>(),
  { color: STATE.up, height: 30, showGaps: true },
)

const W = 100 // viewBox 宽度,靠 preserveAspectRatio 拉伸填满容器

const geometry = computed(() => {
  const values = props.values
  if (values.length < 2) return { path: '', area: '', gaps: [] as number[] }

  const numeric = values.filter((v): v is number => v !== null && v !== undefined && !Number.isNaN(v))
  if (!numeric.length) return { path: '', area: '', gaps: [] as number[] }

  const min = Math.min(...numeric)
  const max = Math.max(...numeric)
  // 全平的序列(min===max)给个假的量程,否则除零
  const span = max - min || Math.abs(max) || 1
  const h = props.height
  const pad = 2

  const x = (i: number) => (i / (values.length - 1)) * W
  const y = (v: number) => pad + (1 - (v - min) / span) * (h - pad * 2)

  // 断点处不连线 —— 用多个 M 命令分段
  const segments: string[] = []
  const gaps: number[] = []
  let current: string[] = []
  values.forEach((v, i) => {
    if (v === null || v === undefined || Number.isNaN(v)) {
      if (current.length) {
        segments.push(current.join(' '))
        current = []
      }
      gaps.push(x(i))
      return
    }
    current.push(`${current.length ? 'L' : 'M'}${x(i).toFixed(2)},${y(v).toFixed(2)}`)
  })
  if (current.length) segments.push(current.join(' '))

  // 面积只画最后一段(通常也就一段),多段填充会互相叠加显得脏
  const last = segments[segments.length - 1]
  const area = last
    ? `${last} L${W},${h - pad} L${last.slice(1).split(',')[0]},${h - pad} Z`
    : ''

  return { path: segments.join(' '), area, gaps }
})

const gradId = `spark-${Math.random().toString(36).slice(2, 9)}`
</script>

<template>
  <svg
    class="spark"
    :viewBox="`0 0 ${W} ${height}`"
    preserveAspectRatio="none"
    :style="{ height: `${height}px` }"
  >
    <defs>
      <linearGradient :id="gradId" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" :style="{ stopColor: color }" stop-opacity="0.34" />
        <stop offset="100%" :style="{ stopColor: color }" stop-opacity="0" />
      </linearGradient>
    </defs>
    <path v-if="geometry.area" :d="geometry.area" :fill="`url(#${gradId})`" stroke="none" />
    <path
      v-if="geometry.path"
      :d="geometry.path"
      fill="none"
      :style="{ stroke: color }"
      stroke-width="1.4"
      vector-effect="non-scaling-stroke"
      stroke-linejoin="round"
    />
    <line
      v-for="(gx, i) in showGaps ? geometry.gaps : []"
      :key="i"
      :x1="gx" :x2="gx" y1="0" :y2="height"
      :style="{ stroke: STATE.down }"
      stroke-width="1"
      stroke-opacity="0.5"
      vector-effect="non-scaling-stroke"
    />
    <text
      v-if="!geometry.path"
      :x="W / 2" :y="height / 2 + 3"
      text-anchor="middle" font-size="9" style="fill: var(--cy-ink-3)"
    >无数据</text>
  </svg>
</template>

<style scoped>
.spark { width: 100%; display: block; overflow: visible; }
</style>
