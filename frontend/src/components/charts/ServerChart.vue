<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import * as echarts from 'echarts/core'
import { LineChart } from 'echarts/charts'
import {
  DataZoomComponent, GridComponent, LegendComponent, MarkLineComponent, TooltipComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { CATEGORICAL, INK, STATE, resolveColor } from '@/theme'
import { useThemeStore } from '@/stores/theme'
import { bps, num, pct } from '@/composables/useFormat'

/**
 * 服务器的趋势图。**一次画一个指标**,切换着看 —— 和 GroupChart 同一条理由:
 * 流量(bps)、使用率(%)、负载(倍数)三个量纲塞一张图要三个 Y 轴,
 * 读不出任何东西。
 *
 * 三条和 GroupChart 一致、不能改回去的决定:
 *
 * 1. **时间上不连续的两点之间插 null 断开**(withGaps)。echarts 默认会用
 *    直线连起来,那根线看着像"这段时间很平稳",它其实是"这段时间没有数据"
 *    —— 两件事在监控上含义相反。
 * 2. **失联区间画成红色竖带**,不是把线画到 0。画到 0 会让人以为
 *    "CPU 降到 0 了",而真相是机器登不上去。
 * 3. `animation: false` + `notMerge: false` —— 轮询刷新时开动画线会一直抖,
 *    而 notMerge=true 会丢掉用户手动缩放的视图。
 *
 * ECharts 画在 canvas 上**不认 CSS 变量**,所以颜色要 resolveColor 解出来,
 * 并且在主题切换时重解一次(watch 用 flush:'post' —— 主题 store 是在 pre
 * 阶段把 data-theme 写到 <html> 上的,post 阶段读 getComputedStyle 才拿得到
 * 新值;写成默认的 pre 会解出上一套主题的颜色,只差一帧,极难发现)。
 */

echarts.use([
  LineChart, GridComponent, TooltipComponent, LegendComponent,
  MarkLineComponent, DataZoomComponent, CanvasRenderer,
])

export type ServerMetric = 'net' | 'cpu' | 'mem' | 'load'

const props = defineProps<{
  /** 时序点。必须带 ts;其余字段按 metric 取 */
  points: Array<Record<string, any>>
  metric: ServerMetric
  /** 采集间隔(秒),用来判断"多久没有数据算断开" */
  interval: number
  /** 阈值线。cpu/mem 用 %,load 用每核倍数;net 没有阈值 */
  warn?: number | null
  crit?: number | null
  /** 每核负载要除以核数才能和阈值比 */
  cores?: number | null
  height?: number
}>()

const el = ref<HTMLDivElement>()
const chart = shallowRef<echarts.ECharts>()
const theme = useThemeStore()

function readColors() {
  return {
    ink: resolveColor(INK.base),
    ink2: resolveColor(INK.secondary),
    ink3: resolveColor(INK.muted),
    down: resolveColor(STATE.down),
    degraded: resolveColor(STATE.degraded),
    tooltipBg: resolveColor('var(--cy-tooltip-bg)'),
    cat: CATEGORICAL.map((c) => resolveColor(c)),
  }
}

const C = ref(readColors())
watch(() => theme.mode, () => { C.value = readColors() }, { flush: 'post' })

/** 每个指标画哪几条线、怎么格式化。**单位混不了**,所以一个指标一套。 */
const METRICS = {
  net: {
    axisName: '流量',
    fmt: (v: number | null) => bps(v),
    lines: [
      { key: 'net_in_bps', alt: 'net_in', name: '入向', color: 0, area: true },
      { key: 'net_out_bps', alt: 'net_out', name: '出向', color: 1, area: false },
    ],
    percentAxis: false,
  },
  cpu: {
    axisName: 'CPU(%)',
    fmt: (v: number | null) => pct(v),
    lines: [
      { key: 'cpu_pct', alt: 'cpu', name: 'CPU', color: 2, area: true },
      // iowait 单独一条:**CPU 不高但系统很卡**的时候它是唯一能解释的指标
      { key: 'cpu_iowait_pct', alt: 'iowait', name: 'iowait', color: 3, area: false },
    ],
    percentAxis: true,
  },
  mem: {
    axisName: '内存(%)',
    fmt: (v: number | null) => pct(v),
    lines: [
      { key: 'mem_pct', alt: 'mem', name: '内存', color: 4, area: true },
      { key: 'swap_pct', alt: 'swap', name: 'Swap', color: 5, area: false },
    ],
    percentAxis: true,
  },
  load: {
    axisName: '负载',
    fmt: (v: number | null) => num(v, 2),
    lines: [
      { key: 'load1', alt: 'load1', name: '1 分钟', color: 6, area: true },
      { key: 'load5', alt: 'load5', name: '5 分钟', color: 7, area: false },
      { key: 'load15', alt: 'load15', name: '15 分钟', color: 0, area: false },
    ],
    percentAxis: false,
  },
} as const

/**
 * 时间上不连续处插 null。阈值取采集间隔的 3 倍 —— 偶尔迟到一两拍是正常的,
 * 不该在图上断开。
 */
function withGaps(key: string, alt: string): Array<[string, number | null]> {
  const out: Array<[string, number | null]> = []
  const maxGapMs = Math.max(props.interval * 3, 45) * 1000
  let prevMs: number | null = null

  for (const point of props.points) {
    const nowMs = new Date(point.ts).getTime()
    if (prevMs !== null && nowMs - prevMs > maxGapMs) {
      out.push([new Date(prevMs + (nowMs - prevMs) / 2).toISOString(), null])
    }
    const value = point[key] ?? point[alt] ?? null
    out.push([point.ts, value])
    prevMs = nowMs
  }
  return out
}

/** 连续失联的区间 → markArea 的坐标对。 */
function downAreas(): any[] {
  const areas: any[] = []
  let runStart: string | null = null
  for (const point of props.points) {
    // 两个字段名:series 接口给 reachable,大屏卡片给 up
    const up = point.reachable ?? point.up
    const isDown = up === false
    if (isDown && runStart === null) runStart = point.ts
    else if (!isDown && runStart !== null) {
      areas.push([{ xAxis: runStart }, { xAxis: point.ts }])
      runStart = null
    }
  }
  if (runStart !== null && props.points.length) {
    areas.push([{ xAxis: runStart }, { xAxis: props.points[props.points.length - 1].ts }])
  }
  return areas
}

const option = computed(() => {
  const meta = METRICS[props.metric]
  const areas = downAreas()

  // 负载的阈值是"每核",画到图上要乘回核数 —— 图的 Y 轴是绝对负载值。
  // 核数拿不到就不画阈值线,而不是画一条按 1 核算的线(那条线在 64 核的
  // 机器上会贴着地面,看着像"一直在告警")
  const scale = props.metric === 'load' ? (props.cores || 0) : 1
  const warnLine = props.warn && scale ? props.warn * scale : null
  const critLine = props.crit && scale ? props.crit * scale : null

  const series = meta.lines.map((line, index) => {
    const color = C.value.cat[line.color % C.value.cat.length]
    return {
      name: line.name,
      type: 'line',
      showSymbol: false,
      smooth: false,          // 平滑会把尖峰削掉,而尖峰正是要看的东西
      connectNulls: false,    // 断口留着,它本身是信息
      lineStyle: { width: 1.6, color, shadowBlur: 7, shadowColor: color },
      itemStyle: { color },
      emphasis: { focus: 'series', lineStyle: { width: 2.6 } },
      areaStyle: line.area
        ? {
            opacity: 0.2,
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: `${color}80` },
              { offset: 1, color: `${color}00` },
            ]),
          }
        : undefined,
      data: withGaps(line.key, line.alt),
      markArea: areas.length && index === 0
        ? { silent: true, itemStyle: { color: 'rgba(var(--cy-down-rgb), 0.13)' }, data: areas }
        : undefined,
      markLine: index === 0 && (warnLine || critLine)
        ? {
            silent: true,
            symbol: 'none',
            label: { formatter: '{b}', color: C.value.ink3, fontSize: 10, position: 'insideEndTop' },
            data: [
              ...(warnLine
                ? [{ yAxis: warnLine, name: `警告 ${meta.fmt(warnLine)}`,
                     lineStyle: { color: C.value.degraded, type: 'dashed', width: 1, opacity: 0.6 } }]
                : []),
              ...(critLine
                ? [{ yAxis: critLine, name: `严重 ${meta.fmt(critLine)}`,
                     lineStyle: { color: C.value.down, type: 'dashed', width: 1, opacity: 0.6 } }]
                : []),
            ],
          }
        : undefined,
    }
  })

  return {
    animation: false,
    backgroundColor: 'transparent',
    grid: { left: 58, right: 16, top: 26, bottom: 30 },
    legend: {
      top: 0,
      itemWidth: 14,
      itemHeight: 2,
      textStyle: { color: C.value.ink2, fontSize: 11 },
    },
    tooltip: {
      trigger: 'axis',
      backgroundColor: C.value.tooltipBg,
      borderColor: 'rgba(var(--cy-cyan-rgb), 0.3)',
      borderWidth: 1,
      textStyle: { color: C.value.ink, fontSize: 12 },
      axisPointer: { type: 'line', lineStyle: { color: 'rgba(var(--cy-cyan-rgb), 0.4)' } },
      formatter: (params: any[]) => {
        if (!params?.length) return ''
        const time = new Date(params[0].value[0]).toLocaleTimeString('zh-CN', { hour12: false })
        // 值为 null 的行不显示 —— 断线时"内存: -"那一行是噪音
        const rows = params
          .filter((p) => p.value?.[1] !== null && p.value?.[1] !== undefined)
          .map((p) => `<div style="display:flex;gap:10px;justify-content:space-between">
                         <span>${p.marker}${p.seriesName}</span>
                         <b style="font-family:'JetBrains Mono',monospace">${meta.fmt(p.value[1])}</b>
                       </div>`)
        const missing = params.length - rows.length
        const foot = missing
          ? `<div style="margin-top:4px;color:${C.value.down};font-size:11px">${missing} 项无数据</div>`
          : ''
        return `<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:${C.value.ink3};margin-bottom:5px">${time}</div>${rows.join('')}${foot}`
      },
    },
    xAxis: {
      type: 'time',
      axisLine: { lineStyle: { color: 'rgba(var(--cy-cyan-rgb), 0.2)' } },
      axisLabel: { color: C.value.ink3, fontSize: 10, hideOverlap: true },
      splitLine: { show: false },
    },
    yAxis: {
      type: 'value',
      name: meta.axisName,
      nameTextStyle: { color: C.value.ink3, fontSize: 10, align: 'right' },
      // 使用率固定 0-100:一台常年 3% 的机器如果自适应量程,
      // 那 3% 会被画成剧烈波动
      min: 0,
      max: meta.percentAxis ? 100 : undefined,
      axisLine: { show: false },
      axisLabel: {
        color: C.value.ink3,
        fontSize: 10,
        formatter: (value: number) => meta.fmt(value),
      },
      splitLine: { lineStyle: { color: 'rgba(var(--cy-cyan-rgb), 0.07)' } },
    },
    series,
  }
})

function render() {
  if (!chart.value) return
  chart.value.setOption(option.value as any, { notMerge: false, lazyUpdate: true })
}

let observer: ResizeObserver | undefined

onMounted(() => {
  if (!el.value) return
  chart.value = echarts.init(el.value, undefined, { renderer: 'canvas' })
  render()
  observer = new ResizeObserver(() => chart.value?.resize())
  observer.observe(el.value)
})

watch(option, render)

onBeforeUnmount(() => {
  observer?.disconnect()
  chart.value?.dispose()
})
</script>

<template>
  <div ref="el" class="srv-chart" :style="{ height: `${height || 240}px` }" />
</template>

<style scoped>
.srv-chart { width: 100%; }
</style>
