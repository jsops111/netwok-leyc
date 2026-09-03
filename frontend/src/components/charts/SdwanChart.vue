<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import * as echarts from 'echarts/core'
import { LineChart } from 'echarts/charts'
import {
  GridComponent, LegendComponent, MarkAreaComponent, MarkLineComponent, TooltipComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { SdwanLinkRow } from '@/api'
import { CATEGORICAL, INK, STATE, resolveColor } from '@/theme'
import { useThemeStore } from '@/stores/theme'
import { ms, pct } from '@/composables/useFormat'

echarts.use([
  LineChart, GridComponent, LegendComponent, TooltipComponent,
  MarkAreaComponent, MarkLineComponent, CanvasRenderer,
])

/**
 * 一个健康检查一张图,线 = 各个出口。
 *
 * 和 `GroupChart.vue` 同一套规矩(它们画的是同一类东西 —— 一批链路的
 * 延迟随时间变化),所以这几条照抄不改:
 *
 * 1. **断线画成红色 markArea 竖带,不是把线画到 0。**画到 0 会让人以为
 *    延迟降到 0 了。
 * 2. **时间上不连续的两点之间插 null 断开。**echarts 默认会用直线连起来,
 *    那根线看着像"这段时间延迟平稳",它其实是"这段时间没有数据" ——
 *    两件事在监控上含义相反。
 * 3. **延迟/抖动的 Y 轴不强制从 0 起**(内网线路常年 0.0x ms,从 0 起会把
 *    所有线挤在顶端一条缝里);丢包率固定 0-100。
 * 4. `animation: false` —— 轮询刷新时开动画,线会一直抖。
 * 5. `setOption` 用 `notMerge: false`,刷新不丢掉用户手动缩放的视图。
 *
 * 多的一条:**SLA 门限画成虚线**。这是 SD-WAN 特有的 —— 一条 186ms 的线
 * 算不算超,取决于那台设备上配的门限是 100 还是 500,而那个数不在图上的话
 * 人得自己去防火墙翻配置。
 */

const props = defineProps<{
  /** 同一个健康检查下的所有出口 */
  links: SdwanLinkRow[]
  metric: 'latency' | 'jitter' | 'loss'
  height?: number
}>()

const el = ref<HTMLElement>()
const chart = shallowRef<echarts.ECharts>()
const theme = useThemeStore()

/**
 * ECharts 不认 `var()`,所以要解成具体值 —— 而且**主题切换时要重新解一次**。
 * `flush: 'post'` 是有意的:主题 store 在 pre 阶段把 `data-theme` 写到
 * `<html>` 上,post 阶段读 `getComputedStyle` 才拿得到新值。写成默认的 pre
 * 会解出**上一套主题**的颜色,只差一帧,极难发现。
 */
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

const META = {
  latency: { name: '延迟', unit: 'ms', fmt: ms, key: 'latency', thr: 'sla_latency_threshold' },
  jitter: { name: '抖动', unit: 'ms', fmt: ms, key: 'jitter', thr: 'sla_jitter_threshold' },
  loss: { name: '丢包率', unit: '%', fmt: pct, key: 'loss', thr: 'sla_loss_threshold' },
} as const

/** 见文件头第 2 条。阈值给 3 分钟 —— SD-WAN 跟着设备采集的节拍走 */
function withGaps(
  series: Array<Record<string, any>>, metric: string,
): Array<[string, number | null]> {
  const out: Array<[string, number | null]> = []
  const maxGapMs = 180 * 1000
  let prevMs: number | null = null
  for (const point of series) {
    const nowMs = new Date(point.ts).getTime()
    if (prevMs !== null && nowMs - prevMs > maxGapMs) {
      out.push([new Date(prevMs + (nowMs - prevMs) / 2).toISOString(), null])
    }
    out.push([point.ts, point[metric] ?? null])
    prevMs = nowMs
  }
  return out
}

const option = computed(() => {
  const meta = META[props.metric]
  const links = props.links

  // 门限线取所有出口里**最严的那一档** —— 一张图上四条线各有门限,
  // 画四条虚线就成了栅栏。取最小值是保守方向:压过它就一定有出口超标了
  const thresholds = links
    .map((l) => l[meta.thr] as number | null)
    .filter((v): v is number => v !== null && v > 0)
  const thrLine = thresholds.length ? Math.min(...thresholds) : null

  const series: any[] = links.map((link, i) => {
    const color = C.value.cat[i % C.value.cat.length]

    // 断线区间:连续 state=dead 的段落,画成红色竖带
    const downAreas: any[] = []
    let runStart: string | null = null
    for (const point of link.series || []) {
      const isDown = point.state === 'dead'
      if (isDown && runStart === null) runStart = point.ts
      else if (!isDown && runStart !== null) {
        downAreas.push([{ xAxis: runStart }, { xAxis: point.ts }])
        runStart = null
      }
    }
    const pts = link.series || []
    if (runStart !== null && pts.length) {
      downAreas.push([{ xAxis: runStart }, { xAxis: pts[pts.length - 1].ts }])
    }

    return {
      name: link.member,
      type: 'line',
      showSymbol: false,
      smooth: false,        // 平滑会把尖峰削掉,而尖峰正是要看的东西
      connectNulls: false,  // 断口留着,它本身是信息
      lineStyle: { width: 1.6, color, shadowBlur: 7, shadowColor: color },
      itemStyle: { color },
      emphasis: { focus: 'series', lineStyle: { width: 2.6 } },
      areaStyle: links.length === 1
        ? {
            opacity: 0.22,
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: `${color}80` },
              { offset: 1, color: `${color}00` },
            ]),
          }
        : undefined,
      data: withGaps(pts, meta.key),
      markArea: downAreas.length
        ? {
            silent: true,
            itemStyle: { color: 'rgba(var(--cy-down-rgb), 0.14)' },
            data: downAreas,
          }
        : undefined,
      // 门限线只画一次,画在第一条线上
      markLine: i === 0 && thrLine
        ? {
            silent: true,
            symbol: 'none',
            label: {
              formatter: '{b}', color: C.value.ink3, fontSize: 10,
              position: 'insideEndTop',
            },
            data: [{
              yAxis: thrLine,
              name: `SLA 门限 ${thrLine}${meta.unit}`,
              lineStyle: { color: C.value.degraded, type: 'dashed', width: 1, opacity: 0.7 },
            }],
          }
        : undefined,
    }
  })

  return {
    animation: false,
    backgroundColor: 'transparent',
    grid: { left: 52, right: 18, top: 26, bottom: links.length > 3 ? 46 : 30 },
    legend: {
      type: 'scroll', bottom: 0, itemWidth: 14, itemHeight: 2,
      textStyle: { color: C.value.ink2, fontSize: 11 },
      pageIconColor: C.value.cat[0], pageTextStyle: { color: C.value.ink3 },
    },
    tooltip: {
      trigger: 'axis',
      backgroundColor: C.value.tooltipBg,
      borderColor: 'rgba(var(--cy-cyan-rgb), 0.3)',
      borderWidth: 1,
      textStyle: { color: C.value.ink, fontSize: 12 },
      axisPointer: { type: 'line', lineStyle: { color: 'rgba(var(--cy-cyan-rgb), 0.4)' } },
      // 值为 null 的行不显示 —— 断线时会显示 "wan2: -",那一行是噪音;
      // 但**要在脚注里说有几条断着**,不能让它悄悄消失
      formatter: (params: any[]) => {
        if (!params?.length) return ''
        const time = new Date(params[0].value[0]).toLocaleTimeString('zh-CN', { hour12: false })
        const rows = params
          .filter((p) => p.value?.[1] !== null && p.value?.[1] !== undefined)
          .map((p) => `<div style="display:flex;gap:10px;justify-content:space-between">
              <span>${p.marker}${p.seriesName}</span>
              <b style="font-family:'JetBrains Mono',monospace">${meta.fmt(p.value[1])}</b>
            </div>`)
        const missing = params.length - rows.length
        const foot = missing
          ? `<div style="margin-top:4px;color:${C.value.down};font-size:11px">${missing} 个出口断线 / 无数据</div>`
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
      name: `${meta.name}(${meta.unit})`,
      nameTextStyle: { color: C.value.ink3, fontSize: 10, align: 'right' },
      max: props.metric === 'loss' ? 100 : undefined,
      min: props.metric === 'loss' ? 0 : 'dataMin',
      scale: props.metric !== 'loss',
      axisLine: { show: false },
      axisLabel: { color: C.value.ink3, fontSize: 10 },
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
  <div ref="el" class="chart" :style="{ height: `${height || 220}px` }" />
</template>

<style scoped>
.chart { width: 100%; }
</style>
