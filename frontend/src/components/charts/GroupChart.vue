<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import * as echarts from 'echarts/core'
import { LineChart } from 'echarts/charts'
import {
  DataZoomComponent, GridComponent, LegendComponent, MarkLineComponent,
  TitleComponent, TooltipComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { ChartGroup } from '@/api'
import { CATEGORICAL, INK, STATE, seriesColor } from '@/theme'
import { ms, pct } from '@/composables/useFormat'

/**
 * 「一个监控类一个大图」的那张大图。
 *
 * 三个设计决定值得说明:
 *
 * 1. **默认画延迟,丢包/抖动切换着看,而不是三个指标堆一张图。**
 *    三个指标量纲不同(ms / % / ms),硬塞一张图要两三个 Y 轴,
 *    十条线 × 三个指标 = 三十条曲线,人读不出任何东西。
 * 2. **断线用 markArea 画成红色竖带,不是把线画到 0。**
 *    画到 0 会让人以为"延迟降到 0 了";而且断线期间的点本来就是 null,
 *    连线跳过它们(connectNulls: false),断口本身就是信息。
 * 3. **阈值用 markLine 画出来。**一条 200ms 的线是好是坏,取决于这条线路的
 *    阈值 —— 把警告线画在图上,读图的人不用去翻配置。
 *
 * 用 echarts/core 的按需引入(不是完整包):完整 echarts 打进来 1MB+,
 * 这里只用到折线图和五个组件。
 */

echarts.use([
  LineChart, GridComponent, TooltipComponent, LegendComponent,
  TitleComponent, MarkLineComponent, DataZoomComponent, CanvasRenderer,
])

const props = defineProps<{
  data: ChartGroup
  /** 画哪个指标 */
  metric: 'rtt' | 'loss' | 'jitter'
  height?: number
}>()

const el = ref<HTMLDivElement>()
const chart = shallowRef<echarts.ECharts>()

const METRIC_META = {
  rtt: { name: '延迟', unit: 'ms', fmt: ms, warnKey: 'latency_warn', critKey: 'latency_crit' },
  loss: { name: '丢包率', unit: '%', fmt: pct, warnKey: 'loss_warn', critKey: 'loss_crit' },
  jitter: { name: '抖动', unit: 'ms', fmt: ms, warnKey: 'jitter_warn', critKey: 'jitter_crit' },
} as const

/** 分组自定义了强调色就用它当第一条线的颜色,否则整组走色板。 */
function lineColor(index: number): string {
  if (index === 0 && props.data.group.color) return props.data.group.color
  return seriesColor(index)
}

/**
 * 把时间上不连续的两个点之间插一个 null,让线断开。
 *
 * 为什么需要:采集停过一段(worker 挂了、线路刚启用、被停用后又启用),
 * 前后两个点之间可能隔了十几分钟。echarts 会**用一根直线把它们连起来**,
 * 而那根线看着像"这段时间延迟平稳" —— 它其实是"这段时间没有数据"。
 * 这两件事在监控上的含义完全相反,不能让图把它们画成一样。
 *
 * 判定阈值取采集间隔的 3 倍:偶尔迟到一两拍是正常的,不该断线。
 */
function withGaps(
  series: Array<Record<string, any>>,
  metric: string,
  intervalSeconds: number,
): Array<[string, number | null]> {
  const out: Array<[string, number | null]> = []
  const maxGapMs = Math.max(intervalSeconds * 3, 30) * 1000
  let prevMs: number | null = null

  for (const point of series) {
    const nowMs = new Date(point.ts).getTime()
    if (prevMs !== null && nowMs - prevMs > maxGapMs) {
      // 断点插在间隙中间,这样两端的线都收在自己的时间范围里
      out.push([new Date(prevMs + (nowMs - prevMs) / 2).toISOString(), null])
    }
    out.push([point.ts, point[metric] ?? null])
    prevMs = nowMs
  }
  return out
}

const option = computed(() => {
  const meta = METRIC_META[props.metric]
  const lines = props.data.lines

  // 阈值线取所有线路里最严格的那档 —— 一张图上十条线各有阈值,
  // 画十条 markLine 就成了栅栏。取最小值是保守方向:图上那条线是"最早
  // 该报警的位置",压过它就一定有线路超标了。
  const warns = lines.map((l) => l.thresholds[meta.warnKey]).filter((v) => v > 0)
  const crits = lines.map((l) => l.thresholds[meta.critKey]).filter((v) => v > 0)
  const warnLine = warns.length ? Math.min(...warns) : null
  const critLine = crits.length ? Math.min(...crits) : null

  const series: any[] = lines.map((line, i) => {
    const color = lineColor(i)
    // 断线区间:连续 ok=false 的段落,画成红色竖带
    const downAreas: any[] = []
    let runStart: string | null = null
    for (const point of line.series) {
      const isDown = point.ok === false
      if (isDown && runStart === null) runStart = point.ts
      else if (!isDown && runStart !== null) {
        downAreas.push([{ xAxis: runStart }, { xAxis: point.ts }])
        runStart = null
      }
    }
    if (runStart !== null && line.series.length) {
      downAreas.push([{ xAxis: runStart }, { xAxis: line.series[line.series.length - 1].ts }])
    }

    return {
      name: line.name,
      type: 'line',
      showSymbol: false,
      symbolSize: 5,
      smooth: false, // 不平滑 —— 平滑会把尖峰削掉,而尖峰正是要看的东西
      connectNulls: false, // 断口留着,它本身是信息
      lineStyle: { width: 1.6, color, shadowBlur: 7, shadowColor: color },
      itemStyle: { color },
      emphasis: { focus: 'series', lineStyle: { width: 2.6 } },
      // 只给第一条线加渐变填充 —— 十条线都填充会糊成一片
      areaStyle:
        lines.length === 1
          ? {
              opacity: 0.22,
              color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: `${color}80` },
                { offset: 1, color: `${color}00` },
              ]),
            }
          : undefined,
      data: withGaps(line.series, props.metric, line.interval),
      markArea:
        downAreas.length && i === 0
          ? {
              silent: true,
              itemStyle: { color: 'rgba(255, 84, 112, 0.13)' },
              data: downAreas,
            }
          : undefined,
      markLine:
        i === 0 && (warnLine || critLine)
          ? {
              silent: true,
              symbol: 'none',
              label: { formatter: '{b}', color: INK.muted, fontSize: 10, position: 'insideEndTop' },
              data: [
                ...(warnLine
                  ? [{ yAxis: warnLine, name: `警告 ${warnLine}${meta.unit}`,
                       lineStyle: { color: STATE.degraded, type: 'dashed', width: 1, opacity: 0.6 } }]
                  : []),
                ...(critLine
                  ? [{ yAxis: critLine, name: `严重 ${critLine}${meta.unit}`,
                       lineStyle: { color: STATE.down, type: 'dashed', width: 1, opacity: 0.6 } }]
                  : []),
              ],
            }
          : undefined,
    }
  })

  return {
    animation: false, // 轮询刷新时开动画会让线一直在抖
    backgroundColor: 'transparent',
    grid: { left: 52, right: 18, top: 30, bottom: lines.length > 4 ? 52 : 34 },
    legend: {
      type: 'scroll',
      bottom: 0,
      itemWidth: 14,
      itemHeight: 2,
      textStyle: { color: INK.secondary, fontSize: 11 },
      pageIconColor: CATEGORICAL[0],
      pageTextStyle: { color: INK.muted },
    },
    tooltip: {
      trigger: 'axis',
      backgroundColor: 'rgba(10, 14, 26, 0.94)',
      borderColor: 'rgba(34, 224, 232, 0.3)',
      borderWidth: 1,
      textStyle: { color: INK.base, fontSize: 12 },
      axisPointer: { type: 'line', lineStyle: { color: 'rgba(34, 224, 232, 0.4)' } },
      // 值为 null 的行不显示 —— 断线时十条线里有一条断了,
      // 默认会显示 "线路A: -",那一行是噪音
      formatter: (params: any[]) => {
        if (!params?.length) return ''
        const time = new Date(params[0].value[0]).toLocaleTimeString('zh-CN', { hour12: false })
        const rows = params
          .filter((p) => p.value?.[1] !== null && p.value?.[1] !== undefined)
          .map((p) => {
            const v = meta.fmt(p.value[1])
            return `<div style="display:flex;gap:10px;justify-content:space-between">
                      <span>${p.marker}${p.seriesName}</span>
                      <b style="font-family:'JetBrains Mono',monospace">${v}</b>
                    </div>`
          })
        const missing = params.length - rows.length
        const foot = missing
          ? `<div style="margin-top:4px;color:${STATE.down};font-size:11px">${missing} 条无数据 / 断线</div>`
          : ''
        return `<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:${INK.muted};margin-bottom:5px">${time}</div>${rows.join('')}${foot}`
      },
    },
    xAxis: {
      type: 'time',
      axisLine: { lineStyle: { color: 'rgba(34, 224, 232, 0.2)' } },
      axisLabel: { color: INK.muted, fontSize: 10, hideOverlap: true },
      splitLine: { show: false },
    },
    yAxis: {
      type: 'value',
      name: `${meta.name}(${meta.unit})`,
      nameTextStyle: { color: INK.muted, fontSize: 10, align: 'right' },
      // 丢包率固定 0-100,否则一条全 0 的线会把 Y 轴缩到 0~0.001,
      // 看着像剧烈波动。
      // **延迟和抖动不强制从 0 起**:内网线路常年在 0.0x ms,从 0 起会把
      // 所有线挤在顶端一条缝里,看不出任何波动。让 echarts 自适应量程。
      max: props.metric === 'loss' ? 100 : undefined,
      min: props.metric === 'loss' ? 0 : 'dataMin',
      scale: props.metric !== 'loss',
      axisLine: { show: false },
      axisLabel: { color: INK.muted, fontSize: 10 },
      splitLine: { lineStyle: { color: 'rgba(34, 224, 232, 0.07)' } },
    },
    series,
  }
})

function render() {
  if (!chart.value) return
  // notMerge=false + lazyUpdate:轮询刷新时复用已有配置,只更新数据,
  // 这样不会丢掉用户手动缩放的视图
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
  <div ref="el" class="chart" :style="{ height: `${height || 300}px` }" />
</template>

<style scoped>
.chart { width: 100%; }
</style>
