<script setup lang="ts">
import { computed } from 'vue'
import Sparkline from './Sparkline.vue'
import { STATE, valueColor } from '@/theme'
import { num } from '@/composables/useFormat'
import type { DeviceCard } from '@/api'

/**
 * 设备卡片里的 CPU / 内存 / 温度三条迷你趋势。
 *
 * **缺失指标显示"该型号不支持",不显示 0。**C9200L 采不到温度是画像里
 * 声明过的缺项(absent_metrics / optional_metrics),把它画成 0 会让人
 * 去查一个不存在的问题。
 */
const props = defineProps<{ card: DeviceCard }>()

const METRICS = [
  { key: 'cpu' as const, label: 'CPU', warn: 'cpu_warn', crit: 'cpu_crit', unit: '%' },
  { key: 'mem' as const, label: '内存', warn: 'mem_warn', crit: 'mem_crit', unit: '%' },
  { key: 'temp' as const, label: '温度', warn: 'temp_warn', crit: 'temp_crit', unit: '℃' },
]

const rows = computed(() =>
  METRICS.map((m) => {
    const metricName = m.key === 'cpu' ? 'cpu_pct' : m.key === 'mem' ? 'mem_pct' : 'temp_c'
    const unsupported = props.card.absent_metrics.includes(metricName)
    const values = props.card.trend.map((p) => p[m.key])
    const current = props.card[m.key]
    const hasData = values.some((v) => v !== null && v !== undefined)
    return {
      ...m,
      unsupported,
      hasData,
      values,
      current,
      color: valueColor(current, props.card.thresholds[m.warn], props.card.thresholds[m.crit]),
      // 采不到但不是"不支持" = optional 缺项,提示措辞不一样
      optional: !hasData && !unsupported && props.card.optional_metrics.includes(metricName),
    }
  }),
)
</script>

<template>
  <div class="trend-grid">
    <div v-for="row in rows" :key="row.key" class="trend-row">
      <div class="trend-head">
        <span class="lbl">{{ row.label }}</span>
        <span class="val cy-mono" :style="{ color: row.hasData ? row.color : '#7a8fa0' }">
          {{ row.hasData ? num(row.current, row.key === 'temp' ? 0 : 1, row.unit) : '—' }}
        </span>
      </div>
      <Sparkline v-if="row.hasData" :values="row.values" :color="row.color" :height="26" />
      <div v-else class="na">
        {{ row.unsupported ? '该型号不提供此指标' : row.optional ? '固件未上报' : '暂无数据' }}
      </div>
    </div>
  </div>
</template>

<style scoped>
.trend-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.trend-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  margin-bottom: 3px;
}
.lbl { font-size: 11px; color: #7a8fa0; letter-spacing: 0.06em; }
.val { font-size: 13px; font-weight: 700; }
.na {
  height: 26px;
  display: flex;
  align-items: center;
  font-size: 10px;
  color: #5c6b78;
  border-bottom: 1px dashed rgba(122, 143, 160, 0.28);
}
</style>
