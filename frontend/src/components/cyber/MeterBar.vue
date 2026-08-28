<script setup lang="ts">
import { computed } from 'vue'
import { valueColor } from '@/theme'
import { pct } from '@/composables/useFormat'

/**
 * 阈值仪表条。CPU / 内存 / 带宽利用率都用它。
 *
 * 阈值刻线画在条上 —— 光看"70%"这个数字判断不出严重程度,
 * 而看到它已经压到警告刻线上,一眼就懂。
 */
const props = withDefaults(
  defineProps<{
    value: number | null | undefined
    warn?: number | null
    crit?: number | null
    max?: number
    /** 显示右侧数值 */
    showValue?: boolean
    label?: string
  }>(),
  { max: 100, showValue: true },
)

const color = computed(() => valueColor(props.value, props.warn, props.crit))
const width = computed(() => {
  if (props.value === null || props.value === undefined) return 0
  return Math.min(100, Math.max(0, (props.value / props.max) * 100))
})
const markPos = (threshold?: number | null) =>
  threshold ? `${Math.min(100, (threshold / props.max) * 100)}%` : null
</script>

<template>
  <div class="meter-wrap">
    <div v-if="label || showValue" class="meter-head">
      <span class="lbl">{{ label }}</span>
      <span class="val cy-mono" :style="{ color }">{{ pct(value) }}</span>
    </div>
    <div class="cy-meter">
      <div class="cy-meter-fill" :style="{ width: `${width}%`, '--fill': color }" />
      <i v-if="markPos(warn)" class="cy-meter-mark" :style="{ left: markPos(warn)! }" />
      <i v-if="markPos(crit)" class="cy-meter-mark" :style="{ left: markPos(crit)!, opacity: 0.75 }" />
    </div>
  </div>
</template>

<style scoped>
.meter-wrap { width: 100%; }
.meter-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  margin-bottom: 4px;
}
.lbl { font-size: 11px; color: var(--cy-ink-3); letter-spacing: 0.06em; }
.val { font-size: 13px; font-weight: 600; }
</style>
