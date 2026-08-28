<script setup lang="ts">
import { ref, watch } from 'vue'

/**
 * 统计格 —— 大屏顶部那排。
 *
 * 值变化时闪一下(cy-flash)。这是数据区唯一允许的动画:大屏上没人盯着看,
 * 一次 450ms 的短暗示能让人知道"这个数刚变了",又不干扰读数。
 */
const props = withDefaults(
  defineProps<{
    label: string
    value: number | string | null | undefined
    unit?: string
    color?: string
    /** 脚注,通常是"当前 N 条未恢复"这类补充 */
    foot?: string
    /** 值为 0 时用暗色 —— 一排都是 0 的时候不该五颜六色地亮着 */
    dimZero?: boolean
  }>(),
  { unit: '', color: '#22e0e8', foot: '', dimZero: true },
)

const flash = ref(false)
watch(
  () => props.value,
  (next, prev) => {
    // 首次渲染(prev === undefined)不闪 —— 那不是"变化"
    if (prev === undefined || next === prev) return
    flash.value = false
    // 强制重排一次,否则连续变化时动画不会重新触发
    requestAnimationFrame(() => {
      flash.value = true
      window.setTimeout(() => (flash.value = false), 500)
    })
  },
)

const isZero = () => props.value === 0 || props.value === '0'
</script>

<template>
  <div
    class="cy-tile"
    :class="{ 'cy-flash': flash }"
    :style="{ '--tile': dimZero && isZero() ? '#7a8fa0' : color }"
  >
    <div class="cy-tile-label">{{ label }}</div>
    <div class="cy-tile-value">
      {{ value === null || value === undefined ? '—' : value }}<span v-if="unit" class="cy-tile-unit">{{ unit }}</span>
    </div>
    <div v-if="foot" class="cy-tile-foot">{{ foot }}</div>
  </div>
</template>
