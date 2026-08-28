<script setup lang="ts">
import { computed } from 'vue'
import { stateColor } from '@/theme'

/**
 * 状态灯。
 *
 * unknown 不呼吸 —— 它表示"还没有数据",静止是准确的表达。
 * down 呼吸得更急(1.1s vs 2.4s),频率本身传递紧迫感。
 */
const props = withDefaults(defineProps<{ state?: string | null; label?: boolean }>(), {
  state: 'unknown',
  label: false,
})

const color = computed(() => stateColor(props.state))
const live = computed(() => props.state !== 'unknown')
const LABELS: Record<string, string> = {
  up: '正常', degraded: '劣化', down: '中断', unknown: '未知',
}
</script>

<template>
  <span class="wrap">
    <i
      class="cy-dot"
      :class="{ 'is-live': live, 'is-down': state === 'down' }"
      :style="{ '--dot': color }"
    />
    <span v-if="label" class="txt" :style="{ color }">{{ LABELS[state || 'unknown'] }}</span>
  </span>
</template>

<style scoped>
.wrap { display: inline-flex; align-items: center; gap: 7px; }
.txt { font-size: 12px; font-weight: 600; letter-spacing: 0.03em; }
</style>
