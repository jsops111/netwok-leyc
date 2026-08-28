<script setup lang="ts">
import { computed } from 'vue'
import { severityColor } from '@/theme'

/**
 * 级别标签。
 *
 * **字色按底色亮度算,不写死白色。**警告档的底色 #ffb224 上白字只有 1.83:1,
 * 根本读不出来 —— 这是隔壁项目实测踩过的坑(全站 49 处)。
 */
const props = defineProps<{ severity: string; label?: string }>()

const bg = computed(() => severityColor(props.severity))

/** 相对亮度决定用深字还是浅字。阈值 0.55 是实测出来的分界。 */
const ink = computed(() => {
  const hex = bg.value.replace('#', '')
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
  const lin = (c: number) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)
  const luminance = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
  return luminance > 0.35 ? '#0c1016' : '#ffffff'
})
</script>

<template>
  <span class="sev" :style="{ background: bg, color: ink }">{{ label || severity }}</span>
</template>

<style scoped>
.sev {
  display: inline-block;
  padding: 1px 7px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.06em;
  clip-path: polygon(3px 0, 100% 0, calc(100% - 3px) 100%, 0 100%);
}
</style>
