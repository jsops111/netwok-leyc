<script setup lang="ts">
/**
 * 切角霓虹面板 —— 全站所有内容块的外壳。
 *
 * live 为 true 时开启扫描线动画,它表示"这块面板在自动刷新"。
 * **暂停刷新时要把 live 关掉**,否则那道线就成了纯装饰(见 cyber.css 的自律 1)。
 */
withDefaults(
  defineProps<{
    title?: string
    subtitle?: string
    /** 自动刷新中 —— 开扫描线 */
    live?: boolean
    /** critical / warning 会让整块面板的边框变色并脉冲 */
    level?: 'normal' | 'warning' | 'critical'
    /** 去掉 body 内边距(表格自己贴边时用) */
    flush?: boolean
  }>(),
  { live: false, level: 'normal', flush: false },
)
</script>

<template>
  <section
    class="cy-panel"
    :class="[
      { 'is-live': live },
      level === 'critical' ? 'is-critical' : level === 'warning' ? 'is-warning' : '',
    ]"
  >
    <div v-if="live" class="cy-sweep" />
    <header v-if="title || $slots.actions" class="cy-panel-head">
      <div class="cy-panel-title">
        {{ title }}
        <span v-if="subtitle" class="cy-panel-sub">{{ subtitle }}</span>
      </div>
      <div class="head-actions"><slot name="actions" /></div>
    </header>
    <div class="cy-panel-body" :style="flush ? { padding: '0' } : undefined">
      <slot />
    </div>
  </section>
</template>

<style scoped>
.head-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
</style>
