<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'
import {
  NConfigProvider, NDialogProvider, NMessageProvider, darkTheme, zhCN, dateZhCN,
} from 'naive-ui'
import { darkOverrides } from '@/theme'
import { useMetaStore } from '@/stores/meta'
import { api } from '@/api'
import { usePolling } from '@/composables/usePolling'

/**
 * 应用外壳。
 *
 * 顶部那条状态栏里的健康指示是有意放在全局的:**"接口 200 但采集停了"
 * 是这类平台最难被发现的故障** —— 图还在,只是不更新了,而人不会去数
 * 时间轴的最后一个点是几分钟前的。这里把它做成一个常驻的红点。
 */

const route = useRoute()
const meta = useMetaStore()
const clock = ref(new Date())

const health = usePolling(() => api.health().then((r) => r.data), 30000)

onMounted(() => {
  void meta.load()
  window.setInterval(() => (clock.value = new Date()), 1000)
})

const clockText = computed(() => {
  const d = clock.value
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
})

const healthState = computed(() => {
  const h = health.data.value
  if (health.error.value) return { level: 'down', text: '后端连接失败' }
  if (!h) return { level: 'unknown', text: '检查中' }
  if (h.status === 'ok') return { level: 'up', text: `采集正常 · ${h.probes_enabled} 条线路` }
  const parts: string[] = []
  if (h.probes_never_run) parts.push(`${h.probes_never_run} 条从未执行`)
  if (h.probes_stale?.length) parts.push(`${h.probes_stale.length} 条采集停滞`)
  return { level: 'degraded', text: parts.join(' · ') || '采集异常' }
})

const DOT_COLORS: Record<string, string> = {
  up: '#2ee6a8', degraded: '#ffb224', down: '#ff5470', unknown: '#7a8fa0',
}
</script>

<template>
  <NConfigProvider
    :theme="darkTheme"
    :theme-overrides="darkOverrides"
    :locale="zhCN"
    :date-locale="dateZhCN"
  >
    <NMessageProvider :max="3">
      <NDialogProvider>
        <!-- 背景层:网格 + 缓慢漂移的辉光 -->
        <div class="cy-bg" />
        <!-- CRT 扫描线叠层 -->
        <div class="cy-scanlines" />

        <div class="app-shell">
          <header class="topbar">
            <div class="brand">
              <div class="logo">
                <span class="logo-mark" />
                <span class="logo-text cy-display cy-glitch" data-text="NET-CHECK">NET-CHECK</span>
              </div>
              <span class="brand-sub">网络线路检测与展示平台</span>
            </div>

            <nav class="nav">
              <RouterLink
                v-for="r in [
                  { to: '/', label: '监控大屏' },
                  { to: '/events', label: '事件记录' },
                  { to: '/config', label: '配置中心' },
                ]"
                :key="r.to"
                :to="r.to"
                class="cy-nav-item"
                :class="{ 'is-active': route.path === r.to }"
              >
                {{ r.label }}
              </RouterLink>
            </nav>

            <div class="status">
              <span class="health" :title="healthState.text">
                <i
                  class="cy-dot"
                  :class="{ 'is-live': healthState.level !== 'unknown', 'is-down': healthState.level === 'down' }"
                  :style="{ '--dot': DOT_COLORS[healthState.level] }"
                />
                <span class="health-txt" :style="{ color: DOT_COLORS[healthState.level] }">
                  {{ healthState.text }}
                </span>
              </span>
              <span class="clock cy-mono">{{ clockText }}</span>
            </div>
          </header>

          <main class="content">
            <RouterView />
          </main>
        </div>
      </NDialogProvider>
    </NMessageProvider>
  </NConfigProvider>
</template>

<style scoped>
.topbar {
  position: sticky;
  top: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  gap: 24px;
  padding: 11px 20px;
  background: linear-gradient(180deg, rgba(8, 11, 20, 0.96), rgba(8, 11, 20, 0.82));
  border-bottom: 1px solid rgba(34, 224, 232, 0.2);
  backdrop-filter: blur(9px);
  flex-wrap: wrap;
}
/* 顶栏下那道霓虹线 */
.topbar::after {
  content: '';
  position: absolute;
  left: 0;
  right: 0;
  bottom: -1px;
  height: 1px;
  background: linear-gradient(90deg, transparent, #22e0e8 22%, #ff3d8b 78%, transparent);
  opacity: 0.5;
}

.brand { display: flex; flex-direction: column; gap: 1px; }
.logo { display: flex; align-items: center; gap: 9px; }
.logo-mark {
  width: 15px;
  height: 15px;
  background: linear-gradient(135deg, #22e0e8, #ff3d8b);
  clip-path: polygon(50% 0, 100% 28%, 100% 72%, 50% 100%, 0 72%, 0 28%);
  box-shadow: 0 0 14px rgba(34, 224, 232, 0.6);
}
.logo-text {
  position: relative;
  font-size: 18px;
  letter-spacing: 0.14em;
  color: #e8f4f8;
  text-shadow: 0 0 18px rgba(34, 224, 232, 0.42);
}
.brand-sub {
  font-size: 10.5px;
  letter-spacing: 0.1em;
  color: #7a8fa0;
  padding-left: 24px;
}

.nav { display: flex; align-items: center; gap: 22px; margin-left: 14px; }

.status {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 18px;
}
.health { display: inline-flex; align-items: center; gap: 7px; }
.health-txt { font-size: 11.5px; font-weight: 600; letter-spacing: 0.03em; }
.clock { font-size: 12.5px; color: #a8bcc8; letter-spacing: 0.02em; }

.content {
  flex: 1;
  padding: 16px 20px 30px;
  min-width: 0;
}

@media (max-width: 820px) {
  .topbar { gap: 12px; }
  .brand-sub { display: none; }
  .status { width: 100%; margin-left: 0; justify-content: space-between; }
}
</style>
