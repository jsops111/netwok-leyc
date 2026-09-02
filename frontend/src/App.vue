<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import {
  NButton, NConfigProvider, NDialogProvider, NDropdown, NMessageProvider,
  NTooltip, darkTheme, lightTheme, zhCN, dateZhCN,
} from 'naive-ui'
import { darkOverrides, lightOverrides } from '@/theme'
import { useMetaStore } from '@/stores/meta'
import { useAuthStore } from '@/stores/auth'
import { useThemeStore } from '@/stores/theme'
import { api } from '@/api'
import { usePolling } from '@/composables/usePolling'

/**
 * 应用外壳。
 *
 * 顶部那条状态栏里的健康指示是有意放在全局的:**"接口 200 但采集停了"
 * 是这类平台最难被发现的故障** —— 图还在,只是不更新了,而人不会去数
 * 时间轴的最后一个点是几分钟前的。这里把它做成一个常驻的红点。
 *
 * 登录页不套这层外壳(`meta.bare`):导航、时钟、健康灯在没登录的时候
 * 全是噪声,而且顶栏上的那几个链接点了只会被守卫弹回来。
 */

const route = useRoute()
const router = useRouter()
const meta = useMetaStore()
const auth = useAuthStore()
const theme = useThemeStore()
const clock = ref(new Date())

const bare = computed(() => route.meta.bare === true)

// 健康接口是全站唯一不要求登录的(容器 healthcheck 打的就是它),
// 所以登录页上这个轮询也不会刷出一片 401
const health = usePolling(() => api.health().then((r) => r.data), 30000)

onMounted(() => {
  void auth.load().then(() => {
    // 枚举字典要登录后才拿得到 —— 未登录时拉一次只会拿到 401 并触发跳转
    if (auth.authenticated) void meta.load()
  })
  window.setInterval(() => (clock.value = new Date()), 1000)
})

async function logout() {
  await auth.logout()
  await router.replace('/login')
}

const NAV = [
  { to: '/', label: '监控大屏' },
  { to: '/servers', label: '服务器' },
  { to: '/backups', label: '配置备份' },
  { to: '/policies', label: '防火墙策略' },
  { to: '/events', label: '事件记录' },
  { to: '/config', label: '配置中心' },
  { to: '/manage', label: '管理后台' },
]

const userMenu = computed(() => [
  { key: 'manage', label: '管理后台' },
  { key: 'logout', label: '退出登录' },
])

function onUserMenu(key: string) {
  if (key === 'manage') void router.push('/manage')
  else if (key === 'logout') void logout()
}

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
  // 未登录时后端只给计数、不给名字(线路名和服务器名都是网络拓扑,
  // 不该在登录页上读到),所以这里用 count 而不是列表长度
  const stale = h.probes_stale_count ?? h.probes_stale?.length ?? 0
  if (stale) parts.push(`${stale} 条线路采集停滞`)
  const serverStale = h.servers_stale_count ?? h.servers_stale?.length ?? 0
  if (serverStale) parts.push(`${serverStale} 台服务器采集停滞`)
  return { level: 'degraded', text: parts.join(' · ') || '采集异常' }
})

const DOT_COLORS: Record<string, string> = {
  up: 'var(--cy-up)', degraded: 'var(--cy-degraded)', down: 'var(--cy-down)', unknown: 'var(--cy-unknown)',
}
</script>

<template>
  <NConfigProvider
    :theme="theme.isDark ? darkTheme : lightTheme"
    :theme-overrides="theme.isDark ? darkOverrides : lightOverrides"
    :locale="zhCN"
    :date-locale="dateZhCN"
  >
    <NMessageProvider :max="3">
      <NDialogProvider>
        <!-- 背景层:网格 + 缓慢漂移的辉光 -->
        <div class="cy-bg" />
        <!-- CRT 扫描线叠层 -->
        <div class="cy-scanlines" />

        <!-- 登录页只要背景,不要导航栏 -->
        <RouterView v-if="bare" />

        <div v-else class="app-shell">
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
                v-for="r in NAV"
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

              <NTooltip trigger="hover">
                <template #trigger>
                  <NButton text class="theme-btn" @click="theme.toggle()">
                    <!-- 图标表示"点了会变成什么",不是"现在是什么" ——
                         后者要人先反应一次"所以点了会怎样" -->
                    <span aria-hidden="true">{{ theme.isDark ? '☀' : '☾' }}</span>
                  </NButton>
                </template>
                {{ theme.isDark ? '切到亮色' : '切到深色' }}
              </NTooltip>

              <NDropdown
                v-if="auth.user"
                trigger="click"
                :options="userMenu"
                @select="onUserMenu"
              >
                <NButton text class="who">
                  <span class="who-name">{{ auth.user.display_name || auth.user.username }}</span>
                  <!-- 绑了两步验证的账号标一个盾,没绑的不标 —— 平台不强制绑定,
                       给未绑的人挂一个红叉是在指责一个允许的选择 -->
                  <span v-if="auth.user.two_factor" class="who-2fa" title="已开启两步验证">2FA</span>
                </NButton>
              </NDropdown>
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
  background: linear-gradient(180deg, rgba(var(--cy-body-rgb), 0.96), rgba(var(--cy-body-rgb), 0.82));
  border-bottom: 1px solid rgba(var(--cy-cyan-rgb), 0.2);
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
  background: linear-gradient(90deg, transparent, var(--cy-cyan) 22%, var(--cy-magenta) 78%, transparent);
  opacity: 0.5;
}

.brand { display: flex; flex-direction: column; gap: 1px; }
.logo { display: flex; align-items: center; gap: 9px; }
.logo-mark {
  width: 15px;
  height: 15px;
  background: linear-gradient(135deg, var(--cy-cyan), var(--cy-magenta));
  clip-path: polygon(50% 0, 100% 28%, 100% 72%, 50% 100%, 0 72%, 0 28%);
  box-shadow: 0 0 14px rgba(var(--cy-cyan-rgb), 0.6);
}
.logo-text {
  position: relative;
  font-size: 18px;
  letter-spacing: 0.14em;
  color: var(--cy-ink);
  text-shadow: 0 0 18px rgba(var(--cy-cyan-rgb), 0.42);
}
.brand-sub {
  font-size: 10.5px;
  letter-spacing: 0.1em;
  color: var(--cy-ink-3);
  padding-left: 24px;
}

/* 七个页签,窄屏上必须能换行 —— 不换行会把右边的状态栏挤出屏幕 */
.nav {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-left: 14px;
  flex-wrap: wrap;
  row-gap: 4px;
}

.status {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 18px;
}
.health { display: inline-flex; align-items: center; gap: 7px; }
.theme-btn {
  font-size: 15px;
  line-height: 1;
  color: var(--cy-ink-2);
  transition: color 0.15s ease;
}
.theme-btn:hover { color: var(--cy-cyan); }

.who { display: inline-flex; align-items: center; gap: 6px; }
.who-name { font-size: 12px; color: var(--cy-ink-2); letter-spacing: 0.02em; }
.who-2fa {
  font-family: 'JetBrains Mono', monospace;
  font-size: 9px;
  letter-spacing: 0.06em;
  color: var(--cy-up);
  border: 1px solid rgba(var(--cy-up-rgb), 0.42);
  padding: 0 3px;
  line-height: 13px;
}
.health-txt { font-size: 11.5px; font-weight: 600; letter-spacing: 0.03em; }
.clock { font-size: 12.5px; color: var(--cy-ink-2); letter-spacing: 0.02em; }

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
