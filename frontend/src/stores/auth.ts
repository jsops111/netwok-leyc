import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api } from '@/api'
import type { Me } from '@/api'

/**
 * 会话状态。
 *
 * `ready` 是这个 store 里最关键的一个字段:**路由守卫必须等它变 true 才判断**。
 * 不等的话,刷新页面的瞬间 user 还是 null,守卫会把一个已登录的人踢回登录页,
 * 然后 session 请求回来又跳回去 —— 表现是每次刷新都闪一下登录框。
 */
export const useAuthStore = defineStore('auth', () => {
  const user = ref<Me | null>(null)
  const ready = ref(false)

  const authenticated = computed(() => user.value !== null)
  /** 「用户管理 / 登录审计 / 系统信息」三个 tab 的开关 */
  const isAdmin = computed(() => !!user.value?.is_staff)

  async function load(force = false) {
    if (ready.value && !force) return user.value
    try {
      const { data } = await api.session()
      user.value = data.authenticated ? data.user : null
    } catch {
      // 拿不到会话(后端挂了)时按未登录处理 —— 空着让页面转圈更糟
      user.value = null
    } finally {
      ready.value = true
    }
    return user.value
  }

  /** 登录。返回 'ok' 或 'otp_required' —— 后者是流程第二步,不是错误。 */
  async function login(username: string, password: string, otp?: string) {
    const { data } = await api.login(username, password, otp)
    if (data.status === 'otp_required') return 'otp_required' as const
    user.value = data.user ?? null
    return 'ok' as const
  }

  async function logout() {
    try {
      await api.logout()
    } finally {
      user.value = null
    }
  }

  /** 401 拦截器调它 —— 会话在后台过期时,本地状态要跟着掉 */
  function clear() {
    user.value = null
    ready.value = true
  }

  return { user, ready, authenticated, isAdmin, load, login, logout, clear }
})
