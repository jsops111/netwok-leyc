import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'

export type ThemeMode = 'dark' | 'light'

const KEY = 'netcheck-theme'

/**
 * 主题。深色是默认 —— 这个平台首先是挂在墙上的监控大屏。
 *
 * **主题写在 `<html>` 的 data-theme 上,不是写在组件里。**所有颜色都是
 * `styles/cyber.css` 里的 CSS 变量,换属性值整站跟着变,不需要任何组件重渲染。
 * 唯二的例外是 canvas(ECharts)和 naive-ui 的主题对象,它们不认 CSS 变量,
 * 所以要 watch `mode`(见图表组件和 App.vue)。
 *
 * 选择记在 localStorage:大屏是一台固定的机器,每次开机都要重选一次很烦。
 * **不跟随系统偏好** —— 机房那台机器的系统主题和"这块屏该长什么样"没关系,
 * 而跟随系统会让白天黑夜自己跳变,大屏上那是很突兀的。
 */
export const useThemeStore = defineStore('theme', () => {
  const mode = ref<ThemeMode>(read())

  function read(): ThemeMode {
    try {
      return localStorage.getItem(KEY) === 'light' ? 'light' : 'dark'
    } catch {
      // 隐私模式 / 禁用了存储 —— 回落到默认,不要因此崩掉整个应用
      return 'dark'
    }
  }

  function apply(value: ThemeMode) {
    document.documentElement.setAttribute('data-theme', value)
    try {
      localStorage.setItem(KEY, value)
    } catch {
      /* 存不上就算了,本次会话内仍然生效 */
    }
  }

  function toggle() {
    mode.value = mode.value === 'dark' ? 'light' : 'dark'
  }

  const isDark = computed(() => mode.value === 'dark')

  watch(mode, apply, { immediate: true })

  return { mode, isDark, toggle }
})
