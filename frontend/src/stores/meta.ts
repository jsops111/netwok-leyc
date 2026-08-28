import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api'
import type { Choice } from '@/api'

/**
 * 枚举字典。
 *
 * **前端不许硬编码中文枚举标签** —— 那是两边漂移的起点(后端改了标签,
 * 前端还显示旧的,而没有任何报错)。所有枚举从 /api/meta/choices/ 取。
 *
 * 只拉一次,存在 store 里。枚举不会在运行时变。
 */
export const useMetaStore = defineStore('meta', () => {
  const choices = ref<Record<string, Choice[]>>({})
  const loaded = ref(false)
  const error = ref('')

  async function load(force = false) {
    if (loaded.value && !force) return
    try {
      const { data } = await api.choices()
      choices.value = data
      loaded.value = true
      error.value = ''
    } catch (e) {
      const err = e as { friendlyMessage?: string }
      error.value = err?.friendlyMessage || '枚举字典加载失败'
    }
  }

  /** naive-ui 的 options 形状。取不到时返回空数组,不抛 —— 表单要能渲染出来。 */
  function options(key: string): Array<{ label: string; value: string }> {
    return (choices.value[key] || []).map((c) => ({ label: c.label, value: c.value }))
  }

  /** value → label。找不到就把 value 原样显示,不显示空白。 */
  function label(key: string, value: string | null | undefined): string {
    if (!value) return '—'
    return choices.value[key]?.find((c) => c.value === value)?.label || value
  }

  return { choices, loaded, error, load, options, label }
})
