import { onScopeDispose, ref, shallowRef } from 'vue'

/**
 * 轮询。大屏的三个数据源都走它。
 *
 * 三条不显然但必要的处理:
 *
 * 1. **页签隐藏时暂停。**大屏常年开着,但运维也会切到别的页签。不暂停的话
 *    一个后台页签会持续每 5 秒打一次接口,一整天几万个无人看的请求。
 *    回到前台立刻补一次,不等下个周期 —— 否则切回来看到的是旧数据。
 * 2. **上一次请求没回来就跳过这一拍。**接口偶尔慢到超过轮询间隔时,
 *    不跳过会让请求叠着堆积,越来越慢。
 * 3. **失败不清空已有数据。**网络抖一下就把图清空,比显示"数据是 5 秒前的"
 *    糟糕得多。失败只记 error 和 stale,数据留着。
 */
export function usePolling<T>(
  fetcher: () => Promise<T>,
  intervalMs = 5000,
  options: { immediate?: boolean } = {},
) {
  const data = shallowRef<T | null>(null)
  const loading = ref(false)
  const error = ref('')
  const lastSuccess = ref<Date | null>(null)
  const paused = ref(false)
  const inFlight = ref(false)

  let timer: number | undefined
  let disposed = false

  async function refresh(): Promise<void> {
    if (inFlight.value || disposed) return
    inFlight.value = true
    if (data.value === null) loading.value = true
    try {
      const result = await fetcher()
      if (disposed) return
      data.value = result
      error.value = ''
      lastSuccess.value = new Date()
    } catch (e) {
      if (disposed) return
      const err = e as { friendlyMessage?: string; message?: string }
      error.value = err?.friendlyMessage || err?.message || '刷新失败'
    } finally {
      inFlight.value = false
      loading.value = false
    }
  }

  function tick() {
    if (!paused.value && !document.hidden) void refresh()
  }

  function start() {
    stop()
    timer = window.setInterval(tick, intervalMs)
  }

  function stop() {
    if (timer !== undefined) {
      window.clearInterval(timer)
      timer = undefined
    }
  }

  function onVisibility() {
    if (!document.hidden && !paused.value) void refresh()
  }

  document.addEventListener('visibilitychange', onVisibility)
  if (options.immediate !== false) void refresh()
  start()

  onScopeDispose(() => {
    disposed = true
    stop()
    document.removeEventListener('visibilitychange', onVisibility)
  })

  /** 数据是否已经陈旧 —— 面板角上那个"上次刷新"提示用它变色。 */
  function isStale(toleranceMs = intervalMs * 3): boolean {
    if (!lastSuccess.value) return false
    return Date.now() - lastSuccess.value.getTime() > toleranceMs
  }

  return {
    data, loading, error, lastSuccess, paused, refresh,
    start, stop, isStale,
    toggle: () => {
      paused.value = !paused.value
      if (!paused.value) void refresh()
    },
  }
}
