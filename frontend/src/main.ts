import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import { setUnauthorizedHandler } from './api'
import { useAuthStore } from './stores/auth'
import './styles/global.css'

const app = createApp(App)
const pinia = createPinia()
app.use(pinia).use(router)

/**
 * 会话在后台过期时(比如 30 天到了,或者管理员停用了这个账号),
 * 任何一个轮询请求都会拿到 401。这里把本地状态清掉并送去登录页 ——
 * 不做的话大屏会停在最后一帧数据上"看起来还活着",而它其实已经不刷新了。
 */
setUnauthorizedHandler(() => {
  const auth = useAuthStore(pinia)
  if (!auth.authenticated && router.currentRoute.value.meta.public) return
  auth.clear()
  const current = router.currentRoute.value
  if (!current.meta.public) {
    void router.replace({ path: '/login', query: current.fullPath === '/' ? {} : { next: current.fullPath } })
  }
})

app.mount('#app')
