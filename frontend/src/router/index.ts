import { createRouter, createWebHistory } from 'vue-router'

/**
 * 三个页面 —— 需求里点名要的那三个。
 * 大屏是首页:这个平台绝大多数时间是挂在墙上被看的,不是被操作的。
 */
const routes = [
  {
    path: '/',
    name: 'dashboard',
    component: () => import('@/views/Dashboard.vue'),
    meta: { title: '监控大屏', nav: '监控大屏' },
  },
  {
    path: '/events',
    name: 'events',
    component: () => import('@/views/Events.vue'),
    meta: { title: '事件记录', nav: '事件记录' },
  },
  {
    path: '/config',
    name: 'config',
    component: () => import('@/views/Config.vue'),
    meta: { title: '配置中心', nav: '配置中心' },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.afterEach((to) => {
  document.title = `${to.meta.title || '网络监控'} · NET-CHECK`
})

export default router
