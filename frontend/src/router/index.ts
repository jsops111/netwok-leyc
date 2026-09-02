import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

/**
 * 路由。八个页面 + 一个登录页。
 * 大屏是首页:这个平台绝大多数时间是挂在墙上被看的,不是被操作的。
 *
 * **除了登录页,全部要登录**(`meta.public` 是唯一的例外标记)。
 * 前端的守卫只是体验层 —— 真正的门在后端(DRF 默认 IsAuthenticated),
 * 别把"前端藏起来了"当成权限。
 */
const routes = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/Login.vue'),
    meta: { title: '登录', public: true, bare: true },
  },
  {
    path: '/',
    name: 'dashboard',
    component: () => import('@/views/Dashboard.vue'),
    meta: { title: '监控大屏', nav: '监控大屏' },
  },
  {
    path: '/servers',
    name: 'servers',
    component: () => import('@/views/Servers.vue'),
    meta: { title: '服务器', nav: '服务器' },
  },
  {
    path: '/interfaces',
    name: 'interfaces',
    component: () => import('@/views/Interfaces.vue'),
    meta: { title: '设备接口', nav: '设备接口' },
  },
  {
    path: '/backups',
    name: 'backups',
    component: () => import('@/views/Backups.vue'),
    meta: { title: '配置备份', nav: '配置备份' },
  },
  {
    path: '/policies',
    name: 'policies',
    component: () => import('@/views/Policies.vue'),
    meta: { title: '防火墙策略', nav: '防火墙策略' },
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
  {
    path: '/manage',
    name: 'manage',
    component: () => import('@/views/Manage.vue'),
    meta: { title: '管理后台', nav: '管理后台' },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  // **必须等第一次会话查询回来再判断。**不等的话刷新页面的瞬间 user 还是
  // null,已登录的人会被踢回登录页,session 回来又跳回去 —— 表现是每次
  // 刷新都闪一下登录框
  await auth.load()

  if (to.meta.public) {
    // 已登录的人点到登录页就直接送回大屏,不要让他对着登录框发呆
    return auth.authenticated ? { path: '/' } : true
  }
  if (!auth.authenticated) {
    // 记下他本来要去哪儿,登录后直接送过去
    return { path: '/login', query: to.fullPath === '/' ? {} : { next: to.fullPath } }
  }
  return true
})

router.afterEach((to) => {
  document.title = `${to.meta.title || '网络监控'} · NET-CHECK`
})

export default router
