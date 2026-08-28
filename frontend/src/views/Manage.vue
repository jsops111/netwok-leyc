<script setup lang="ts">
import { computed, h, onMounted, ref, watch } from 'vue'
import {
  NButton, NDataTable, NInput, NInputNumber, NModal, NPopconfirm, NSelect,
  NSpace, NSwitch, NTabPane, NTabs, NTag, useMessage,
} from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import MeterBar from '@/components/cyber/MeterBar.vue'
import SchemaForm from '@/components/SchemaForm.vue'
import type { FieldSpec } from '@/components/SchemaForm.vue'
import { api, errText } from '@/api'
import type { LoginAuditRow, RetentionPolicy, SystemInfo, UserRow } from '@/api'
import { useAuthStore } from '@/stores/auth'
import { ago, bytes, dateTimeOf, int } from '@/composables/useFormat'
import { STATE } from '@/theme'

/**
 * 管理后台。四个 tab:用户管理 / 我的安全 / 登录审计 / 系统信息。
 *
 * **只有「我的安全」对所有人开放**,另外三个要 is_staff —— 而且不是靠
 * 前端藏起来就算数的:后端 /api/manage/* 整段是 IsAdminUser。这里的隐藏
 * 只是别让人点到一个必然 403 的 tab。
 *
 * 两步验证在这里是**自愿绑定**的:平台不强制,但要有这个能力。
 * 绑定流程刻意做成三步(生成 → 扫码 → 输一次码确认),第三步不能省:
 * 跳过它的话,手机时间不同步这类问题要等到下次登录才暴露,
 * 而那时人已经被自己锁在门外了。
 */

const message = useMessage()
const auth = useAuthStore()

const tab = ref(auth.isAdmin ? 'users' : 'security')

// ================================================================ 用户管理

const users = ref<UserRow[]>([])
const usersLoading = ref(false)

async function loadUsers() {
  if (!auth.isAdmin) return
  usersLoading.value = true
  try {
    const { data } = await api.users({ page_size: 200 })
    users.value = data.results
  } catch (e) {
    message.error(errText(e))
  } finally {
    usersLoading.value = false
  }
}

const userModal = ref(false)
const userForm = ref<Record<string, any>>({})
const userErrors = ref<Record<string, string>>({})
const savingUser = ref(false)
const isNewUser = computed(() => !userForm.value.id)

const USER_FIELDS: FieldSpec[] = [
  { key: 'username', label: '用户名', type: 'text', required: true, placeholder: '登录用的账号' },
  { key: 'display_name', label: '姓名', type: 'text', placeholder: '显示用,可留空' },
  { key: 'email', label: '邮箱', type: 'text', placeholder: '可留空' },
  {
    key: 'password', label: '密码', type: 'password', full: true,
    // 编辑时留空 = 不修改,和配置中心的凭据字段同一个规矩
    hint: '至少 10 位,不能是纯数字或常见弱口令。编辑时留空表示不修改。',
  },
  { key: 'is_active', label: '启用', type: 'switch', hint: '停用后无法登录,已有会话下次请求即失效' },
  { key: 'is_staff', label: '管理员', type: 'switch', hint: '能进管理后台:用户管理 / 登录审计 / 系统信息' },
]

function openUser(row?: UserRow) {
  userErrors.value = {}
  userForm.value = row
    ? { ...row, password: '' }
    : { username: '', display_name: '', email: '', password: '', is_active: true, is_staff: false }
  userModal.value = true
}

async function saveUser() {
  savingUser.value = true
  userErrors.value = {}
  const body = { ...userForm.value }
  if (!isNewUser.value && !body.password) delete body.password
  try {
    isNewUser.value ? await api.createUser(body) : await api.updateUser(body.id, body)
    message.success(isNewUser.value ? '用户已创建' : '已保存')
    userModal.value = false
    await loadUsers()
  } catch (e) {
    const data = (e as any)?.response?.data
    if (data && typeof data === 'object') {
      const errs: Record<string, string> = {}
      for (const [k, v] of Object.entries(data)) errs[k] = Array.isArray(v) ? v.join('; ') : String(v)
      userErrors.value = errs
    }
    message.error(errText(e))
  } finally {
    savingUser.value = false
  }
}

async function userAction(fn: () => Promise<any>, okText: string) {
  try {
    await fn()
    message.success(okText)
    await loadUsers()
  } catch (e) {
    message.error(errText(e))
  }
}

// 管理员重置别人的密码 —— 单独一个小弹窗,不走编辑表单:
// 在一个有六个字段的表单里改密码,容易顺手把别的字段也改了
const resetTarget = ref<UserRow | null>(null)
const resetPassword = ref('')
const resetting = ref(false)

async function doReset() {
  if (!resetTarget.value) return
  resetting.value = true
  try {
    await api.resetUserPassword(resetTarget.value.id, resetPassword.value)
    message.success(`${resetTarget.value.username} 的密码已重置`)
    resetTarget.value = null
    resetPassword.value = ''
  } catch (e) {
    message.error(errText(e))
  } finally {
    resetting.value = false
  }
}

const userColumns: DataTableColumns<UserRow> = [
  {
    title: '用户', key: 'username', width: 190, fixed: 'left',
    render: (r) => h('div', { style: 'line-height:1.45' }, [
      h('div', { style: 'font-weight:600' }, [
        r.username,
        r.id === auth.user?.id
          ? h(NTag, { size: 'tiny', type: 'info', bordered: false, style: 'margin-left:6px' }, () => '我')
          : null,
      ]),
      h('div', { style: 'font-size:10.5px;color:var(--cy-ink-3)' }, r.display_name || r.email || '—'),
    ]),
  },
  {
    title: '权限', key: 'is_staff', width: 92,
    render: (r) => h(NTag, {
      size: 'small', bordered: false,
      type: r.is_superuser ? 'error' : r.is_staff ? 'warning' : 'default',
    }, () => (r.is_superuser ? '超级管理员' : r.is_staff ? '管理员' : '普通用户')),
  },
  {
    title: '两步验证', key: 'two_factor', width: 128,
    render: (r) => (r.two_factor
      ? h('div', { style: 'line-height:1.4' }, [
        h('span', { style: `color:${STATE.up};font-size:11.5px;font-weight:600` }, '已开启'),
        h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' }, `恢复码剩 ${r.recovery_left}`),
      ])
      // 未开启不用红色 —— 平台不强制绑定,这是一个状态不是一个故障
      : h('span', { style: 'color:var(--cy-ink-3);font-size:11.5px' }, '未开启')),
  },
  {
    title: '最后登录', key: 'last_login', width: 168,
    render: (r) => h('div', { style: 'line-height:1.4' }, [
      h('div', { style: 'font-size:11px' }, r.last_login ? ago(r.last_login) : '从未登录'),
      h('div', { class: 'cy-mono', style: 'font-size:10px;color:var(--cy-ink-3)' }, r.last_login_ip || '—'),
    ]),
  },
  {
    title: '启用', key: 'is_active', width: 66,
    render: (r) => h(NSwitch, {
      value: r.is_active, size: 'small', disabled: r.id === auth.user?.id,
      onUpdateValue: () => userAction(
        () => api.updateUser(r.id, { is_active: !r.is_active }), r.is_active ? '已停用' : '已启用',
      ),
    }),
  },
  {
    title: '操作', key: 'act', width: 250, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', ghost: true, onClick: () => openUser(r) }, () => '编辑'),
      h(NButton, {
        size: 'tiny', ghost: true, type: 'warning',
        onClick: () => { resetTarget.value = r; resetPassword.value = '' },
      }, () => '重置密码'),
      r.two_factor
        ? h(NPopconfirm, {
          onPositiveClick: () => userAction(() => api.disableUser2fa(r.id), '已强制解绑'),
        }, {
          trigger: () => h(NButton, { size: 'tiny', text: true, type: 'warning' }, () => '解绑2FA'),
          default: () => `强制解除 ${r.username} 的两步验证?这条操作会记进登录审计。`,
        })
        : null,
      h(NButton, {
        size: 'tiny', text: true,
        onClick: () => userAction(() => api.unlockUser(r.id), '已清除失败计数'),
      }, () => '解锁'),
      r.id === auth.user?.id
        ? null
        : h(NPopconfirm, { onPositiveClick: () => userAction(() => api.deleteUser(r.id), '已删除') }, {
          trigger: () => h(NButton, { size: 'tiny', text: true, type: 'error' }, () => '删除'),
          default: () => `删除 ${r.username}?`,
        }),
    ]),
  },
]

// ================================================================ 我的安全

const pwdForm = ref({ old_password: '', new_password: '', confirm: '' })
const pwdErrors = ref<Record<string, string>>({})
const changingPwd = ref(false)

async function submitPassword() {
  pwdErrors.value = {}
  if (pwdForm.value.new_password !== pwdForm.value.confirm) {
    pwdErrors.value = { confirm: '两次输入的新密码不一致' }
    return
  }
  changingPwd.value = true
  try {
    await api.changePassword(pwdForm.value.old_password, pwdForm.value.new_password)
    message.success('密码已修改')
    pwdForm.value = { old_password: '', new_password: '', confirm: '' }
  } catch (e) {
    const data = (e as any)?.response?.data
    if (data && typeof data === 'object') {
      const errs: Record<string, string> = {}
      for (const [k, v] of Object.entries(data)) errs[k] = Array.isArray(v) ? v.join('; ') : String(v)
      pwdErrors.value = errs
    }
    message.error(errText(e))
  } finally {
    changingPwd.value = false
  }
}

// ---- 两步验证绑定 ----
const setup = ref<{ secret: string; uri: string; qr_svg: string } | null>(null)
const bindCode = ref('')
const binding = ref(false)
const recoveryCodes = ref<string[]>([])
const confirmPwd = ref('')
const pwdPrompt = ref<'disable' | 'recovery' | null>(null)
const promptBusy = ref(false)

async function startBind() {
  try {
    const { data } = await api.totpSetup()
    setup.value = data
    bindCode.value = ''
  } catch (e) {
    message.error(errText(e))
  }
}

async function confirmBind() {
  binding.value = true
  try {
    const { data } = await api.totpConfirm(bindCode.value.trim())
    recoveryCodes.value = data.recovery_codes
    setup.value = null
    bindCode.value = ''
    await auth.load(true)
    message.success('两步验证已开启')
  } catch (e) {
    message.error(errText(e))
  } finally {
    binding.value = false
  }
}

async function submitPrompt() {
  promptBusy.value = true
  try {
    if (pwdPrompt.value === 'disable') {
      await api.totpDisable(confirmPwd.value)
      message.success('两步验证已关闭')
      recoveryCodes.value = []
    } else {
      const { data } = await api.totpRecovery(confirmPwd.value)
      recoveryCodes.value = data.recovery_codes
      message.success('恢复码已重新生成,旧的全部作废')
    }
    pwdPrompt.value = null
    confirmPwd.value = ''
    await auth.load(true)
  } catch (e) {
    message.error(errText(e))
  } finally {
    promptBusy.value = false
  }
}

async function copyCodes() {
  const text = recoveryCodes.value.join('\n')
  try {
    await navigator.clipboard.writeText(text)
    message.success('已复制到剪贴板')
  } catch {
    // http 页面下 clipboard API 不可用 —— 这是内网 http 部署的常态,
    // 所以要给出替代路径,而不是只报一句"复制失败"
    message.warning('浏览器不允许复制,请手动选中下面的恢复码')
  }
}

// ================================================================ 登录审计

const audit = ref<LoginAuditRow[]>([])
const auditLoading = ref(false)
const auditTotal = ref(0)
const auditPage = ref(1)
const auditResult = ref<string | null>(null)
const auditSearch = ref('')

const AUDIT_COLORS: Record<string, string> = {
  ok: STATE.up,
  otp_required: STATE.degraded,
  logout: STATE.unknown,
}

async function loadAudit() {
  if (!auth.isAdmin) return
  auditLoading.value = true
  try {
    const { data } = await api.loginAudit({
      page: auditPage.value, page_size: 20,
      result: auditResult.value || undefined,
      search: auditSearch.value || undefined,
    })
    audit.value = data.results
    auditTotal.value = data.count
  } catch (e) {
    message.error(errText(e))
  } finally {
    auditLoading.value = false
  }
}

watch([auditResult, auditSearch], () => { auditPage.value = 1; void loadAudit() })
watch(auditPage, () => void loadAudit())

// 结果枚举从后端来(序列化器给了 result_label),前端不硬编码中文标签
const auditOptions = computed(() => {
  const seen = new Map<string, string>()
  for (const row of audit.value) seen.set(row.result, row.result_label)
  return [...seen].map(([value, label]) => ({ value, label }))
})

const auditColumns: DataTableColumns<LoginAuditRow> = [
  { title: '时间', key: 'created_at', width: 165,
    render: (r) => h('span', { class: 'cy-mono', style: 'font-size:11px' }, dateTimeOf(r.created_at)) },
  { title: '用户名', key: 'username', width: 140,
    render: (r) => h('span', { style: 'font-weight:600' }, r.username) },
  { title: '结果', key: 'result', width: 118,
    render: (r) => h('span', {
      style: `color:${AUDIT_COLORS[r.result] || STATE.down};font-size:11.5px;font-weight:600`,
    }, r.result_label) },
  { title: '两步', key: 'used_2fa', width: 58,
    render: (r) => (r.used_2fa ? h('span', { style: `color:${STATE.up}` }, '✓') : h('span', { style: 'color:var(--cy-ink-3)' }, '—')) },
  { title: '来源 IP', key: 'ip', width: 130,
    render: (r) => h('span', { class: 'cy-mono', style: 'font-size:11px' }, r.ip || '—') },
  { title: '说明', key: 'detail', ellipsis: { tooltip: true },
    render: (r) => h('span', { style: 'font-size:11px;color:var(--cy-ink-2)' }, r.detail || r.user_agent || '—') },
]

// ================================================================ 系统信息

const sys = ref<SystemInfo | null>(null)
const sysLoading = ref(false)

async function loadSystem() {
  if (!auth.isAdmin) return
  sysLoading.value = true
  try {
    const { data } = await api.systemInfo()
    sys.value = data
  } catch (e) {
    message.error(errText(e))
  } finally {
    sysLoading.value = false
  }
}

// ---- 数据保留策略 ----
// 改这个的典型场景是磁盘快满了的半夜,所以它必须是页面上点几下就能改的。
// 改完下一次清理任务(每小时)按新值执行,不用重启任何进程。
const retention = ref<RetentionPolicy | null>(null)
const retentionErrors = ref<Record<string, string>>({})
const savingRetention = ref(false)

interface RetentionField {
  key: keyof RetentionPolicy
  label: string
  unit: string
  hint?: string
  /** 允许填 0 表示永久 */
  forever?: boolean
}

const RETENTION_FIELDS: RetentionField[] = [
  { key: 'raw_hours', label: '原始秒级样本', unit: '小时',
    hint: '磁盘的主要消费者。一条 1 秒频率的线路一天约 86400 行' },
  { key: 'rollup_1m_days', label: '1 分钟桶', unit: '天', hint: '≤2 天跨度的图查它' },
  { key: 'rollup_5m_days', label: '5 分钟桶', unit: '天', hint: '≤14 天跨度的图查它' },
  { key: 'rollup_1h_days', label: '1 小时桶', unit: '天', forever: true,
    hint: '0 = 永久。一条线路一年才 8760 行,是唯一能回答「去年这条线怎么样」的数据' },
  { key: 'event_days', label: '事件', unit: '天', forever: true,
    hint: '0 = 永久。只删已恢复的;事件是复盘材料,不是磁盘的矛盾所在' },
  { key: 'notify_log_days', label: '推送记录', unit: '天', hint: '「告警到底发出去没有」的审计材料' },
  { key: 'login_audit_days', label: '登录审计', unit: '天', hint: '谁在什么时候登过这台机器' },
]

const retentionError = ref('')

async function loadRetention() {
  if (!auth.isAdmin) return
  retentionError.value = ''
  try {
    const { data } = await api.retention()
    retention.value = data
  } catch (e) {
    // **失败要在面板里留下痕迹。**原来这里只弹一个会消失的 toast,
    // 然后面板静默地少掉整块输入区 —— 看到的人只会以为"没做这个功能",
    // 而真正的原因(后端是旧版、没有这个接口)一点线索都没有
    retentionError.value = errText(e)
    // 系统信息接口里也带了一份保留策略,拿它兜底,至少能看到当前值
    if (sys.value?.retention) retention.value = { ...sys.value.retention }
  }
}

async function saveRetention() {
  if (!retention.value) return
  savingRetention.value = true
  retentionErrors.value = {}
  try {
    const { data } = await api.updateRetention(retention.value)
    retention.value = data
    message.success('保留策略已保存,下一次清理按新值执行')
    await loadSystem()
  } catch (e) {
    const d = (e as any)?.response?.data
    if (d && typeof d === 'object') {
      const errs: Record<string, string> = {}
      for (const [k, v] of Object.entries(d)) errs[k] = Array.isArray(v) ? v.join('; ') : String(v)
      retentionErrors.value = errs
    }
    retentionError.value = errText(e)
    message.error(errText(e))
  } finally {
    savingRetention.value = false
  }
}

// 磁盘使用率的告警线。**这是展示用的固定刻度,不是可配阈值** ——
// 磁盘满了是硬故障,80/90 是通用经验值,不值得再加一个配置项
const DISK_WARN = 80
const DISK_CRIT = 90

const COUNT_LABELS: Record<string, string> = {
  probes: '检测线路', probes_enabled: '其中启用', devices: '网络设备',
  notifiers: '通知渠道', events: '事件', samples: '原始样本(估算)',
  users: '用户', users_active: '启用中', users_2fa: '已绑两步验证',
}

onMounted(() => {
  void auth.load()
  void loadUsers()
  void loadAudit()
  // 先取 system(它带一份保留策略),再取 retention —— 后者失败时能兜底
  void loadSystem().then(loadRetention)
})
</script>

<template>
  <div class="mg">
    <NTabs v-model:value="tab" type="line" animated>
      <!-- ============ 用户管理 ============ -->
      <NTabPane v-if="auth.isAdmin" name="users" tab="用户管理">
        <CyberPanel title="用户" :subtitle="`${users.length} 个账号`" flush>
          <template #actions>
            <NButton size="small" type="primary" ghost @click="openUser()">新建用户</NButton>
            <NButton size="small" ghost :loading="usersLoading" @click="loadUsers()">刷新</NButton>
          </template>
          <NDataTable
            :columns="userColumns" :data="users" :loading="usersLoading"
            size="small" :bordered="false" :single-line="false" :scroll-x="1030"
            :pagination="{ pageSize: 20 }"
          />
        </CyberPanel>
      </NTabPane>

      <!-- ============ 我的安全 ============ -->
      <NTabPane name="security" tab="我的安全">
        <div class="sec-grid">
          <!-- 改密码 -->
          <CyberPanel title="修改密码" :subtitle="auth.user?.username">
            <div class="stack">
              <label class="lab">当前密码</label>
              <NInput
                v-model:value="pwdForm.old_password" type="password" show-password-on="click"
                :status="pwdErrors.old_password ? 'error' : undefined"
              />
              <p v-if="pwdErrors.old_password" class="fe">{{ pwdErrors.old_password }}</p>

              <label class="lab">新密码</label>
              <NInput
                v-model:value="pwdForm.new_password" type="password" show-password-on="click"
                :status="pwdErrors.new_password ? 'error' : undefined"
              />
              <p class="fe hint">至少 10 位,不能是纯数字、常见弱口令,或和用户名太像。</p>
              <p v-if="pwdErrors.new_password" class="fe">{{ pwdErrors.new_password }}</p>

              <label class="lab">确认新密码</label>
              <NInput
                v-model:value="pwdForm.confirm" type="password" show-password-on="click"
                :status="pwdErrors.confirm ? 'error' : undefined"
              />
              <p v-if="pwdErrors.confirm" class="fe">{{ pwdErrors.confirm }}</p>

              <NButton
                type="primary" :loading="changingPwd" class="mt"
                :disabled="!pwdForm.old_password || !pwdForm.new_password"
                @click="submitPassword"
              >
                修改密码
              </NButton>
            </div>
          </CyberPanel>

          <!-- 两步验证 -->
          <CyberPanel
            title="两步验证"
            :subtitle="auth.user?.two_factor ? '已开启' : '未开启 · 自愿绑定'"
          >
            <!-- 已绑定 -->
            <div v-if="auth.user?.two_factor && !setup" class="stack">
              <div class="on-badge">
                <span class="cy-dot is-live" style="--dot: var(--cy-up)" />
                登录时除了密码,还要输一次验证器上的 6 位码
              </div>
              <div class="kv">
                <span>剩余恢复码</span>
                <b :class="{ low: (auth.user?.recovery_left ?? 0) <= 2 }">
                  {{ auth.user?.recovery_left }} / 10
                </b>
              </div>
              <p class="note">
                恢复码是手机丢了时唯一的自救路径。用完了、或者怀疑泄露了,
                在这里重新生成一套 —— 旧的会全部作废。
              </p>
              <NSpace>
                <NButton size="small" ghost @click="pwdPrompt = 'recovery'">重新生成恢复码</NButton>
                <NButton size="small" ghost type="error" @click="pwdPrompt = 'disable'">关闭两步验证</NButton>
              </NSpace>
            </div>

            <!-- 未绑定,还没开始 -->
            <div v-else-if="!setup" class="stack">
              <p class="note">
                <b>这一项不是必须的。</b>开启之后,登录要在密码之外再输一次
                验证器 App(Google Authenticator / 微软 Authenticator / 1Password 等)
                上的 6 位动态码。密码被别人知道了也进不来。
              </p>
              <NButton type="primary" ghost @click="startBind">开始绑定</NButton>
            </div>

            <!-- 绑定中 -->
            <div v-else class="stack">
              <div class="qr-row">
                <!-- 二维码由后端渲染成 SVG:一个一辈子只用一次的功能,
                     不值得让每个访问大屏的人都下载一份 QR 生成库 -->
                <div class="qr" v-html="setup.qr_svg" />
                <div class="qr-side">
                  <p class="note">用验证器 App 扫这个码。扫不了就手动输入密钥:</p>
                  <code class="secret cy-mono">{{ setup.secret }}</code>
                </div>
              </div>
              <label class="lab">输入 App 上显示的 6 位码,确认绑定</label>
              <NInput
                v-model:value="bindCode" placeholder="6 位数字" class="cy-mono"
                @keyup.enter="confirmBind"
              />
              <p class="fe hint">
                <b>必须验证一次才算绑定成功。</b>跳过这一步的话,手机时间不同步
                这类问题要等到下次登录才暴露,而那时人已经被锁在门外了。
              </p>
              <NSpace class="mt">
                <NButton
                  type="primary" :loading="binding" :disabled="bindCode.trim().length < 6"
                  @click="confirmBind"
                >
                  确认绑定
                </NButton>
                <NButton ghost @click="setup = null">取消</NButton>
              </NSpace>
            </div>
          </CyberPanel>
        </div>
      </NTabPane>

      <!-- ============ 登录审计 ============ -->
      <NTabPane v-if="auth.isAdmin" name="audit" tab="登录审计">
        <CyberPanel title="登录记录" :subtitle="`共 ${int(auditTotal)} 条`" flush>
          <template #actions>
            <NSelect
              v-model:value="auditResult" :options="auditOptions" placeholder="全部结果"
              clearable size="small" style="width: 150px"
            />
            <NInput
              v-model:value="auditSearch" placeholder="用户名 / IP" clearable size="small"
              style="width: 170px"
            />
            <NButton size="small" ghost :loading="auditLoading" @click="loadAudit()">刷新</NButton>
          </template>
          <NDataTable
            :columns="auditColumns" :data="audit" :loading="auditLoading"
            size="small" :bordered="false" :single-line="false" :scroll-x="880"
            remote
            :pagination="{
              page: auditPage, pageSize: 20, itemCount: auditTotal,
              'onUpdate:page': (p: number) => (auditPage = p),
            }"
          />
          <div v-if="!audit.length && !auditLoading" class="cy-empty">
            没有匹配的登录记录。
          </div>
        </CyberPanel>
      </NTabPane>

      <!-- ============ 系统信息 ============ -->
      <NTabPane v-if="auth.isAdmin" name="system" tab="系统信息">
        <!-- 磁盘单独一整行:这是数据采集平台,涨起来的就是磁盘 -->
        <CyberPanel
          title="磁盘"
          :subtitle="sys?.disk?.ok ? `${sys.disk.path} · 承载 Docker 数据的那块盘` : '读不到'"
          :level="(sys?.disk?.percent ?? 0) >= DISK_CRIT ? 'critical'
            : (sys?.disk?.percent ?? 0) >= DISK_WARN ? 'warning' : 'normal'"
          class="disk-panel"
        >
          <template #actions>
            <NButton size="small" ghost :loading="sysLoading" @click="loadSystem()">刷新</NButton>
          </template>
          <div v-if="sys?.disk?.ok" class="disk">
            <div class="disk-meter">
              <MeterBar
                :value="sys.disk.percent" :warn="DISK_WARN" :crit="DISK_CRIT" label="已用"
              />
              <div class="disk-nums cy-mono">
                <span>总 {{ bytes(sys.disk.total) }}</span>
                <span>已用 {{ bytes(sys.disk.used) }}</span>
                <span class="free">可用 {{ bytes(sys.disk.free) }}</span>
              </div>
            </div>

            <div class="disk-growth">
              <div class="kv">
                <span>每天新增样本</span>
                <b class="cy-mono">{{ int(sys.growth?.rows_per_day) }} 行</b>
              </div>
              <div class="kv">
                <span>折算每天</span>
                <b class="cy-mono">{{ bytes(sys.growth?.bytes_per_day) }}</b>
              </div>
              <div class="kv">
                <span>保留期内稳定占用</span>
                <b class="cy-mono">{{ bytes(sys.growth?.steady_bytes) }}</b>
              </div>
              <p class="note tiny">
                按<b>当前线路配置</b>推算(每条线路每天写 86400÷间隔 行),不是实测增速。
                单行字节数由样本表实际大小反推,所以刚部署时还没有这个数。
                清理跑起来之后,原始表会稳定在「保留期内稳定占用」那个量级。
              </p>
            </div>
          </div>
          <div v-else class="cy-empty">
            读不到磁盘用量:{{ sys?.disk?.error || '—' }}
          </div>
        </CyberPanel>

        <!-- 保留策略:磁盘不够时就是在这里动手 -->
        <CyberPanel
          title="数据保留"
          :subtitle="retention?.updated_by ? `最后由 ${retention.updated_by} 修改` : '默认值'"
        >
          <template #actions>
            <NButton
              size="small" type="primary" ghost :loading="savingRetention"
              :disabled="!retention" @click="saveRetention"
            >
              保存
            </NButton>
          </template>
          <p class="note">
            改完<b>下一次清理任务就按新值执行</b>,不用重启任何进程。
            磁盘告急时先缩「原始秒级样本」—— 它是主要消费者,而长期趋势看的是降采样桶,不受影响。
          </p>
          <div v-if="retentionError" class="ret-error">
            <b>读不到保留策略:</b>{{ retentionError }}
            <div class="ret-error-hint">
              如果这里显示 404,说明<b>后端还是旧版本</b> ——
              保留策略的接口在后端,只重建前端不够。
              在服务器上 <code>git pull</code> 后**把 backend 也重建一次**,
              然后 <code>docker compose up -d</code>。
            </div>
            <NButton size="tiny" ghost class="ret-retry" @click="loadRetention()">重试</NButton>
          </div>
          <div v-if="retention" class="ret-grid">
            <div v-for="f in RETENTION_FIELDS" :key="f.key" class="ret-item">
              <label class="lab">{{ f.label }}</label>
              <NInputNumber
                v-model:value="(retention[f.key] as number)"
                :min="f.forever ? 0 : 1" :status="retentionErrors[f.key] ? 'error' : undefined"
                size="small" style="width: 100%"
              >
                <template #suffix>{{ f.unit }}</template>
              </NInputNumber>
              <p class="fe" :class="{ hint: !retentionErrors[f.key] }">
                {{ retentionErrors[f.key] || f.hint }}
              </p>
            </div>
          </div>
          <div v-if="!retention && !retentionError" class="cy-empty">加载中…</div>
          <p v-if="retention" class="note tiny warnline">
            <b>粗粒度的保留不能短于细粒度的。</b>图表按跨度自动选粒度
            (≤2h 原始 / ≤2d 1m / ≤14d 5m / 更长 1h),细桶比粗桶留得久的话,
            查粗桶的那个跨度就是一片空白 —— 后端会挡住这种配置。
          </p>
        </CyberPanel>

        <div class="sys-grid">
          <CyberPanel title="运行参数">
            <template #actions>
              <NButton size="small" ghost :loading="sysLoading" @click="loadSystem()">刷新</NButton>
            </template>
            <div v-if="sys" class="kvs">
              <div class="kv"><span>版本</span><b class="cy-mono">{{ sys.version }}</b></div>
              <div class="kv"><span>时区</span><b>{{ sys.timezone }}</b></div>
              <div class="kv">
                <span>DEBUG</span>
                <!-- 生产开着 DEBUG 是要能一眼看到的事:它会把 SQL 和配置
                     写进报错页面 -->
                <b :style="sys.debug ? `color:${STATE.down}` : ''">{{ sys.debug ? '开启(生产不该开)' : '关闭' }}</b>
              </div>
              <div class="kv"><span>派发间隔</span><b>{{ sys.tick_seconds }} 秒</b></div>
              <div class="kv">
                <span>原始样本保留</span>
                <b>{{ sys.raw_retention_hours }} 小时<span class="from">来自保留策略</span></b>
              </div>
              <div class="kv"><span>会话有效期</span><b>{{ sys.session_days }} 天</b></div>
            </div>
          </CyberPanel>

          <CyberPanel title="依赖状态" subtitle="数据库 / 调度器">
            <div v-if="sys" class="kvs">
              <div class="kv">
                <span>PostgreSQL</span>
                <b :style="`color:${sys.database.ok ? STATE.up : STATE.down}`">
                  {{ sys.database.ok ? sys.database.version : sys.database.error }}
                </b>
              </div>
              <div class="kv">
                <span>调度器(Redis)</span>
                <b :style="`color:${sys.scheduler.ok ? STATE.up : STATE.down}`">
                  {{ sys.scheduler.ok ? '正常' : sys.scheduler.error }}
                </b>
              </div>
              <template v-if="sys.scheduler.ok">
                <div v-for="(v, k) in sys.scheduler" :key="k" class="kv sub">
                  <template v-if="k !== 'ok'">
                    <span>{{ k }}</span><b class="cy-mono">{{ v }}</b>
                  </template>
                </div>
              </template>
            </div>
          </CyberPanel>

          <CyberPanel title="数据规模">
            <div v-if="sys?.counts" class="kvs">
              <div v-for="(label, key) in COUNT_LABELS" :key="key" class="kv">
                <span>{{ label }}</span><b class="cy-mono">{{ int(sys.counts[key]) }}</b>
              </div>
            </div>
          </CyberPanel>

          <CyberPanel title="表占用" subtitle="原始秒级样本通常是磁盘的主要消费者">
            <div v-if="sys?.tables?.length" class="kvs">
              <div v-for="t in sys.tables" :key="t.name" class="kv">
                <span class="cy-mono tname">{{ t.name }}</span>
                <b class="cy-mono">{{ t.pretty }}</b>
              </div>
            </div>
            <div v-else class="cy-empty">读不到表占用(需要对 pg_catalog 的读权限)。</div>
          </CyberPanel>
        </div>
      </NTabPane>
    </NTabs>

    <!-- ============ 恢复码(只出现这一次) ============ -->
    <NModal
      :show="recoveryCodes.length > 0" preset="card" :bordered="false"
      title="恢复码 —— 现在就抄下来" style="width: min(520px, 94vw)"
      @update:show="(v: boolean) => { if (!v) recoveryCodes = [] }"
    >
      <p class="warn">
        <b>这些码只显示这一次。</b>关掉这个框就再也拿不回来了(库里只有哈希)。
        手机丢了的时候,它们是唯一能自己进得来的路径 —— 抄在纸上或存进密码管理器,
        <b>不要和密码存在同一个地方</b>。每个码只能用一次。
      </p>
      <div class="codes cy-mono">
        <span v-for="c in recoveryCodes" :key="c">{{ c }}</span>
      </div>
      <template #footer>
        <NSpace justify="end">
          <NButton size="small" ghost @click="copyCodes">复制全部</NButton>
          <NButton size="small" type="primary" @click="recoveryCodes = []">我已经保存好了</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- ============ 二次确认密码 ============ -->
    <NModal
      :show="pwdPrompt !== null" preset="card" :bordered="false"
      :title="pwdPrompt === 'disable' ? '关闭两步验证' : '重新生成恢复码'"
      style="width: min(420px, 94vw)"
      @update:show="(v: boolean) => { if (!v) { pwdPrompt = null; confirmPwd = '' } }"
    >
      <p class="note">
        这个操作会降低账号的安全等级,所以要再输一次当前密码 ——
        会话还在不等于人还在。
      </p>
      <NInput
        v-model:value="confirmPwd" type="password" show-password-on="click"
        placeholder="当前密码" @keyup.enter="submitPrompt"
      />
      <template #footer>
        <NSpace justify="end">
          <NButton size="small" @click="pwdPrompt = null">取消</NButton>
          <NButton
            size="small" type="primary" :loading="promptBusy" :disabled="!confirmPwd"
            @click="submitPrompt"
          >
            确认
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- ============ 新建/编辑用户 ============ -->
    <NModal
      v-model:show="userModal" preset="card" :bordered="false"
      :title="isNewUser ? '新建用户' : `编辑 ${userForm.username}`"
      style="width: min(680px, 94vw)"
    >
      <SchemaForm :model="userForm" :fields="USER_FIELDS" :errors="userErrors" />
      <template #footer>
        <NSpace justify="end">
          <NButton size="small" @click="userModal = false">取消</NButton>
          <NButton size="small" type="primary" :loading="savingUser" @click="saveUser">
            {{ isNewUser ? '创建' : '保存' }}
          </NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- ============ 重置别人的密码 ============ -->
    <NModal
      :show="resetTarget !== null" preset="card" :bordered="false"
      :title="`重置 ${resetTarget?.username} 的密码`" style="width: min(420px, 94vw)"
      @update:show="(v: boolean) => { if (!v) resetTarget = null }"
    >
      <p class="note">
        新密码要当面/私下告诉本人,并让他登录后自己改掉。
        <b>两步验证不受影响</b> —— 要一起解除,用列表里的「解绑2FA」。
      </p>
      <NInput
        v-model:value="resetPassword" type="password" show-password-on="click"
        placeholder="新密码,至少 10 位" @keyup.enter="doReset"
      />
      <template #footer>
        <NSpace justify="end">
          <NButton size="small" @click="resetTarget = null">取消</NButton>
          <NButton
            size="small" type="primary" :loading="resetting" :disabled="!resetPassword"
            @click="doReset"
          >
            重置
          </NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.mg :deep(.n-tabs-nav) { margin-bottom: 12px; }

.sec-grid,
.sys-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 14px;
  align-items: start;
}

.stack { display: flex; flex-direction: column; }
.lab {
  font-size: 11px;
  letter-spacing: 0.07em;
  color: var(--cy-ink-2);
  margin: 12px 0 5px;
}
.lab:first-child { margin-top: 0; }
.mt { margin-top: 16px; align-self: flex-start; }

.fe { font-size: 10.5px; line-height: 1.55; color: var(--cy-down); margin: 5px 0 0; }
.fe.hint { color: var(--cy-ink-3); }
.fe b { color: var(--cy-ink-2); }

.note {
  font-size: 11.5px;
  line-height: 1.7;
  color: var(--cy-ink-2);
  margin: 0 0 14px;
}
.note b { color: var(--cy-cyan); font-weight: 600; }

.on-badge {
  display: flex;
  align-items: center;
  gap: 9px;
  font-size: 11.5px;
  color: var(--cy-ink-2);
  padding: 9px 12px;
  margin-bottom: 12px;
  background: rgba(var(--cy-up-rgb), 0.06);
  border-left: 2px solid var(--cy-up);
}

.kvs { display: flex; flex-direction: column; }
.kv {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 12px;
  padding: 6px 0;
  font-size: 11.5px;
  border-bottom: 1px solid rgba(var(--cy-ink-rgb), 0.045);
}
.kv:last-child { border-bottom: none; }
.kv > span { color: var(--cy-ink-3); flex: none; }
.kv > b { color: var(--cy-ink); font-weight: 600; text-align: right; word-break: break-all; }
.kv > b.low { color: var(--cy-degraded); }
.kv.sub > span { padding-left: 12px; font-size: 10.5px; }
.tname { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; }

.disk-panel { margin-bottom: 14px; }
.disk {
  display: grid;
  grid-template-columns: minmax(260px, 1.3fr) minmax(240px, 1fr);
  gap: 18px 26px;
  align-items: start;
}
.disk-nums {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 18px;
  margin-top: 9px;
  font-size: 11.5px;
  color: var(--cy-ink-3);
}
.disk-nums .free { color: var(--cy-up); }
.disk-growth { min-width: 0; }
.note.tiny { font-size: 10.5px; line-height: 1.65; margin: 10px 0 0; color: var(--cy-ink-3); }
.note.tiny b { color: var(--cy-ink-2); }
.warnline {
  padding: 8px 11px;
  background: rgba(var(--cy-degraded-rgb), 0.06);
  border-left: 2px solid rgba(var(--cy-degraded-rgb), 0.55);
}
.warnline b { color: var(--cy-degraded); }

.ret-error {
  font-size: 11.5px;
  line-height: 1.7;
  color: var(--cy-ink-2);
  padding: 10px 12px;
  background: rgba(var(--cy-down-rgb), 0.07);
  border-left: 2px solid var(--cy-down);
}
.ret-error b { color: var(--cy-down); }
.ret-error-hint { margin-top: 6px; color: var(--cy-ink-3); font-size: 10.5px; }
.ret-error-hint b { color: var(--cy-ink-2); }
.ret-error-hint code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  padding: 0 3px;
  background: rgba(var(--cy-ink-rgb), 0.07);
}
.ret-retry { margin-top: 8px; }

.ret-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 4px 16px;
}
.ret-item { min-width: 0; }
.ret-item .lab { display: block; margin: 10px 0 4px; }
.ret-item .fe { margin-top: 3px; }
.from {
  font-size: 9.5px;
  color: var(--cy-ink-3);
  font-weight: 400;
  margin-left: 6px;
  letter-spacing: 0.04em;
}

@media (max-width: 760px) {
  .disk { grid-template-columns: 1fr; }
}

.qr-row { display: flex; gap: 14px; align-items: flex-start; margin-bottom: 6px; }
/* 二维码底色必须是白的 —— 深色底上的码有些老验证器扫不出来 */
.qr {
  flex: none;
  width: 148px;
  height: 148px;
  padding: 7px;
  background: #fff;   /* 与主题无关:二维码底必须白 */
  border: 1px solid rgba(var(--cy-cyan-rgb), 0.3);
}
.qr :deep(svg) { width: 100%; height: 100%; display: block; }
.qr-side { flex: 1; min-width: 0; }
.secret {
  display: block;
  font-size: 11px;
  line-height: 1.6;
  color: var(--cy-cyan);
  word-break: break-all;
  padding: 7px 9px;
  background: rgba(var(--cy-cyan-rgb), 0.06);
  border: 1px solid rgba(var(--cy-cyan-rgb), 0.2);
}

.warn {
  font-size: 11.5px;
  line-height: 1.75;
  color: var(--cy-ink-2);
  margin: 0 0 14px;
  padding: 10px 12px;
  background: rgba(var(--cy-degraded-rgb), 0.07);
  border-left: 2px solid var(--cy-degraded);
}
.warn b { color: var(--cy-degraded); font-weight: 600; }

.codes {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 6px 14px;
  user-select: all;
}
.codes span {
  font-size: 13px;
  letter-spacing: 0.06em;
  color: var(--cy-ink);
  padding: 6px 9px;
  background: rgba(var(--cy-ink-rgb), 0.035);
  text-align: center;
}
</style>
