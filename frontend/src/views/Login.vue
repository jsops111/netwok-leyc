<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { NButton, NInput } from 'naive-ui'
import { useAuthStore } from '@/stores/auth'
import { errText } from '@/api'

/**
 * 登录页。
 *
 * **两步是分开的两屏,不是一屏上放三个输入框。**绑了两步验证的人才需要
 * 验证码,而大部分账号没绑 —— 一上来就摆一个用不到的框,每次登录都要
 * 多想一次"这个要不要填"。所以先提交用户名密码,后端说 otp_required
 * 才切到第二屏。
 *
 * 第二屏一个框收两种东西(6 位验证码 / 恢复码):两个框会让人选错,
 * 而"这两个我该填哪个"是没有必要让用户回答的问题 —— 后端两种都试。
 */

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()

const step = ref<'password' | 'otp'>('password')
const username = ref('')
const password = ref('')
const otp = ref('')
const error = ref('')
const busy = ref(false)

const otpRef = ref<InstanceType<typeof NInput> | null>(null)
const userRef = ref<InstanceType<typeof NInput> | null>(null)

onMounted(() => {
  void nextTick(() => userRef.value?.focus())
})

const canSubmit = computed(() =>
  step.value === 'password'
    ? username.value.trim().length > 0 && password.value.length > 0
    : otp.value.trim().length >= 6,
)

async function submit() {
  if (!canSubmit.value || busy.value) return
  busy.value = true
  error.value = ''
  try {
    const result = await auth.login(
      username.value.trim(), password.value, step.value === 'otp' ? otp.value.trim() : undefined,
    )
    if (result === 'otp_required') {
      step.value = 'otp'
      await nextTick()
      otpRef.value?.focus()
      return
    }
    // 登录前想去的地方 —— 守卫把它塞在 query.next 里
    const next = typeof route.query.next === 'string' ? route.query.next : '/'
    await router.replace(next.startsWith('/') ? next : '/')
  } catch (e) {
    error.value = errText(e)
    if (step.value === 'otp') {
      otp.value = ''
      await nextTick()
      otpRef.value?.focus()
    }
  } finally {
    busy.value = false
  }
}

function back() {
  step.value = 'password'
  otp.value = ''
  error.value = ''
}
</script>

<template>
  <div class="login-wrap">
    <div class="login-card cy-panel">
      <div class="cy-sweep" />

      <div class="head">
        <span class="logo-mark" />
        <div>
          <div class="logo-text cy-display cy-glitch" data-text="NET-CHECK">NET-CHECK</div>
          <div class="sub">网络线路检测与展示平台</div>
        </div>
      </div>

      <!-- ============ 第一步:用户名密码 ============ -->
      <form v-if="step === 'password'" class="form" @submit.prevent="submit">
        <label class="lab">用户名</label>
        <NInput
          ref="userRef" v-model:value="username" placeholder="用户名"
          :input-props="{ autocomplete: 'username' }" @keyup.enter="submit"
        />
        <label class="lab">密码</label>
        <NInput
          v-model:value="password" type="password" show-password-on="click" placeholder="密码"
          :input-props="{ autocomplete: 'current-password' }" @keyup.enter="submit"
        />
        <p v-if="error" class="err">{{ error }}</p>
        <NButton
          type="primary" block :loading="busy" :disabled="!canSubmit"
          attr-type="submit" class="go"
        >
          登 录
        </NButton>
      </form>

      <!-- ============ 第二步:两步验证 ============ -->
      <form v-else class="form" @submit.prevent="submit">
        <div class="who">{{ username }} · 已开启两步验证</div>
        <label class="lab">验证码</label>
        <NInput
          ref="otpRef" v-model:value="otp" placeholder="验证器上的 6 位数字"
          class="otp cy-mono" :input-props="{ autocomplete: 'one-time-code', inputmode: 'text' }"
          @keyup.enter="submit"
        />
        <p class="hint">
          手机不在手边时,可以在这里输入一个<b>恢复码</b>(绑定时保存的那十个)。
          恢复码用一个少一个。
        </p>
        <p v-if="error" class="err">{{ error }}</p>
        <NButton
          type="primary" block :loading="busy" :disabled="!canSubmit"
          attr-type="submit" class="go"
        >
          验 证
        </NButton>
        <NButton text size="small" class="back" @click="back">← 换个账号</NButton>
      </form>

      <div class="foot cy-mono">内网监控平台 · 仅限授权访问</div>
    </div>
  </div>
</template>

<style scoped>
.login-wrap {
  position: relative;
  z-index: 2;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
}

.login-card {
  width: min(390px, 100%);
  padding: 30px 30px 22px;
}

.head { display: flex; align-items: center; gap: 12px; margin-bottom: 26px; }
.logo-mark {
  width: 26px;
  height: 26px;
  flex: none;
  background: linear-gradient(135deg, #22e0e8, #ff3d8b);
  clip-path: polygon(50% 0, 100% 28%, 100% 72%, 50% 100%, 0 72%, 0 28%);
  box-shadow: 0 0 18px rgba(34, 224, 232, 0.55);
}
.logo-text {
  position: relative;
  font-size: 21px;
  letter-spacing: 0.15em;
  color: #e8f4f8;
  text-shadow: 0 0 18px rgba(34, 224, 232, 0.42);
}
.sub { font-size: 10.5px; letter-spacing: 0.09em; color: #7a8fa0; margin-top: 2px; }

.form { display: flex; flex-direction: column; }
.lab {
  font-size: 11px;
  letter-spacing: 0.08em;
  color: #a8bcc8;
  margin: 0 0 5px;
}
.lab + :deep(.n-input) { margin-bottom: 15px; }

.who {
  font-size: 11.5px;
  color: #22e0e8;
  margin-bottom: 16px;
  padding: 7px 10px;
  background: rgba(34, 224, 232, 0.06);
  border-left: 2px solid rgba(34, 224, 232, 0.5);
}

/* 验证码是要一眼看清的一串数字 —— 等宽 + 拉开字距 */
.otp :deep(input) { letter-spacing: 0.32em; font-size: 15px; }

.hint {
  font-size: 10.5px;
  line-height: 1.65;
  color: #7a8fa0;
  margin: -8px 0 14px;
}
.hint b { color: #a8bcc8; font-weight: 600; }

/* 错误信息不做闪烁动画:它是要被读的文字,不是状态灯(见 cyber.css 的自律 2) */
.err {
  font-size: 11.5px;
  line-height: 1.5;
  color: #ff5470;
  margin: 0 0 12px;
  padding: 7px 10px;
  background: rgba(255, 84, 112, 0.08);
  border-left: 2px solid #ff5470;
  white-space: pre-line;
}

.go { letter-spacing: 0.2em; }
.back { margin-top: 12px; align-self: center; color: #7a8fa0; }

.foot {
  margin-top: 22px;
  padding-top: 13px;
  border-top: 1px solid rgba(34, 224, 232, 0.12);
  font-size: 10px;
  letter-spacing: 0.1em;
  color: #556677;
  text-align: center;
}
</style>
