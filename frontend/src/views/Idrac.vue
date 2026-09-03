<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { NButton, NModal, NSwitch, NTag, NTooltip, useMessage } from 'naive-ui'
import HudCurve from '@/components/HudCurve.vue'
import { api, errText } from '@/api'
import type { IdracBoardHost, IdracDetail } from '@/api'
import { usePolling } from '@/composables/usePolling'
import { cyber } from '@/theme'

/**
 * 带外硬件大屏(iDRAC)—— 视觉语言整套搬自 ops-ai-cmdb 的监控大屏。
 *
 * 分工:`/servers` 走 SSH,答「系统忙不忙、盘满没满」;这一屏走带外,
 * 答**「机器本身会不会坏」**(盘 / RAID / 内存 / 电源 / 风扇 / 温度)。
 * 两边覆盖不重合 —— 一块正在 SMART 预警的硬盘、一个已经掉了电的冗余电源,
 * 在操作系统里一点症状都没有。
 *
 * ## 界面上不解释设计,只给判据
 *
 * 大屏是**盯着看**的,一屏字越多越糟。所有"为什么这么做"写在注释里,
 * 屏上只留:是什么、多少、哪台、要不要动手。
 *
 * ## ⚠ 判据是平台自己算的,不照抄 iDRAC 的状态位
 *
 * iDRAC 的温度严重线通常是 100 ℃(CPU 的绝对上限),所以一颗散热坏了、
 * 比同机另一颗高 20 ℃ 的 CPU 在它眼里是"正常"的。温差、SMART 预警、
 * SSD 寿命这些判据在后端 `idrac/collector.py` 一处算,这里只画。
 *
 * ## 颜色规矩
 *
 * 大红 `--cy-alarm` **只给确定的异常**,紫=偏高,青=正常,绿=闲,灰=没读到。
 * 装饰、身份、排名一律不许用红 —— **一直都在的红等于没有红**。
 */

const message = useMessage()

/** 带外变化很慢,60 秒一拍。这一页只读平台自己的库,不碰 BMC */
const board = usePolling(() => api.idracBoard().then((r) => r.data), 60_000)
const data = computed(() => board.data.value)
const summary = computed(() => data.value?.totals ?? null)
const hosts = computed(() => data.value?.hosts ?? [])
const alerts = computed(() => data.value?.alerts ?? [])
const dist = computed(() => data.value?.distributions ?? null)

const vars = computed(() => ({
  '--i-bg': cyber.SURFACE.body,
  '--i-panel': cyber.SURFACE.card,
  '--i-raised': cyber.SURFACE.raised,
  '--i-cyan': cyber.NEON.cyan,
  '--i-violet': cyber.NEON.violet,
  '--i-ok': cyber.STATUS.success,
  '--i-crit': cyber.HUD.alarm,
  '--i-hi': cyber.HUD.hilite,
  '--i-ink': cyber.INK.base,
  '--i-ink2': cyber.INK.secondary,
  '--i-ink3': cyber.INK.muted,
}))

/** 进场动画:条形从 0 长出来 */
const armed = ref(false)
onMounted(() => window.setTimeout(() => (armed.value = true), 60))

const ICON: Record<string, string> = {
  temp: 'M14 14V5a2 2 0 1 0-4 0v9a4 4 0 1 0 4 0zM12 9v6',
  disk: 'M4 6c0-1.1 3.6-2 8-2s8 .9 8 2v12c0 1.1-3.6 2-8 2s-8-.9-8-2zM4 6c0 1.1 3.6 2 8 2s8-.9 8-2M4 12c0 1.1 3.6 2 8 2s8-.9 8-2',
  mem: 'M3 8h18v8H3zM7 8v8M11 8v8M15 8v8M5 16v3M19 16v3',
  psu: 'M13 2 4 14h7l-1 8 9-12h-7z',
  fan: 'M12 12a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM12 12c0 3 2 4 5 4M12 12c-2 2-2 5 0 7M12 12c-2-1-5 0-6 3',
  raid: 'M4 5h16v5H4zM4 14h16v5H4zM7 7.5h.01M7 16.5h.01',
  alarm: 'M12 4l9 16H3zM12 10v5M12 17h.01',
}

/**
 * 每台一格的等级 —— 顶上那条灯带和底下的矩阵共用。
 *
 * **`pending`(还没轮到采)按 unknown 画,不按故障画** ——
 * 算成红的话新加的机器会先红一阵子,人会去查一个不存在的问题。
 */
function levelOf(h: IdracBoardHost): string {
  if (h.level === 'pending' || h.health === null) return 'unknown'
  return h.level === 'down' ? 'crit' : h.level
}

function bandOf(v: number | null, warn: number, crit: number): string {
  if (v === null) return 'var(--i-ink3)'
  if (v >= crit) return 'var(--i-crit)'
  if (v >= warn) return 'var(--i-violet)'
  return 'var(--i-ok)'
}

/** 盘 / RAID / 内存 / 电源 四类里有问题的件数合计 */
const partsBad = computed(() => {
  const s = summary.value
  if (!s) return 0
  return s.disk_bad + s.disk_smart + s.vdisk_bad + s.memory_bad + s.psu_bad
})

/* ---------------------------------------------------------------- 四张大卡
 * 四张都要有**真实分布**可画 —— 纯计数画不出曲线,而没有曲线的卡在这套
 * 视觉里就是一块空白。挑的是:最高温、两颗 CPU 的温差、SSD 剩余寿命、
 * 部件故障合计。前两个正是平台自己那两条判据的原料。 */
const metrics = computed(() => {
  const s = summary.value
  const d = dist.value
  if (!s || !d) return []
  const hottest = d.temps[0] ?? null
  const maxDelta = d.deltas[0] ?? null
  const worstLife = d.lives[0] ?? null
  return [
    {
      key: 'temp', icon: 'temp', title: '最高温',
      big: hottest === null ? '—' : hottest.toFixed(0), unit: '℃',
      bar: hottest === null ? 0 : Math.min(100, hottest),
      accent: bandOf(hottest, 65, 80),
      lines: [s.temp_max_host || '—', `均温 ${s.temp_avg?.toFixed(1) ?? '—'} ℃`],
      curve: d.temps, curveNote: `${d.temps.length} 台按最高温降序`,
      breakdown: null,
    },
    {
      // **这一条厂商不会报**:两颗都没超阈值,但差 20 ℃ 就是散热坏了
      key: 'delta', icon: 'fan', title: '两颗 CPU 温差',
      big: maxDelta === null ? '—' : String(maxDelta), unit: '℃',
      bar: maxDelta === null ? 0 : Math.min(100, (maxDelta / 30) * 100),
      accent: bandOf(maxDelta, 15, 25),
      lines: ['同机同负载不该差这么多', '差得多 = 散热器 / 风扇 / 硅脂'],
      curve: d.deltas, curveNote: `${d.deltas.length} 台按温差降序`,
      breakdown: null,
    },
    {
      key: 'life', icon: 'disk', title: 'SSD 最低寿命',
      big: worstLife === null ? '—' : worstLife.toFixed(0), unit: '%',
      bar: worstLife === null ? 0 : worstLife,
      // 寿命是**越低越糟**,和别的指标反着来
      accent: worstLife === null ? 'var(--i-ink3)'
        : worstLife <= 5 ? 'var(--i-crit)'
          : worstLife <= 20 ? 'var(--i-violet)' : 'var(--i-ok)',
      lines: [`${d.lives.length} 块 SSD`, `${s.disk_total} 块盘 · 机械盘不适用`],
      curve: d.lives, curveNote: `${d.lives.length} 块按剩余寿命升序`,
      breakdown: null,
    },
    {
      // 这四张必须每张都能回答「有没有事」,不然一眼扫过去看到的全是正常数字
      key: 'parts', icon: 'raid', title: '部件故障',
      big: String(partsBad.value), unit: '件',
      bar: partsBad.value ? 100 : 0,
      accent: partsBad.value ? 'var(--i-crit)' : 'var(--i-ok)',
      lines: [
        partsBad.value ? '盘 / RAID / 内存 / 电源' : '盘 / RAID / 内存 / 电源 全部正常',
        `共 ${s.disk_total + s.vdisk_total + s.memory_total + s.psu_total} 个部件`,
      ],
      // 这一格没有"分布"可画(它是四类计数的合计),**就不画** ——
      // 硬凑一条别的曲线上去,标题和图说的不是一件事
      curve: [], curveNote: '',
      breakdown: [
        { k: '盘', bad: s.disk_bad + s.disk_smart, total: s.disk_total },
        { k: 'RAID', bad: s.vdisk_bad, total: s.vdisk_total },
        { k: '内存', bad: s.memory_bad, total: s.memory_total },
        { k: '电源', bad: s.psu_bad, total: s.psu_total },
      ],
    },
  ]
})

/** 部件清点。**分母一起给** —— 「坏 0」和「一块都没有」是两件事 */
const health = computed(() => {
  const s = summary.value
  if (!s) return []
  const mk = (title: string, bad: number, total: number, icon: string) => ({
    title, icon, bad, total,
  })
  return [
    mk('物理盘', s.disk_bad + s.disk_smart, s.disk_total, 'disk'),
    mk('RAID 卷', s.vdisk_bad, s.vdisk_total, 'raid'),
    mk('内存条', s.memory_bad, s.memory_total, 'mem'),
    mk('电源模块', s.psu_bad, s.psu_total, 'psu'),
    mk('SSD 损耗', s.ssd_worn, s.disk_total, 'disk'),
    // **「读不到」不等于「没问题」** —— 它单独占一格,而且用告警图标
    mk('读不到', s.unknown + s.down + s.pending, s.hosts, 'alarm'),
  ]
})

/** 报错按机器归拢 —— 同一台上的几条要挨着 */
const walls = computed(() => {
  const by = new Map<string, typeof alerts.value>()
  for (const a of alerts.value) {
    const key = a.host || '?'
    if (!by.has(key)) by.set(key, [])
    by.get(key)!.push(a)
  }
  return [...by.entries()]
    .map(([host, rows]) => ({
      host, rows,
      level: rows.some((r) => r.severity === 'critical') ? 'crit' : 'warn',
    }))
    .sort((a, b) =>
      a.level === b.level ? a.host.localeCompare(b.host) : a.level === 'crit' ? -1 : 1)
})

/** 机器矩阵:按最高温铺色,有报错的加描边(两重编码,不互相顶替) */
const matrix = computed(() =>
  [...hosts.value]
    .sort((a, b) => (b.metrics.max_temp_c ?? -1) - (a.metrics.max_temp_c ?? -1))
    .map((h) => ({
      id: h.id,
      host: h.name,
      ip: h.host,
      celsius: h.metrics.max_temp_c,
      level: levelOf(h),
      model: h.model,
      alerts: h.alerts.length,
      color: bandOf(h.metrics.max_temp_c, 65, 80),
      raw: h,
    })),
)

const verdict = computed(() => data.value?.verdict ?? 'unknown')

/** 有问题那几台**点名** —— 「1 台要看一眼」还得再找一遍,这一行就是省掉那次找 */
function named(level: string): string {
  const hs = hosts.value.filter((h) => h.level === level).map((h) => h.name)
  return hs.length && hs.length <= 3 ? hs.join(' · ') : `${hs.length} 台`
}

/**
 * 一句话结论。**屏上最先被读到的一行**,所以它说的是「要不要动手」,
 * 不是「有多少台」—— 后者在底下的灯带和矩阵里。
 */
const headline = computed(() => {
  const s = summary.value
  if (!s) return ''
  if (s.down) return `${named('down')} 带外连不上`
  if (s.alert_crit) return `${named('crit')} 要立刻处理`
  if (s.alert_warn) return `${named('warn')} 要看一眼`
  if (s.unknown) return `${s.ok} 台正常,${s.unknown} 台没读到`
  if (s.pending) return `${s.ok} 台正常,${s.pending} 台还没轮到采`
  return `${s.hosts} 台硬件正常`
})
const headlineSub = computed(() => {
  const s = summary.value
  if (!s) return ''
  const bits: string[] = []
  if (partsBad.value) bits.push(`${partsBad.value} 个部件有问题`)
  if (s.psu_redundancy_lost) bits.push(`${s.psu_redundancy_lost} 台电源冗余丢失`)
  if (s.ssd_worn) bits.push(`${s.ssd_worn} 块 SSD 寿命告急`)
  if (s.sel_recent_critical) bits.push(`硬件日志 ${s.sel_recent_critical} 条严重`)
  // **「读不到」不等于「没问题」** —— 这句话要带出来
  if (s.unknown) bits.push(`${s.unknown} 台读不到(不等于没问题)`)
  if (s.down) bits.push(`${s.down} 台带外连不上(查网络/凭据)`)
  if (!bits.length) {
    bits.push(`盘 ${s.disk_total} · 内存 ${s.memory_total} · 电源 ${s.psu_total} 全部正常`)
  }
  return bits.join(' · ')
})
const VERDICT_TEXT: Record<string, string> = {
  ok: '正常', warn: '注意', crit: '严重', unknown: '未知',
}

// ---------------------------------------------------------------- 明细
const detailOpen = ref(false)
const detail = ref<IdracDetail | null>(null)
const detailLoading = ref(false)
const testing = ref(0)

async function openDetail(id: number) {
  detailOpen.value = true
  detail.value = null
  detailLoading.value = true
  try {
    const { data: d } = await api.idracDetail(id)
    detail.value = d
  } catch (e) {
    message.error(errText(e))
    detailOpen.value = false
  } finally {
    detailLoading.value = false
  }
}

async function testHost(id: number, name: string) {
  testing.value = id
  try {
    const { data: r } = await api.testIdrac(id)
    if (r.ok) message.success(r.detail, { duration: 12000 })
    else message.error(r.detail, { duration: 12000 })
  } catch (e) {
    message.error(errText(e))
  } finally {
    testing.value = 0
  }
}

async function collectNow(id: number) {
  try {
    const { data: r } = await api.collectIdracNow(id)
    message.success(r.detail)
  } catch (e) {
    message.error(errText(e))
  }
}

const HEALTH_TEXT: Record<string, string> = {
  ok: '正常', warning: '警告', critical: '严重', unknown: '读不到',
}
function tempColor(v: number | null): string {
  return bandOf(v, 65, 80)
}
function num(v: number | null | undefined, digits = 0, unit = ''): string {
  return v === null || v === undefined ? '—' : `${v.toFixed(digits)}${unit}`
}
</script>

<template>
  <div v-if="summary" class="ib" :style="vars">
    <div class="ib-scan" aria-hidden="true"></div>

    <!-- ============================ 横幅 -->
    <header class="ib-banner">
      <div class="ib-bn-l">
        <div class="ib-bn-name">带外硬件</div>
        <div class="ib-bn-sub">iDRAC · Redfish</div>
      </div>
      <div class="ib-bn-c">
        <i class="ib-diag ib-diag-l" aria-hidden="true"></i>
        <h2>iDRAC 硬件健康总览</h2>
        <i class="ib-diag ib-diag-r" aria-hidden="true"></i>
      </div>
      <div class="ib-bn-r">
        <span class="ib-chip ib-chip-live">{{ summary.hosts }} 台</span>
        <span class="ib-chip ib-chip-time">
          {{ data ? data.generated_at.slice(0, 19).replace('T', ' ') : '采集时刻未知' }}
        </span>
        <span :class="['ib-chip', 'ib-chip-lv', `lv-${verdict}`]">
          {{ verdict === 'unknown' ? '⚠ ' : '' }}{{ VERDICT_TEXT[verdict] }}
        </span>
      </div>
    </header>

    <!-- 一句话结论。**这是"一眼"的落点** —— 底下的格子和卡回答的是细节,
         而人先要知道"要不要现在动手" -->
    <div class="ib-verdict" :class="verdict">
      <b>{{ headline }}</b>
      <span>{{ headlineSub }}</span>
    </div>

    <!-- 全场一行:每台一个刻度 -->
    <div class="ib-signal">
      <NTooltip v-for="h in hosts" :key="`sig-${h.id}`" placement="bottom">
        <template #trigger><i :class="['ib-tick', `lv-${levelOf(h)}`]"></i></template>
        <span class="ib-mono">
          {{ h.name }} · {{ h.metrics.max_temp_c === null ? '温度没读到' : `${h.metrics.max_temp_c} ℃` }}
          {{ h.alerts.length ? ` · ${h.alerts.length} 条报错` : '' }}
        </span>
      </NTooltip>
    </div>

    <!-- ============================ 报错(只在有的时候出现) -->
    <section v-if="walls.length" class="ib-card ib-alarmbox" :class="{ hot: summary.alert_crit > 0 }">
      <div class="ib-ct ib-ct-row">
        <svg viewBox="0 0 24 24" class="ib-ico"><path :d="ICON.alarm" /></svg>
        <span>硬件报错 {{ walls.length }} 台 · {{ alerts.length }} 条</span>
      </div>
      <ul class="ib-alarms">
        <li v-for="w in walls" :key="w.host" :class="w.level">
          <b class="ib-ahost">{{ w.host }}</b>
          <span v-for="(a, i) in w.rows" :key="i" class="ib-a">
            <i class="ib-adot"></i>{{ a.kind_label }}<em>{{ a.message }}</em>
          </span>
        </li>
      </ul>
    </section>

    <!-- ============================ 四张大卡 -->
    <section class="ib-metrics">
      <article v-for="m in metrics" :key="m.key" class="ib-card ib-mcard" :style="{ '--acc': m.accent }">
        <div class="ib-ct">
          <svg viewBox="0 0 24 24" class="ib-ico"><path :d="ICON[m.icon]" /></svg>
          <span>{{ m.title }}</span>
        </div>
        <div class="ib-mbig"><b>{{ m.big }}</b><small>{{ m.unit }}</small></div>
        <div class="ib-mbar"><i :style="{ width: armed ? `${Math.max(0, Math.min(100, m.bar))}%` : '0%' }" /></div>
        <div v-for="(l, i) in m.lines" :key="i" :class="['ib-mline', i ? 'ib-mline-2' : '']">{{ l }}</div>
        <HudCurve v-if="m.curve.length" :values="m.curve" :color="m.accent" :height="46" class="ib-mcurve" />
        <!-- 没有分布可画的那一格给四类占比,不硬凑曲线 -->
        <div v-else-if="m.breakdown" class="ib-bd">
          <div v-for="b in m.breakdown" :key="b.k" class="ib-bd-row">
            <span>{{ b.k }}</span>
            <i><em :style="{ width: b.total ? `${(1 - b.bad / b.total) * 100}%` : '0%' }" /></i>
            <b :class="{ bad: b.bad }">{{ b.bad }}</b>
          </div>
        </div>
        <div class="ib-mnote">{{ m.curveNote }}</div>
      </article>
    </section>

    <!-- 部件清点:**一行紧凑条,不是六张大卡**。全是 0 的时候(常态)
         它不该占一大片版面 —— 版面要留给有问题的那些 -->
    <section class="ib-parts">
      <span v-for="h in health" :key="h.title" class="ib-part" :class="{ bad: h.bad }">
        <svg viewBox="0 0 24 24" class="ib-pico"><path :d="ICON[h.icon]" /></svg>
        <span class="ib-pk">{{ h.title }}</span>
        <b>{{ h.bad }}</b><i>/ {{ h.total }}</i>
      </span>
    </section>

    <!-- ============================ 机器矩阵 -->
    <section class="ib-card ib-matrix">
      <div class="ib-ct ib-ct-row">
        <span>机器矩阵</span>
        <em>{{ matrix.length }} 台 · 按最高温降序 · 有报错的加框 · 点开看明细</em>
        <span class="ib-legend">
          <i style="background: var(--i-ok)" />&lt; 65
          <i style="background: var(--i-violet)" />65–80
          <i style="background: var(--i-crit)" />≥ 80 ℃
          <i style="background: var(--i-ink3)" />未采到
        </span>
      </div>
      <div class="ib-cells">
        <NTooltip v-for="c in matrix" :key="c.id" trigger="hover">
          <template #trigger>
            <div class="ib-cell" :class="c.level" :style="{ '--c': c.color }" @click="openDetail(c.id)">
              <span class="ib-c-ip">{{ c.host }}</span>
              <span class="ib-c-t">{{ c.celsius === null ? '—' : `${c.celsius.toFixed(0)}°` }}</span>
              <span class="ib-c-bar" />
            </div>
          </template>
          {{ c.host }} · {{ c.ip }} · {{ c.model || '型号未采到' }} ·
          {{ c.celsius === null ? '温度没读到' : `${c.celsius} ℃` }}
          {{ c.alerts ? ` · ${c.alerts} 条报错` : '' }}
        </NTooltip>
      </div>
    </section>

    <!-- 页脚:压到最底下,它不是要盯的东西 -->
    <div class="ib-foot">
      <label class="ib-tgl">
        <NSwitch :value="!board.paused.value" size="small" @update:value="board.toggle" />
        <span>{{ board.paused.value ? '已暂停刷新' : '每 60s 自动刷新' }}</span>
      </label>
      <span v-if="board.isStale()" class="ib-note">刷新落后了</span>
      <span v-if="board.error.value" class="ib-err">
        {{ board.error.value }} —— 显示的是上一次拿到的数据
      </span>
      <button class="ib-btn" :disabled="board.loading.value" @click="board.refresh">
        {{ board.loading.value ? '刷新中…' : '立即刷新' }}
      </button>
    </div>

    <!-- ============================ 明细 -->
    <NModal
      v-model:show="detailOpen" preset="card" :bordered="false"
      :title="detail?.host.name || '带外明细'"
      style="width: min(1080px, 96vw)"
    >
      <div v-if="detailLoading" class="d-dim">读取明细…</div>
      <template v-else-if="detail">
        <div v-for="(n, i) in detail.notes" :key="`n${i}`" class="d-note">{{ n }}</div>
        <!-- **为什么某一栏是空的** —— 没有这几条,"硬盘 0 块"看着像
             这台机器没有硬盘 -->
        <div v-for="(msg, seg) in detail.endpoint_errors" :key="`e${seg}`" class="d-note warn">
          <b>{{ seg }}</b> 这一段没取到:{{ msg }} —— 下面对应的部件是空的,
          <b>不代表这台机器没有</b>
        </div>

        <div class="d-actions">
          <NButton size="tiny" ghost :loading="testing === detail.host.id"
                   @click="testHost(detail.host.id, detail.host.name)">测试连通性</NButton>
          <NButton size="tiny" ghost @click="collectNow(detail.host.id)">立即采集</NButton>
        </div>

        <div class="d-grid">
          <div class="d-block">
            <div class="d-bh">物理盘 <span class="d-dim">{{ detail.disks.length }} 块</span></div>
            <div v-if="!detail.disks.length" class="d-dim d-sm">没有读到物理盘</div>
            <div v-for="(d, i) in detail.disks" :key="`d${i}`" class="d-line">
              <span class="d-n" :title="d.model">{{ d.slot || d.name }}</span>
              <NTag size="tiny" :bordered="false">{{ d.media }}</NTag>
              <span class="d-dim">{{ d.capacity_gb ? `${d.capacity_gb} GB` : '—' }}</span>
              <!-- **机械盘不显示剩余寿命** —— 它没有这个概念,后端给 null。
                   显示成 0% 会让人以为一排盘都写光了 -->
              <span v-if="d.life_pct !== null"
                    :style="{ color: d.life_pct <= 10 ? 'var(--i-crit)'
                      : d.life_pct <= 25 ? 'var(--i-violet)' : 'var(--i-ink2)' }">
                寿命 {{ d.life_pct }}%
              </span>
              <span v-else-if="d.is_ssd" class="d-dim d-sm">寿命未知</span>
              <span v-else class="d-dim d-sm">机械盘无寿命指标</span>
              <NTag v-if="d.smart_alert" size="tiny" :bordered="false"
                    style="color: var(--i-violet); border: 1px solid var(--i-violet)">SMART 预警</NTag>
              <span :style="{ color: d.health === 'ok' ? 'var(--i-ok)'
                : d.health === 'unknown' ? 'var(--i-ink3)' : 'var(--i-crit)' }">
                {{ HEALTH_TEXT[d.health] }}
              </span>
            </div>
          </div>

          <div class="d-block">
            <div class="d-bh">RAID 卷</div>
            <div v-if="!detail.volumes.length" class="d-dim d-sm">没有读到 RAID 卷</div>
            <div v-for="(v, i) in detail.volumes" :key="`v${i}`" class="d-line">
              <span class="d-n">{{ v.name }}</span>
              <NTag size="tiny" :bordered="false">{{ v.raid_type || '—' }}</NTag>
              <span class="d-dim">{{ v.capacity_gb ? `${v.capacity_gb} GB` : '—' }}</span>
              <!-- 冗余度 0 = 再坏一块盘这个卷就没了。卷本身还是"正常" -->
              <span v-if="v.remaining_redundancy === 0" style="color: var(--i-violet)">
                已无冗余(再坏一块就丢数据)
              </span>
              <span :style="{ color: v.health === 'ok' ? 'var(--i-ok)'
                : v.health === 'unknown' ? 'var(--i-ink3)' : 'var(--i-crit)' }">
                {{ HEALTH_TEXT[v.health] }}
              </span>
            </div>
          </div>

          <div class="d-block">
            <div class="d-bh">电源</div>
            <div v-if="!detail.psus.length" class="d-dim d-sm">没有读到电源</div>
            <div v-for="(p, i) in detail.psus" :key="`p${i}`" class="d-line">
              <span class="d-n">{{ p.name }}</span>
              <span class="d-dim">{{ p.capacity_w ? `${p.capacity_w}W` : '—' }}</span>
              <!-- 输入电压 0 = 没接电。**机器照跑,操作系统里没有症状** -->
              <span v-if="p.input_voltage !== null"
                    :style="{ color: p.input_voltage < 50 ? 'var(--i-violet)' : 'var(--i-ink2)' }">
                输入 {{ p.input_voltage }}V{{ p.input_voltage < 50 ? '(没接电)' : '' }}
              </span>
              <span :style="{ color: p.health === 'ok' ? 'var(--i-ok)'
                : p.health === 'unknown' ? 'var(--i-ink3)' : 'var(--i-crit)' }">
                {{ HEALTH_TEXT[p.health] }}
              </span>
            </div>
          </div>

          <div class="d-block">
            <div class="d-bh">温度探头 <span class="d-dim">阈值是平台自己的</span></div>
            <div v-for="(t, i) in detail.temps" :key="`t${i}`" class="d-line">
              <span class="d-n">{{ t.name }}</span>
              <b :style="{ color: tempColor(t.celsius) }">{{ num(t.celsius, 0, '℃') }}</b>
              <span v-if="t.is_inlet" class="d-dim d-sm">进风(机房环境)</span>
              <span v-else-if="t.is_exhaust" class="d-dim d-sm">出风</span>
              <!-- iDRAC 自己的严重线带出来只为对照:它通常是 100℃ -->
              <span v-if="t.crit_c" class="d-dim d-sm">iDRAC 严重线 {{ t.crit_c }}℃</span>
            </div>
          </div>

          <div class="d-block">
            <div class="d-bh">内存</div>
            <div v-if="!detail.memory.length" class="d-dim d-sm">
              没有逐条内存明细(这个固件不支持 $expand)
            </div>
            <div v-for="(m, i) in detail.memory" :key="`m${i}`" class="d-line">
              <span class="d-n">{{ m.name }}</span>
              <span class="d-dim">
                {{ m.size_mib ? `${(m.size_mib / 1024).toFixed(0)} GiB` : '—' }}
                {{ m.speed_mhz ? `· ${m.speed_mhz}MHz` : '' }}
              </span>
              <span :style="{ color: m.health === 'ok' ? 'var(--i-ok)'
                : m.health === 'unknown' ? 'var(--i-ink3)' : 'var(--i-crit)' }">
                {{ HEALTH_TEXT[m.health] }}
              </span>
            </div>
          </div>

          <div class="d-block">
            <div class="d-bh">风扇</div>
            <div v-for="(f, i) in detail.fans" :key="`f${i}`" class="d-line">
              <span class="d-n">{{ f.name }}</span>
              <!-- 单位要带出来:把 40(%) 当成 40 RPM 会显示成"风扇快停了" -->
              <b>{{ f.rpm ?? '—' }} {{ f.units === 'rpm' ? 'RPM' : '%' }}</b>
              <span :style="{ color: f.health === 'ok' ? 'var(--i-ok)'
                : f.health === 'unknown' ? 'var(--i-ink3)' : 'var(--i-crit)' }">
                {{ HEALTH_TEXT[f.health] }}
              </span>
            </div>
          </div>
        </div>

        <div v-if="detail.sel" class="d-block d-sel">
          <div class="d-bh">
            硬件日志(SEL)
            <span class="d-dim">
              近 {{ detail.sel.window_days }} 天:{{ detail.sel.recent_critical }} 条严重 /
              {{ detail.sel.recent_warning }} 条警告 · 表里共 {{ detail.sel.total }} 条
            </span>
          </div>
          <!-- **SEL 不会自动清。**不说的话人会拿"共 N 条"当成"出过 N 次问题" -->
          <div class="d-note">
            SEL 不会自动清,一台跑了几年的机器上留着很早以前的记录是正常的 ——
            所以上面按窗口过滤过。<b>一条永远都在的红等于没有红。</b>
            <template v-if="detail.sel.undated">
              另有 {{ detail.sel.undated }} 条时间戳解不出来,它们<b>不计入</b>窗口统计。
            </template>
          </div>
          <div v-for="(e, i) in detail.sel.entries" :key="`s${i}`" class="d-line">
            <span class="d-dim d-t">{{ e.at ? e.at.slice(0, 19).replace('T', ' ') : '时间未知' }}</span>
            <NTag size="tiny" :bordered="false"
                  :style="{ color: e.severity === 'critical' ? 'var(--i-crit)'
                    : e.severity === 'warning' ? 'var(--i-violet)' : 'var(--i-ink3)' }">
              {{ e.severity }}
            </NTag>
            <span :class="{ 'd-dim': !e.in_window }">{{ e.message }}</span>
            <span v-if="!e.in_window" class="d-dim d-sm">(窗口外)</span>
          </div>
        </div>
      </template>
    </NModal>
  </div>

  <div v-else class="ib-empty" :style="vars">
    <h3>带外硬件(iDRAC)</h3>
    <p v-if="board.error.value" class="ib-err">{{ board.error.value }}</p>
    <p v-else>
      还没有带外主机。到<b>配置中心 → 带外硬件</b>加一台 —— 走 Redfish(HTTPS,只读),
      要填 <b>iDRAC 的地址(带外管理口,不是服务器自己的 IP)</b>
      和一个有 Read Only 及以上角色的账号。
    </p>
  </div>
</template>

<style scoped>
.ib {
  position: relative;
  background: var(--i-bg);
  border: 1px solid color-mix(in srgb, var(--i-cyan) 26%, transparent);
  padding: 12px;
  color: var(--i-ink);
  overflow: hidden;
}
/* 扫描线:**纯装饰,不带任何语义** */
.ib-scan {
  position: absolute;
  inset: 0;
  pointer-events: none;
  background: repeating-linear-gradient(
    0deg,
    transparent 0 3px,
    color-mix(in srgb, var(--i-cyan) 4%, transparent) 3px 4px
  );
  opacity: 0.5;
}
.ib > * { position: relative; }

/* ---------------- 横幅 */
.ib-banner {
  display: grid;
  grid-template-columns: 1fr auto 1fr;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  margin-bottom: 8px;
  background: linear-gradient(90deg,
    color-mix(in srgb, var(--i-violet) 16%, var(--i-panel)),
    var(--i-panel) 45%,
    color-mix(in srgb, var(--i-cyan) 14%, var(--i-panel)));
  border: 1px solid color-mix(in srgb, var(--i-cyan) 30%, transparent);
  clip-path: polygon(0 0, calc(100% - 14px) 0, 100% 14px, 100% 100%, 14px 100%, 0 calc(100% - 14px));
  box-shadow:
    inset 0 1px 0 color-mix(in srgb, var(--i-cyan) 35%, transparent),
    inset 0 -22px 30px -26px var(--i-violet);
}
.ib-bn-name {
  font-size: 17px;
  font-weight: 700;
  color: var(--i-cyan);
  text-shadow: 0 0 12px color-mix(in srgb, var(--i-cyan) 50%, transparent);
}
.ib-bn-sub { font-size: 13px; color: var(--i-ink3); letter-spacing: 0.08em; }
.ib-bn-c { display: flex; align-items: center; gap: 12px; }
.ib-bn-c h2 {
  margin: 0;
  font-size: 24px;
  font-weight: 800;
  letter-spacing: 0.18em;
  white-space: nowrap;
  text-shadow: 0 0 18px color-mix(in srgb, var(--i-cyan) 45%, transparent);
}
.ib-diag {
  display: block;
  width: 108px;
  height: 14px;
  background: repeating-linear-gradient(115deg, var(--i-violet) 0 2px, transparent 2px 7px);
  opacity: 0.6;
}
.ib-bn-r { display: flex; justify-content: flex-end; gap: 6px; flex-wrap: wrap; }
.ib-chip {
  font-size: 13px;
  padding: 2px 9px;
  border: 1px solid currentColor;
  clip-path: polygon(0 0, calc(100% - 6px) 0, 100% 6px, 100% 100%, 0 100%);
  white-space: nowrap;
}
.ib-chip-live { color: var(--i-cyan); }
.ib-chip-time { color: var(--i-ink3); }
.ib-chip-lv.lv-ok { color: var(--i-ok); }
.ib-chip-lv.lv-warn { color: var(--i-violet); }
.ib-chip-lv.lv-crit { color: var(--i-crit); animation: ib-pulse 1.6s ease-in-out infinite; }
.ib-chip-lv.lv-unknown { color: var(--i-ink3); }

/* ---------------- 灯带 */
.ib-signal { display: flex; gap: 3px; flex-wrap: wrap; margin-bottom: 8px; }
.ib-tick {
  flex: 1 1 10px;
  min-width: 8px;
  height: 14px;
  display: block;
  background: var(--i-ink3);
  clip-path: polygon(0 0, calc(100% - 4px) 0, 100% 4px, 100% 100%, 0 100%);
  transition: transform 140ms ease, filter 140ms ease;
}
.ib-tick:hover { transform: scaleY(1.35); filter: brightness(1.4); }
.ib-tick.lv-ok {
  background: linear-gradient(180deg, color-mix(in srgb, var(--i-ok) 55%, var(--i-hi)), var(--i-ok));
  box-shadow: 0 0 6px -1px color-mix(in srgb, var(--i-ok) 60%, transparent);
}
.ib-tick.lv-warn {
  background: linear-gradient(180deg, color-mix(in srgb, var(--i-violet) 55%, var(--i-hi)), var(--i-violet));
  box-shadow: 0 0 8px -1px color-mix(in srgb, var(--i-violet) 70%, transparent);
}
.ib-tick.lv-crit { background: var(--i-crit); animation: ib-pulse 1.4s ease-in-out infinite; }
.ib-tick.lv-unknown { background: var(--i-ink3); opacity: 0.5; }
.ib-mono { font-variant-numeric: tabular-nums; }

/* ---------------- 卡片通用 */
.ib-card {
  position: relative;
  background:
    linear-gradient(180deg, color-mix(in srgb, var(--acc, var(--i-cyan)) 7%, transparent) 0 38px, transparent 38px),
    var(--i-panel);
  border: 1px solid color-mix(in srgb, var(--acc, var(--i-cyan)) 22%, transparent);
  padding: 9px 12px 11px;
  /* 右上切角 —— 和横幅、chip 同一套形状语言 */
  clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 0 100%);
  transition: border-color 200ms ease, box-shadow 200ms ease;
}
/* 顶部一道渐变霓虹:卡片的"通电"感全靠它,颜色跟着这张卡的档位走 */
.ib-card::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  height: 2px;
  width: 100%;
  background: linear-gradient(90deg, var(--acc, var(--i-cyan)), transparent 70%);
  opacity: 0.85;
}
/* 左下角标:两条短线。**不用整框** —— 整框在一屏十张卡上会糊成网格 */
.ib-card::after {
  content: '';
  position: absolute;
  left: -1px;
  bottom: -1px;
  width: 14px;
  height: 14px;
  border-left: 1px solid var(--acc, var(--i-cyan));
  border-bottom: 1px solid var(--acc, var(--i-cyan));
  opacity: 0.55;
  pointer-events: none;
}
.ib-card:hover {
  border-color: color-mix(in srgb, var(--acc, var(--i-cyan)) 55%, transparent);
  box-shadow: 0 0 18px -4px color-mix(in srgb, var(--acc, var(--i-cyan)) 45%, transparent);
}
.ib-ct {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  color: var(--i-ink2);
  letter-spacing: 0.06em;
}
.ib-ct-row {
  padding-bottom: 6px;
  margin-bottom: 6px;
  border-bottom: 1px solid color-mix(in srgb, var(--i-cyan) 15%, transparent);
}
.ib-ct-row em { font-style: normal; font-size: 13px; color: var(--i-ink3); }
.ib-ico {
  width: 15px;
  height: 15px;
  fill: none;
  stroke: var(--acc, var(--i-cyan));
  stroke-width: 1.6;
  stroke-linecap: round;
}

/* ---------------- 报错 */
.ib-alarmbox {
  border-color: color-mix(in srgb, var(--i-crit) 55%, transparent);
  margin-bottom: 8px;
  --acc: var(--i-crit);
}
.ib-alarmbox.hot { animation: ib-boxpulse 1.8s ease-in-out infinite; }
.ib-alarms { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
.ib-alarms li {
  display: flex;
  align-items: baseline;
  gap: 10px;
  flex-wrap: wrap;
  font-size: 13px;
}
.ib-ahost { min-width: 108px; font-variant-numeric: tabular-nums; }
.ib-alarms li.crit .ib-ahost { color: var(--i-crit); }
.ib-alarms li.warn .ib-ahost { color: var(--i-violet); }
.ib-a { display: inline-flex; align-items: baseline; gap: 5px; }
.ib-adot { width: 5px; height: 5px; background: currentColor; display: inline-block; }
.ib-alarms li.crit .ib-a { color: var(--i-crit); }
.ib-alarms li.warn .ib-a { color: var(--i-violet); }
.ib-a em { font-style: normal; color: var(--i-ink3); font-size: 13px; }

/* ---------------- 四张大卡 */
.ib-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 8px;
  margin-bottom: 8px;
}
.ib-mcard { border-color: color-mix(in srgb, var(--acc) 32%, transparent); }
.ib-mbig { display: flex; align-items: baseline; gap: 3px; margin-top: 2px; }
.ib-mbig b {
  font-size: 42px;
  line-height: 1.05;
  font-weight: 800;
  color: var(--acc);
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.02em;
  /* 上亮下暗的渐变字:纯色大字在深底上发闷,这一层让它像发着光的 LED。
     ⚠ 渐变字要 `-webkit-text-fill-color: transparent`,所以**必须**保留
     上面那行 color 作为不支持时的兜底 —— 不然某些浏览器上是一片空白 */
  background: linear-gradient(180deg, var(--i-hi) 0%, var(--acc) 55%, color-mix(in srgb, var(--acc) 55%, transparent) 100%);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  filter: drop-shadow(0 0 14px color-mix(in srgb, var(--acc) 55%, transparent));
}
.ib-mbig small { font-size: 13px; color: var(--acc); }
.ib-mbar {
  height: 4px;
  background: color-mix(in srgb, var(--i-ink3) 25%, transparent);
  margin: 6px 0 5px;
  overflow: hidden;
}
.ib-mbar i {
  display: block;
  height: 100%;
  background: var(--acc);
  transition: width 900ms cubic-bezier(0.22, 1, 0.36, 1);
}
.ib-mline { font-size: 13px; color: var(--i-ink2); font-variant-numeric: tabular-nums; }
.ib-mline-2 { color: var(--i-ink3); font-size: 13px; }
.ib-mcurve { margin-top: 6px; }
/* 曲线是**分布**不是时间轴 —— 这行注脚不能省,否则会被读成趋势 */
.ib-mnote { font-size: 13px; color: var(--i-ink3); text-align: right; }

/* 四类占比:代替那张没有分布可画的卡上的曲线 */
.ib-bd {
  display: flex;
  flex-direction: column;
  gap: 3px;
  margin-top: 6px;
  font-size: 13px;
  font-variant-numeric: tabular-nums;
}
.ib-bd-row {
  display: grid;
  grid-template-columns: 34px 1fr 22px;
  align-items: center;
  gap: 6px;
  color: var(--i-ink3);
}
.ib-bd-row i {
  display: block;
  height: 4px;
  background: color-mix(in srgb, var(--i-crit) 40%, transparent);
  overflow: hidden;
}
.ib-bd-row em { display: block; height: 100%; background: var(--i-ok); opacity: 0.75; }
.ib-bd-row b { text-align: right; color: var(--i-ok); }
.ib-bd-row b.bad { color: var(--i-crit); }

/* ---------------- 结论条:屏上最先被读到的一行 */
.ib-verdict {
  display: flex;
  align-items: baseline;
  gap: 12px;
  flex-wrap: wrap;
  padding: 8px 14px;
  margin-bottom: 8px;
  border-left: 3px solid var(--i-ok);
  background: color-mix(in srgb, var(--i-ok) 8%, transparent);
}
.ib-verdict b { font-size: 19px; font-weight: 800; letter-spacing: 0.04em; color: var(--i-ok); }
.ib-verdict span { font-size: 13px; color: var(--i-ink3); }
.ib-verdict.warn {
  border-left-color: var(--i-violet);
  background: color-mix(in srgb, var(--i-violet) 10%, transparent);
}
.ib-verdict.warn b { color: var(--i-violet); }
/* 严重那档整条闪 —— 这是唯一允许闪的地方(同「红只给确定的异常」) */
.ib-verdict.crit {
  border-left-color: var(--i-crit);
  background: color-mix(in srgb, var(--i-crit) 12%, transparent);
  animation: ib-boxpulse 1.6s ease-in-out infinite;
}
.ib-verdict.crit b { color: var(--i-crit); }
.ib-verdict.unknown { border-left-color: var(--i-ink3); background: transparent; }
.ib-verdict.unknown b { color: var(--i-ink3); }

/* ---------------- 部件清点:一行紧凑条 */
.ib-parts { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
.ib-part {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 10px;
  background: var(--i-panel);
  border: 1px solid color-mix(in srgb, var(--i-cyan) 18%, transparent);
  clip-path: polygon(0 0, calc(100% - 7px) 0, 100% 7px, 100% 100%, 0 100%);
  font-size: 13px;
  font-variant-numeric: tabular-nums;
}
/* 有问题的那一格才亮起来 —— 全绿时这一行是安静的背景 */
.ib-part.bad {
  border-color: color-mix(in srgb, var(--i-crit) 55%, transparent);
  background: color-mix(in srgb, var(--i-crit) 10%, var(--i-panel));
}
.ib-part b { font-size: 14px; color: var(--i-ok); }
.ib-part.bad b { color: var(--i-crit); }
.ib-part i { font-style: normal; color: var(--i-ink3); }
.ib-pk { color: var(--i-ink2); }
.ib-pico { width: 13px; height: 13px; fill: none; stroke: var(--i-ink3); stroke-width: 1.6; }
.ib-part.bad .ib-pico { stroke: var(--i-crit); }

/* ---------------- 矩阵 */
.ib-matrix { margin-bottom: 8px; }
.ib-legend {
  margin-left: auto;
  font-size: 13px;
  color: var(--i-ink3);
  display: flex;
  align-items: center;
  gap: 4px;
}
.ib-legend i { width: 9px; height: 9px; display: inline-block; margin-left: 6px; }
.ib-cells {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(104px, 1fr));
  gap: 5px;
}
.ib-cell {
  background: linear-gradient(
    160deg,
    color-mix(in srgb, var(--c) 22%, var(--i-raised)) 0%,
    var(--i-raised) 70%
  );
  border: 1px solid color-mix(in srgb, var(--c) 34%, transparent);
  padding: 5px 7px 7px;
  display: flex;
  flex-direction: column;
  gap: 1px;
  cursor: pointer;
  clip-path: polygon(0 0, calc(100% - 7px) 0, 100% 7px, 100% 100%, 0 100%);
  transition: transform 140ms ease, box-shadow 140ms ease;
}
.ib-cell:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 16px -6px color-mix(in srgb, var(--c) 70%, transparent);
}
.ib-cell.crit { outline: 1px solid var(--i-crit); outline-offset: 1px; }
.ib-cell.warn { outline: 1px solid var(--i-violet); outline-offset: 1px; }
.ib-c-ip { font-size: 13px; color: var(--i-ink2); font-variant-numeric: tabular-nums; }
.ib-c-t {
  font-size: 17px;
  font-weight: 700;
  color: var(--c);
  font-variant-numeric: tabular-nums;
  line-height: 1.1;
}
.ib-c-bar { height: 2px; background: var(--c); opacity: 0.75; }

/* ---------------- 页脚 */
.ib-foot {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  font-size: 13px;
  color: var(--i-ink3);
}
.ib-tgl { display: flex; align-items: center; gap: 6px; }
.ib-btn {
  margin-left: auto;
  background: transparent;
  border: 1px solid color-mix(in srgb, var(--i-cyan) 55%, transparent);
  color: var(--i-cyan);
  padding: 2px 12px;
  font-size: 13px;
  cursor: pointer;
}
.ib-btn:disabled { opacity: 0.5; cursor: default; }
.ib-err { color: var(--i-crit); }
.ib-empty {
  padding: 24px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  align-items: flex-start;
  border: 1px solid color-mix(in srgb, var(--i-cyan) 26%, transparent);
  background: var(--i-bg);
  color: var(--i-ink2);
}
.ib-empty h3 { margin: 0; color: var(--i-cyan); letter-spacing: 0.1em; }
.ib-empty p { margin: 0; font-size: 13px; line-height: 1.7; max-width: 60ch; }

/* ---------------- 明细弹窗 */
.d-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 14px; }
.d-block { display: flex; flex-direction: column; gap: 3px; }
.d-sel { margin-top: 14px; }
.d-bh {
  font-size: 12px;
  color: var(--cy-ink);
  letter-spacing: 0.05em;
  border-bottom: 1px solid var(--cy-line-soft);
  padding-bottom: 4px;
  margin-bottom: 4px;
  display: flex;
  gap: 8px;
  align-items: baseline;
}
.d-line {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 11.5px;
  line-height: 1.75;
  flex-wrap: wrap;
  font-variant-numeric: tabular-nums;
}
.d-n { min-width: 100px; color: var(--cy-ink-2); font-family: 'JetBrains Mono', monospace; }
.d-t { min-width: 120px; font-family: 'JetBrains Mono', monospace; }
.d-dim { color: var(--cy-ink-3); }
.d-sm { font-size: 10.5px; }
.d-actions { display: flex; gap: 8px; margin-bottom: 10px; }
.d-note {
  font-size: 11.5px;
  line-height: 1.65;
  color: var(--cy-ink-2);
  padding: 6px 11px;
  margin-bottom: 8px;
  border-left: 2px solid var(--cy-line);
  background: color-mix(in srgb, var(--cy-raised) 60%, transparent);
}
.d-note.warn {
  color: var(--cy-degraded);
  border-left-color: var(--cy-degraded);
  background: color-mix(in srgb, var(--cy-degraded) 7%, transparent);
}

@keyframes ib-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.45; }
}
@keyframes ib-boxpulse {
  0%, 100% { background: var(--i-panel); }
  50% { background: color-mix(in srgb, var(--i-crit) 9%, var(--i-panel)); }
}
</style>
