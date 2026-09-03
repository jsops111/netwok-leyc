<script setup lang="ts">
import { computed, ref } from 'vue'
import { NButton, NModal, NSwitch, NTag, NTooltip, useMessage } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import { api, errText } from '@/api'
import type { IdracBoardHost, IdracDetail, PartTriple } from '@/api'
import { usePolling } from '@/composables/usePolling'
import { ago, bytes, dateTimeOf, int, num } from '@/composables/useFormat'
import { SEVERITY, STATE } from '@/theme'

/**
 * 带外硬件大屏(iDRAC)。
 *
 * ## 它和「服务器」页回答的是两个问题
 *
 * `/servers` 走 SSH,答"这台机器上跑的系统忙不忙、盘满没满"。
 * 这一页走带外,答**"这台机器本身会不会坏"** —— 哪块盘、哪条内存、
 * 哪个电源、RAID 卷、风扇、逐点温度。
 *
 * 两边的覆盖**不重合**:一块正在预警的硬盘、一条报了可纠正错误的内存、
 * 一个已经掉电的冗余电源,在操作系统里通常一点症状都没有。所以这一页
 * 不是「服务器」页的一个 tab,它是单独的一块屏。
 *
 * ## 四条显示上的自律
 *
 * 1. **`unknown` 不是绿色,也不是红色。**「读不到这块盘的状态」和
 *    「这块盘是好的」是两个结论。合成一个的话,一台权限配错的 iDRAC
 *    会在大屏上显示成一片绿 —— 而那正是最需要有人去看一眼的时候。
 * 2. **「还没采过」不算故障。**刚加进来还没轮到的机器单独一档(pending),
 *    算成"失联"会让新加的机器先红一阵子,人会去查一个不存在的问题。
 * 3. **「带外连不上」和「硬件有严重告警」是两栏,不合并。**前者去查
 *    网络/凭据,后者去机房换件 —— 合成一栏会让人先跑错方向。
 * 4. **机械盘不显示剩余寿命。**它没有这个概念,后端给的是 null;
 *    显示成 0% 会让人以为一排盘都写光了。
 *
 * ## 刷新
 *
 * 一次刷新**只打一个接口**(`board`)。带外变化很慢,60 秒一拍就够 ——
 * 而且 BMC 是一颗很弱的处理器,这一页的刷新只读平台自己的库、不碰 BMC,
 * 真正打 BMC 的是 worker 那边按每台自己的间隔来的。
 */

const message = useMessage()

const board = usePolling(() => api.idracBoard().then((r) => r.data), 60_000)
const data = computed(() => board.data.value)
const hosts = computed(() => data.value?.hosts ?? [])
const totals = computed(() => data.value?.totals ?? null)

const onlyProblem = ref(false)
const shown = computed(() =>
  onlyProblem.value
    ? hosts.value.filter((h) => h.level !== 'ok')
    : hosts.value,
)

// ---- 明细 ----
const detailOpen = ref(false)
const detail = ref<IdracDetail | null>(null)
const detailLoading = ref(false)
const testing = ref(0)

async function openDetail(host: IdracBoardHost) {
  detailOpen.value = true
  detail.value = null
  detailLoading.value = true
  try {
    const { data: d } = await api.idracDetail(host.id)
    detail.value = d
  } catch (e) {
    message.error(errText(e))
    detailOpen.value = false
  } finally {
    detailLoading.value = false
  }
}

async function testHost(host: IdracBoardHost) {
  testing.value = host.id
  try {
    const { data: r } = await api.testIdrac(host.id)
    if (r.ok) message.success(r.detail, { duration: 12000 })
    else message.error(r.detail, { duration: 12000 })
  } catch (e) {
    message.error(errText(e))
  } finally {
    testing.value = 0
  }
}

async function collectNow(host: IdracBoardHost) {
  try {
    const { data: r } = await api.collectIdracNow(host.id)
    message.success(r.detail)
  } catch (e) {
    message.error(errText(e))
  }
}

// ---- 颜色与文案 ----

/**
 * 六档 → 颜色。**`unknown` 用灰色而不是绿色**(见文件头第 1 条);
 * `pending` 也是灰色,但文案完全不同 —— 一个是"读不到",一个是"还没读"。
 */
const LEVEL_COLOR: Record<string, string> = {
  ok: STATE.up,
  warn: STATE.degraded,
  crit: STATE.down,
  down: STATE.down,
  unknown: STATE.unknown,
  pending: STATE.unknown,
}

const LEVEL_TEXT: Record<string, string> = {
  ok: '正常',
  warn: '警告',
  crit: '严重',
  down: '带外失联',
  unknown: '状态读不到',
  pending: '尚未采集',
}

const VERDICT_TEXT: Record<string, string> = {
  ok: '全部正常',
  warn: '有警告',
  crit: '有严重问题',
  // 这一句要说清楚"不是好也不是坏",而是**这块屏上有一部分是瞎的**
  unknown: '有机器的部件状态读不到 —— 那不等于它们是好的',
}

/**
 * 部件三元组 → 一行文字 + 颜色。
 *
 * `[null,null,null]` = 这台还没采过 → `—`(**不是 0/0**)。
 * 未知数 > 0 时要单独写出来,不能只显示"3/16 异常"把未知那几块吞掉。
 */
function partText(triple: PartTriple): { text: string; color: string; title: string } {
  const [total, bad, unknown] = triple
  if (total === null) return { text: '—', color: 'var(--cy-ink-3)', title: '还没采过' }
  if (!total) {
    // 0 个部件通常不是"这台机器没有硬盘",而是这个账号读不到那一段
    return { text: '0', color: 'var(--cy-ink-3)', title: '一个都没读到 —— 账号权限够吗' }
  }
  const parts: string[] = []
  let color: string = STATE.up
  if (bad) { parts.push(`${bad} 异常`); color = STATE.down }
  if (unknown) { parts.push(`${unknown} 未知`); if (!bad) color = STATE.unknown }
  return {
    text: parts.length ? `${parts.join(' / ')} · 共 ${total}` : String(total),
    color,
    title: unknown
      ? `${unknown} 个部件读不到状态 —— 那不等于它们是好的`
      : `共 ${total} 个`,
  }
}

/** 温度色:按这台自己的阈值判,不是一个全局的数 */
function tempColor(value: number | null): string {
  if (value === null) return 'var(--cy-ink-3)'
  if (value >= 85) return STATE.down
  if (value >= 70) return STATE.degraded
  return 'var(--cy-ink)'
}

const HEALTH_TEXT: Record<string, string> = {
  ok: '正常', warning: '警告', critical: '严重', unknown: '读不到',
}
</script>

<template>
  <div class="idrac">
    <!-- ============ 顶部 ============ -->
    <div class="head">
      <div class="tiles">
        <StatTile label="带外主机" :value="totals?.hosts ?? 0" unit="台" :dim-zero="false" />
        <StatTile label="严重" :value="totals?.crit ?? 0" unit="台" :color="STATE.down"
                  foot="硬件有严重告警 —— 去机房换件" />
        <!-- **带外失联单独一栏,不并进严重** —— 它要人做的事完全不同 -->
        <StatTile label="带外失联" :value="totals?.down ?? 0" unit="台" :color="STATE.down"
                  foot="连不上 BMC —— 查网络 / 凭据" />
        <StatTile label="警告" :value="totals?.warn ?? 0" unit="台" :color="STATE.degraded" />
        <!-- **未知不是正常。**它是"这块屏上有一部分是瞎的" -->
        <StatTile label="状态读不到" :value="totals?.unknown ?? 0" unit="台"
                  :color="STATE.unknown" foot="读不到 ≠ 是好的" />
        <StatTile label="尚未采集" :value="totals?.pending ?? 0" unit="台"
                  :color="STATE.unknown" foot="刚加进来还没轮到,不是故障" />
      </div>
      <div class="actions">
        <label class="toggle">
          <NSwitch v-model:value="onlyProblem" size="small" />
          <span>只看有问题的</span>
        </label>
        <label class="toggle">
          <NSwitch :value="!board.paused.value" size="small" @update:value="board.toggle" />
          <span>{{ board.paused.value ? '已暂停' : '自动刷新' }}</span>
        </label>
        <NButton size="tiny" ghost :loading="board.loading.value" @click="board.refresh">
          刷新
        </NButton>
      </div>
    </div>

    <!-- 全局结论 -->
    <div v-if="data" class="verdict" :style="{ color: LEVEL_COLOR[data.verdict] }">
      <i class="dot" :style="{ background: LEVEL_COLOR[data.verdict] }"></i>
      {{ VERDICT_TEXT[data.verdict] }}
      <span class="dim">
        · 数据于 {{ dateTimeOf(data.generated_at) }}
        <template v-if="board.isStale()">(刷新落后了)</template>
      </span>
    </div>
    <div v-if="board.error.value" class="err">
      {{ board.error.value }} —— 显示的是上一次拿到的数据
    </div>

    <!-- ============ 全局部件计数 ============ -->
    <CyberPanel v-if="totals" title="部件总览" subtitle="全部带外主机加起来">
      <div class="parts-grid">
        <div class="part-box">
          <div class="pb-k">物理盘</div>
          <div class="pb-v">
            <b :style="{ color: totals.disk_bad ? STATE.down : STATE.up }">
              {{ totals.disk_bad }}
            </b>
            <span class="dim"> 异常 / 共 {{ totals.disk_total }}</span>
          </div>
          <!-- 未知单独一行。**并进"正常"会在真出事时闭嘴** -->
          <div v-if="totals.disk_unknown" class="pb-note">
            {{ totals.disk_unknown }} 块读不到状态 —— 那不等于它们是好的
          </div>
          <div v-if="totals.ssd_worn" class="pb-note warn">
            {{ totals.ssd_worn }} 块 SSD 剩余写入寿命告急(机械盘不参与这项)
          </div>
        </div>

        <div class="part-box">
          <div class="pb-k">RAID 卷</div>
          <div class="pb-v">
            <b :style="{ color: totals.vdisk_bad ? STATE.down : STATE.up }">
              {{ totals.vdisk_bad }}
            </b>
            <span class="dim"> 降级 / 共 {{ totals.vdisk_total }}</span>
          </div>
        </div>

        <div class="part-box">
          <div class="pb-k">内存条</div>
          <div class="pb-v">
            <b :style="{ color: totals.memory_bad ? STATE.down : STATE.up }">
              {{ totals.memory_bad }}
            </b>
            <span class="dim"> 异常 / 共 {{ totals.memory_total }}</span>
          </div>
        </div>

        <div class="part-box">
          <div class="pb-k">电源</div>
          <div class="pb-v">
            <b :style="{ color: totals.psu_bad ? STATE.down : STATE.up }">
              {{ totals.psu_bad }}
            </b>
            <span class="dim"> 异常 / 共 {{ totals.psu_total }}</span>
          </div>
        </div>

        <div class="part-box">
          <div class="pb-k">风扇</div>
          <div class="pb-v">
            <b :style="{ color: totals.fan_bad ? STATE.down : STATE.up }">
              {{ totals.fan_bad }}
            </b>
            <span class="dim"> 异常 / 共 {{ totals.fan_total }}</span>
          </div>
        </div>

        <div class="part-box">
          <div class="pb-k">最高温度</div>
          <div class="pb-v">
            <b :style="{ color: tempColor(totals.temp_max) }">
              {{ num(totals.temp_max, 0, '℃') }}
            </b>
            <!-- 最热那台**点名** —— 只给一个数字的话人还得自己去表里找 -->
            <span v-if="totals.temp_max_host" class="dim"> · {{ totals.temp_max_host }}</span>
          </div>
          <div v-if="totals.temp_avg !== null" class="pb-note">
            全场平均 {{ num(totals.temp_avg, 0, '℃') }}
          </div>
        </div>

        <div class="part-box">
          <div class="pb-k">整机功耗</div>
          <div class="pb-v">
            <b>{{ num(totals.power_watts, 0, ' W') }}</b>
            <span class="dim"> 合计</span>
          </div>
        </div>

        <div class="part-box">
          <div class="pb-k">近期硬件日志</div>
          <div class="pb-v">
            <b :style="{ color: totals.sel_recent_critical ? STATE.down : STATE.up }">
              {{ totals.sel_recent_critical }}
            </b>
            <span class="dim"> 条严重</span>
          </div>
          <!-- SEL 不会自动清,所以这个数是**窗口内**的 —— 说出来,
               否则人会拿它和 iDRAC 界面上的总数对不上 -->
          <div class="pb-note">只数每台自己的回看窗口内的,不是历史总数</div>
        </div>
      </div>
    </CyberPanel>

    <!-- ============ 主机矩阵 ============ -->
    <CyberPanel title="带外主机" :subtitle="`${shown.length} 台`">
      <div v-if="!shown.length" class="cy-empty">
        <template v-if="onlyProblem">
          没有有问题的带外主机。
        </template>
        <template v-else>
          还没有带外主机。在<b>配置中心 → 带外硬件</b>里加一台 ——
          需要 iDRAC 的地址(<b>带外管理口的地址,不是服务器自己的 IP</b>)
          和一个有 Read Only 及以上角色的账号。
        </template>
      </div>

      <div class="cards">
        <div
          v-for="h in shown" :key="h.id"
          class="card" :style="{ '--lv': LEVEL_COLOR[h.level] }"
        >
          <div class="c-head">
            <i class="c-dot"></i>
            <div class="c-name">
              <div class="c-n">{{ h.name }}</div>
              <div class="c-ip cy-mono">{{ h.host }}</div>
            </div>
            <NTag size="tiny" :bordered="false" :style="{ color: LEVEL_COLOR[h.level] }">
              {{ LEVEL_TEXT[h.level] }}
            </NTag>
          </div>

          <div class="c-meta">
            <span>{{ h.model || '型号待采集' }}</span>
            <span v-if="h.service_tag" class="dim cy-mono">SN {{ h.service_tag }}</span>
            <!-- 电源状态是带外独有的信息:带内 SSH 连不上时分不出
                 "机器关了"和"网络断了",这里能分 -->
            <span v-if="h.power_state" class="dim">电源 {{ h.power_state }}</span>
          </div>
          <!-- 关联到带内那台服务器 —— 两边覆盖不重合,能对上时把链接给出来 -->
          <div v-if="h.server_name" class="c-link">
            带内:<RouterLink to="/servers">{{ h.server_name }}</RouterLink>
          </div>

          <div v-if="h.level === 'down'" class="c-err">
            {{ h.last_error || '带外连不上' }}
          </div>
          <div v-else-if="h.level === 'pending'" class="c-note">
            还没轮到采集 —— 每 {{ h.interval }}s 一拍,等一拍就有数据了
          </div>

          <template v-else>
            <div class="c-metrics">
              <div class="m">
                <span class="m-k">最高温度</span>
                <b class="cy-mono" :style="{ color: tempColor(h.metrics.max_temp_c) }">
                  {{ num(h.metrics.max_temp_c, 0, '℃') }}
                </b>
                <span v-if="h.hottest" class="m-f">{{ h.hottest }}</span>
              </div>
              <div class="m">
                <span class="m-k">进风</span>
                <b class="cy-mono">{{ num(h.metrics.inlet_temp_c, 0, '℃') }}</b>
                <span class="m-f">机房环境</span>
              </div>
              <div class="m">
                <span class="m-k">同机温差</span>
                <!-- **iDRAC 自己没有这条判据。**它的严重线是 100℃,所以
                     一颗散热坏了的 CPU 在它眼里是正常的 -->
                <b
                  class="cy-mono"
                  :style="{ color: (h.metrics.temp_delta_c ?? 0) >= 15
                    ? STATE.degraded : 'var(--cy-ink)' }"
                >{{ num(h.metrics.temp_delta_c, 0, '℃') }}</b>
                <span class="m-f">两颗差多少</span>
              </div>
              <div class="m">
                <span class="m-k">功耗</span>
                <b class="cy-mono">{{ num(h.metrics.power_watts, 0, ' W') }}</b>
              </div>
            </div>

            <div class="c-parts">
              <NTooltip v-for="(label, key) in {
                disk: '物理盘', vdisk: 'RAID 卷', memory: '内存', psu: '电源', fan: '风扇',
              }" :key="key" placement="top">
                <template #trigger>
                  <div class="p">
                    <span class="p-k">{{ label }}</span>
                    <b :style="{ color: partText(h.parts[key]).color }">
                      {{ partText(h.parts[key]).text }}
                    </b>
                  </div>
                </template>
                {{ partText(h.parts[key]).title }}
              </NTooltip>
            </div>

            <div v-if="h.alerts.length" class="c-alerts">
              <div
                v-for="(a, i) in h.alerts.slice(0, 4)" :key="i"
                class="a" :style="{ borderLeftColor: SEVERITY[a.severity as 'warning'] }"
              >
                <b :style="{ color: SEVERITY[a.severity as 'warning'] }">{{ a.kind_label }}</b>
                {{ a.message }}
              </div>
              <div v-if="h.alerts.length > 4" class="dim small">
                还有 {{ h.alerts.length - 4 }} 条 —— 点「明细」看全部
              </div>
            </div>
          </template>

          <div class="c-foot">
            <span class="dim">{{ h.ts ? `采集于 ${ago(h.ts)}` : '尚未采集' }}</span>
            <span class="c-btns">
              <NButton size="tiny" text type="primary" @click="openDetail(h)">明细</NButton>
              <NButton size="tiny" text :loading="testing === h.id" @click="testHost(h)">
                测试
              </NButton>
              <NButton size="tiny" text @click="collectNow(h)">立即采</NButton>
            </span>
          </div>
        </div>
      </div>
    </CyberPanel>

    <!-- ============ 告警清单 ============ -->
    <CyberPanel
      v-if="data?.alerts.length" title="未恢复的硬件告警"
      :subtitle="`${data.alerts.length} 条`"
    >
      <div
        v-for="(a, i) in data.alerts" :key="i"
        class="row" :style="{ borderLeftColor: SEVERITY[a.severity as 'warning'] }"
      >
        <span class="r-host">{{ a.host }}</span>
        <NTag size="tiny" :bordered="false" :style="{ color: SEVERITY[a.severity as 'warning'] }">
          {{ a.kind_label }}
        </NTag>
        <span class="r-msg">{{ a.message }}</span>
        <span class="dim r-time">{{ ago(a.started_at) }}</span>
      </div>
    </CyberPanel>

    <!-- ============ 明细 ============ -->
    <NModal
      v-model:show="detailOpen" preset="card" :bordered="false"
      :title="detail?.host.name || '带外明细'"
      style="width: min(1080px, 96vw)"
    >
      <div v-if="detailLoading" class="dim">读取明细…</div>
      <template v-else-if="detail">
        <!-- **为什么某一栏是空的** —— 没有这几条,"硬盘 0 块"看着像
             这台机器没有硬盘 -->
        <div v-for="(n, i) in detail.notes" :key="`n${i}`" class="note">{{ n }}</div>
        <div
          v-for="(msg, seg) in detail.endpoint_errors" :key="`e${seg}`"
          class="note warn"
        >
          <b>{{ seg }}</b> 这一段没取到:{{ msg }} —— 下面对应的部件是空的,
          <b>不代表这台机器没有</b>
        </div>

        <div class="d-grid">
          <!-- 物理盘 -->
          <div class="block">
            <div class="bh">物理盘 <span class="dim">{{ detail.disks.length }} 块</span></div>
            <div v-if="!detail.disks.length" class="dim small">没有读到物理盘</div>
            <div v-for="(d, i) in detail.disks" :key="`d${i}`" class="line">
              <span class="l-n cy-mono" :title="d.model">{{ d.slot || d.name }}</span>
              <NTag size="tiny" :bordered="false">{{ d.media }}</NTag>
              <span class="dim">{{ d.capacity_gb ? `${d.capacity_gb} GB` : '—' }}</span>
              <!-- **机械盘不显示剩余寿命** —— 它没有这个概念,后端给 null。
                   显示成 0% 会让人以为一排盘都写光了 -->
              <span
                v-if="d.life_pct !== null" class="cy-mono"
                :style="{ color: d.life_pct <= 10 ? STATE.down
                  : d.life_pct <= 25 ? STATE.degraded : 'var(--cy-ink-2)' }"
              >寿命 {{ d.life_pct }}%</span>
              <span v-else-if="d.is_ssd" class="dim small">寿命未知</span>
              <span v-else class="dim small">机械盘无寿命指标</span>
              <NTag
                v-if="d.smart_alert" size="tiny" :bordered="false"
                :style="`color:${STATE.degraded};border:1px solid ${STATE.degraded}`"
              >SMART 预警</NTag>
              <span :style="{ color: d.health === 'ok' ? STATE.up
                : d.health === 'unknown' ? STATE.unknown : STATE.down }">
                {{ HEALTH_TEXT[d.health] }}
              </span>
            </div>
          </div>

          <!-- RAID 卷 -->
          <div class="block">
            <div class="bh">RAID 卷</div>
            <div v-if="!detail.volumes.length" class="dim small">没有读到 RAID 卷</div>
            <div v-for="(v, i) in detail.volumes" :key="`v${i}`" class="line">
              <span class="l-n cy-mono">{{ v.name }}</span>
              <NTag size="tiny" :bordered="false">{{ v.raid_type || '—' }}</NTag>
              <span class="dim">{{ v.capacity_gb ? `${v.capacity_gb} GB` : '—' }}</span>
              <!-- 冗余度 0 = 再坏一块盘这个卷就没了。卷本身还是"正常",
                   所以这一条必须单独显示出来 -->
              <span
                v-if="v.remaining_redundancy === 0"
                :style="{ color: STATE.degraded }"
              >已无冗余(再坏一块就丢数据)</span>
              <span :style="{ color: v.health === 'ok' ? STATE.up
                : v.health === 'unknown' ? STATE.unknown : STATE.down }">
                {{ HEALTH_TEXT[v.health] }}
              </span>
            </div>
          </div>

          <!-- 电源 -->
          <div class="block">
            <div class="bh">电源</div>
            <div v-if="!detail.psus.length" class="dim small">没有读到电源</div>
            <div v-for="(p, i) in detail.psus" :key="`p${i}`" class="line">
              <span class="l-n cy-mono">{{ p.name }}</span>
              <span class="dim">{{ p.capacity_w ? `${p.capacity_w}W` : '—' }}</span>
              <!-- 输入电压 0 = 没接电。**冗余电源掉一路时机器照跑,
                   操作系统里一点症状都没有** -->
              <span
                v-if="p.input_voltage !== null"
                :style="{ color: p.input_voltage < 50 ? STATE.degraded : 'var(--cy-ink-2)' }"
              >输入 {{ p.input_voltage }}V{{ p.input_voltage < 50 ? '(没接电)' : '' }}</span>
              <span :style="{ color: p.health === 'ok' ? STATE.up
                : p.health === 'unknown' ? STATE.unknown : STATE.down }">
                {{ HEALTH_TEXT[p.health] }}
              </span>
            </div>
          </div>

          <!-- 温度 -->
          <div class="block">
            <div class="bh">
              温度探头
              <span class="dim">阈值是平台自己的,不是 iDRAC 的</span>
            </div>
            <div v-for="(t, i) in detail.temps" :key="`t${i}`" class="line">
              <span class="l-n cy-mono">{{ t.name }}</span>
              <b class="cy-mono" :style="{ color: tempColor(t.celsius) }">
                {{ num(t.celsius, 0, '℃') }}
              </b>
              <span v-if="t.is_inlet" class="dim small">进风(机房环境)</span>
              <span v-else-if="t.is_exhaust" class="dim small">出风</span>
              <!-- iDRAC 自己的严重线带出来只为对照:它通常是 100℃,
                   看一眼就明白为什么不能拿它当判据 -->
              <span v-if="t.crit_c" class="dim small">iDRAC 严重线 {{ t.crit_c }}℃</span>
            </div>
          </div>

          <!-- 内存 -->
          <div class="block">
            <div class="bh">内存</div>
            <div v-if="!detail.memory.length" class="dim small">
              没有逐条内存明细(这个固件不支持 $expand)
            </div>
            <div v-for="(m, i) in detail.memory" :key="`m${i}`" class="line">
              <span class="l-n cy-mono">{{ m.name }}</span>
              <span class="dim">
                {{ m.size_mib ? bytes(m.size_mib * 1024 * 1024) : '—' }}
                {{ m.speed_mhz ? `· ${m.speed_mhz}MHz` : '' }}
              </span>
              <span :style="{ color: m.health === 'ok' ? STATE.up
                : m.health === 'unknown' ? STATE.unknown : STATE.down }">
                {{ HEALTH_TEXT[m.health] }}
              </span>
            </div>
          </div>

          <!-- 风扇 -->
          <div class="block">
            <div class="bh">风扇</div>
            <div v-for="(f, i) in detail.fans" :key="`f${i}`" class="line">
              <span class="l-n cy-mono">{{ f.name }}</span>
              <!-- 单位要带出来:有些机型报的是百分比,把 40(%) 当成
                   40 RPM 会显示成"风扇快停了" -->
              <b class="cy-mono">{{ int(f.rpm) }} {{ f.units === 'rpm' ? 'RPM' : '%' }}</b>
              <span :style="{ color: f.health === 'ok' ? STATE.up
                : f.health === 'unknown' ? STATE.unknown : STATE.down }">
                {{ HEALTH_TEXT[f.health] }}
              </span>
            </div>
          </div>
        </div>

        <!-- 硬件日志 -->
        <div v-if="detail.sel" class="block sel">
          <div class="bh">
            硬件日志(SEL)
            <span class="dim">
              近 {{ detail.sel.window_days }} 天:
              {{ detail.sel.recent_critical }} 条严重 / {{ detail.sel.recent_warning }} 条警告
              · 表里共 {{ detail.sel.total }} 条
            </span>
          </div>
          <!-- **SEL 不会自动清。**这句话必须写出来,否则人会拿"共 N 条"
               当成"这台机器出过 N 次问题" -->
          <div class="note">
            SEL 不会自动清,一台跑了几年的机器上留着很早以前的记录是正常的 ——
            所以上面按窗口过滤过。<b>一条永远都在的红等于没有红。</b>
            <template v-if="detail.sel.undated">
              另有 {{ detail.sel.undated }} 条时间戳解不出来,它们<b>不计入</b>窗口统计。
            </template>
          </div>
          <div v-for="(e, i) in detail.sel.entries" :key="`s${i}`" class="line">
            <span class="dim cy-mono l-t">{{ e.at ? dateTimeOf(e.at) : '时间未知' }}</span>
            <NTag
              size="tiny" :bordered="false"
              :style="{ color: e.severity === 'critical' ? STATE.down
                : e.severity === 'warning' ? STATE.degraded : 'var(--cy-ink-3)' }"
            >{{ e.severity }}</NTag>
            <span :class="{ dim: !e.in_window }">{{ e.message }}</span>
            <span v-if="!e.in_window" class="dim small">(窗口外)</span>
          </div>
        </div>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.idrac { display: flex; flex-direction: column; gap: 14px; }

.head { display: flex; align-items: flex-end; justify-content: space-between; gap: 14px; flex-wrap: wrap; }
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(146px, 1fr));
  gap: 10px;
  flex: 1;
  min-width: 320px;
}
.actions { display: flex; align-items: center; gap: 12px; }
.toggle { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: var(--cy-ink-2); }

.verdict { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 700; }
.verdict .dot { width: 9px; height: 9px; border-radius: 50%; }
.dim { color: var(--cy-ink-3); font-weight: 400; }
.small { font-size: 10.5px; }

.err {
  font-size: 11.5px; color: var(--cy-down);
  padding: 5px 10px; border-left: 2px solid var(--cy-down);
  background: rgba(var(--cy-down-rgb), 0.06);
}

.parts-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 10px;
}
.part-box {
  border: 1px solid var(--cy-line-soft);
  padding: 8px 10px;
  background: rgba(var(--cy-raised-rgb), 0.45);
}
.pb-k { font-size: 10.5px; color: var(--cy-ink-3); letter-spacing: .04em; }
.pb-v { font-size: 13px; margin-top: 2px; }
.pb-v b { font-family: 'JetBrains Mono', monospace; font-size: 17px; }
.pb-note { font-size: 10px; color: var(--cy-ink-3); line-height: 1.5; margin-top: 3px; }
.pb-note.warn { color: var(--cy-degraded); }

.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 12px;
}
.card {
  border: 1px solid var(--cy-line-soft);
  border-left: 3px solid var(--lv);
  padding: 10px 12px;
  background: rgba(var(--cy-raised-rgb), 0.4);
  display: flex;
  flex-direction: column;
  gap: 7px;
}
.c-head { display: flex; align-items: center; gap: 8px; }
.c-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--lv); flex: none; }
.c-name { flex: 1; min-width: 0; }
.c-n { font-size: 12.5px; color: var(--cy-ink); }
.c-ip { font-size: 10.5px; color: var(--cy-ink-3); }
.c-meta { display: flex; gap: 8px; flex-wrap: wrap; font-size: 10.5px; color: var(--cy-ink-2); }
.c-link { font-size: 10.5px; color: var(--cy-ink-3); }
.c-err {
  font-size: 11px; color: var(--cy-down);
  border-left: 2px solid var(--cy-down); padding-left: 7px;
}
.c-note { font-size: 11px; color: var(--cy-ink-3); }

.c-metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; }
.m { display: flex; flex-direction: column; gap: 1px; }
.m-k { font-size: 9.5px; color: var(--cy-ink-3); }
.m b { font-size: 14px; }
.m-f { font-size: 9px; color: var(--cy-ink-3); }

.c-parts { display: flex; gap: 10px; flex-wrap: wrap; }
.p { display: flex; flex-direction: column; gap: 1px; cursor: default; }
.p-k { font-size: 9.5px; color: var(--cy-ink-3); }
.p b { font-size: 11.5px; font-family: 'JetBrains Mono', monospace; }

.c-alerts { display: flex; flex-direction: column; gap: 3px; }
.a {
  font-size: 10.5px; line-height: 1.5; color: var(--cy-ink-2);
  border-left: 2px solid; padding-left: 7px;
}
.c-foot {
  display: flex; align-items: center; justify-content: space-between;
  font-size: 10.5px; border-top: 1px solid var(--cy-line-soft); padding-top: 6px;
}
.c-btns { display: flex; gap: 8px; }

.row {
  display: flex; align-items: center; gap: 8px;
  font-size: 11.5px; line-height: 1.7;
  border-left: 2px solid; padding-left: 8px;
}
.r-host { min-width: 120px; color: var(--cy-ink); }
.r-msg { flex: 1; color: var(--cy-ink-2); }
.r-time { white-space: nowrap; }

.d-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 14px;
}
.block { display: flex; flex-direction: column; gap: 3px; }
.block.sel { margin-top: 14px; }
.bh {
  font-size: 11px; color: var(--cy-ink); letter-spacing: .05em;
  border-bottom: 1px solid var(--cy-line-soft); padding-bottom: 4px; margin-bottom: 4px;
  display: flex; gap: 8px; align-items: baseline;
}
.bh .dim { font-size: 10px; }
.line {
  display: flex; align-items: center; gap: 7px;
  font-size: 11px; line-height: 1.7; flex-wrap: wrap;
}
.l-n { min-width: 96px; color: var(--cy-ink-2); }
.l-t { min-width: 116px; }
.note {
  font-size: 11px; line-height: 1.6; color: var(--cy-ink-2);
  padding: 5px 10px; margin-bottom: 6px;
  border-left: 2px solid var(--cy-line);
  background: rgba(var(--cy-raised-rgb), 0.5);
}
.note.warn {
  color: var(--cy-degraded);
  border-left-color: var(--cy-degraded);
  background: rgba(var(--cy-degraded-rgb), 0.06);
}
</style>
