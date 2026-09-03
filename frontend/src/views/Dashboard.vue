<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { NButton, NButtonGroup, NCheckbox, NSelect, NTooltip } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import StateDot from '@/components/cyber/StateDot.vue'
import MeterBar from '@/components/cyber/MeterBar.vue'
import GroupChart from '@/components/charts/GroupChart.vue'
import SdwanChart from '@/components/charts/SdwanChart.vue'
import DeviceTrend from '@/components/charts/DeviceTrend.vue'
import Sparkline from '@/components/charts/Sparkline.vue'
import { api } from '@/api'
import type { DeviceCard } from '@/api'
import { usePolling } from '@/composables/usePolling'
import { ago, bps, endpoint, int, ms, pct, timeOf } from '@/composables/useFormat'
import { STATE, stateColor } from '@/theme'

/**
 * 监控大屏(展示页面)。
 *
 * **一次刷新只打三个接口** —— overview / charts / devices。
 * 别改成"每条线路一个请求":几十条线路 × 每 5 秒,gunicorn 直接打满。
 *
 * 三个数据源的刷新频率是分开的,因为它们的变化速度不一样:
 *   统计     5s   —— 顶部数字,要跟手
 *   图表     10s  —— 数据量大,而且秒级线路 10s 也就多十个点
 *   设备     30s  —— 设备采集本身最快 10s 一次,刷太勤是白刷
 */

// 顶部统计的时间窗
const windowHours = ref(24)
// 大图的时间跨度(分钟)
const chartMinutes = ref(30)
// 大图当前显示哪个指标
const metric = ref<'rtt' | 'loss' | 'jitter'>('rtt')

const overview = usePolling(() => api.overview(windowHours.value).then((r) => r.data), 5000)
const charts = usePolling(() => api.charts(chartMinutes.value, 12).then((r) => r.data), 10000)
const devices = usePolling(() => api.deviceCards(3).then((r) => r.data), 30000)

const WINDOW_OPTIONS = [
  { label: '最近 1 小时', value: 1 },
  { label: '最近 6 小时', value: 6 },
  { label: '最近 24 小时', value: 24 },
  { label: '最近 7 天', value: 168 },
]
const SPAN_OPTIONS = [
  { label: '10 分钟', value: 10 },
  { label: '30 分钟', value: 30 },
  { label: '2 小时', value: 120 },
  { label: '12 小时', value: 720 },
  { label: '2 天', value: 2880 },
]
const METRIC_OPTIONS = [
  { label: '延迟', value: 'rtt' as const },
  { label: '丢包', value: 'loss' as const },
  { label: '抖动', value: 'jitter' as const },
]

/** 顶部那五格的颜色。断线用红,丢包/延迟/抖动用黄,异常用紫。 */
const TILE_COLORS: Record<string, string> = {
  down: STATE.down,
  loss: STATE.degraded,
  latency: STATE.degraded,
  jitter: 'var(--cy-violet)',
  anomaly: 'var(--cy-magenta)',
}

/** 有未恢复的严重事件 → 整个大屏进入告警态(面板边框脉冲)。 */
const alarmLevel = computed<'normal' | 'warning' | 'critical'>(() => {
  const o = overview.data.value
  if (!o) return 'normal'
  if (o.events.critical_open > 0) return 'critical'
  if (o.events.open > 0) return 'warning'
  return 'normal'
})

function groupLevel(summary: { down: number; degraded: number }) {
  if (summary.down > 0) return 'critical' as const
  if (summary.degraded > 0) return 'warning' as const
  return 'normal' as const
}

/**
 * 这一屏显示哪些设备、怎么排 —— **存在浏览器里,不存库**。
 *
 * 理由:一块挂在墙上的大屏和一个人在工位上开的页面**要看的东西不一样**,
 * 而存库是一份**共享**设置 —— 两个人各调各的会互相覆盖,大屏上的东西
 * 会莫名其妙变掉,还查不出是谁改的。
 *
 * 对比:保留期是存库的(见「时序数据」那一节)—— 那是**系统**设置,
 * 全站只该有一份;而"这块屏显示什么"是**视图**设置,天生该按屏各算各的。
 *
 * ⚠ **隐藏 ≠ 停止监控。**被隐藏的设备照样在采、照样开事件、照样推告警 ——
 * 只是这一屏不画它。要真的停,是配置中心里那个「启用」开关。
 * 这句话写在选择框里,不写的话一定会有人用隐藏来"关掉"一台设备。
 */
const DEVICE_VIEW_KEY = 'netcheck.dashboard.devices'

type DeviceSort = 'order' | 'name' | 'state' | 'collected'

const deviceSort = ref<DeviceSort>('order')
/** 被隐藏的设备 id。**存"隐藏哪些"而不是"显示哪些"** —— 新加的设备
 *  默认就该出现在大屏上,存白名单的话它会悄悄不显示 */
const hiddenDevices = ref<Set<number>>(new Set())
const pickerOpen = ref(false)

try {
  const saved = JSON.parse(localStorage.getItem(DEVICE_VIEW_KEY) || '{}')
  if (Array.isArray(saved.hidden)) hiddenDevices.value = new Set(saved.hidden)
  if (saved.sort) deviceSort.value = saved.sort
} catch {
  // 存坏了就用默认的 —— 一个读不出来的偏好不该让整页打不开
}

function saveDeviceView() {
  try {
    localStorage.setItem(DEVICE_VIEW_KEY, JSON.stringify({
      hidden: [...hiddenDevices.value], sort: deviceSort.value,
    }))
  } catch { /* 隐私模式下写不了,不影响这次会话内的效果 */ }
}

function toggleDevice(id: number) {
  if (hiddenDevices.value.has(id)) hiddenDevices.value.delete(id)
  else hiddenDevices.value.add(id)
  hiddenDevices.value = new Set(hiddenDevices.value)
  saveDeviceView()
}
function showAllDevices() {
  hiddenDevices.value = new Set()
  saveDeviceView()
}
watch(deviceSort, saveDeviceView)

/**
 * SD-WAN SLA 也上大屏,**同一套选择机制**(存浏览器、存"隐藏哪些")。
 *
 * 它和上面那些线路测的**不是同一段**:线路是这个平台自己从部署点探的,
 * SD-WAN 是防火墙自己从它的出口探的 —— 这句话在 `/sdwan` 那一页写在
 * 最上面,大屏上地方小,所以放在小节标题的副标题里。
 */
const SDWAN_VIEW_KEY = 'netcheck.dashboard.sdwan'
/** 图上画哪个指标。**跨度跟着线路图走,指标各自选** —— 延迟和丢包的
 *  量纲不同(ms / %),堆一张图上读不出东西(和 GroupChart 同一条) */
const sdwanMetric = ref<'latency' | 'jitter' | 'loss'>('latency')
const SDWAN_METRIC_OPTIONS = [
  { label: '延迟', value: 'latency' },
  { label: '抖动', value: 'jitter' },
  { label: '丢包', value: 'loss' },
]
const hiddenSdwan = ref<Set<number>>(new Set())
const sdwanPickerOpen = ref(false)
/**
 * **跟着大屏那个时间跨度走**(和线路图同一个选择器)—— 一屏上两块图
 * 显示的是不同的时间窗,人对着看会得出错的结论。
 *
 * 向上取整到小时:接口的参数是小时,而跨度选择器最小是 10 分钟。
 * 取整到 1 小时比取 0 小时安全 —— 后者会让图完全空掉。
 */
const sdwanHours = computed(() => Math.max(1, Math.ceil(chartMinutes.value / 60)))
const sdwan = usePolling(
  () => api.sdwanBoard(sdwanHours.value).then((r) => r.data), 60_000)
watch(sdwanHours, () => void sdwan.refresh())

try {
  const saved = JSON.parse(localStorage.getItem(SDWAN_VIEW_KEY) || '{}')
  if (Array.isArray(saved.hidden)) hiddenSdwan.value = new Set(saved.hidden)
} catch { /* 存坏了用默认的 */ }

function saveSdwanView() {
  try {
    localStorage.setItem(SDWAN_VIEW_KEY,
      JSON.stringify({ hidden: [...hiddenSdwan.value] }))
  } catch { /* 隐私模式 */ }
}
function toggleSdwan(id: number) {
  if (hiddenSdwan.value.has(id)) hiddenSdwan.value.delete(id)
  else hiddenSdwan.value.add(id)
  hiddenSdwan.value = new Set(hiddenSdwan.value)
  saveSdwanView()
}
function showAllSdwan() {
  hiddenSdwan.value = new Set()
  saveSdwanView()
}

/** 全部链路(拉平,不分设备)—— 大屏上按链路看,不按设备看 */
const everySdwanLink = computed(() =>
  (sdwan.data.value?.devices ?? []).flatMap((d) =>
    d.links.map((l) => ({ ...l, device_name: d.device_name }))))

const sdwanLinks = computed(() => {
  const list = everySdwanLink.value.filter((l) => !hiddenSdwan.value.has(l.id))
  // **有问题的排前面** —— 大屏上这一块通常只有几条,而它存在的意义
  // 就是"哪条出口现在不行"。同档内按设备名+成员名,顺序才稳定
  return [...list].sort((a, b) => {
    const rank = (x: typeof a) => (x.state === 'dead' ? 0 : x.sla_met === false ? 1 : 2)
    return rank(a) - rank(b)
      || a.device_name.localeCompare(b.device_name, 'zh-CN')
      || a.member.localeCompare(b.member)
  })
})

/**
 * 按**健康检查**分组 —— 一个检查一张图,线 = 各个出口。
 *
 * 和线路那边「一个监控类一张大图」是同一个结构:同一个检查下的几个出口
 * 探的是**同一个目标**,画在一张图上才能直接比"哪个出口更快"。
 * 拆成一条链路一张图的话,那个比较要靠人在两张图之间眼睛来回扫。
 */
const sdwanBlocks = computed(() => {
  const map = new Map<string, typeof sdwanLinks.value>()
  for (const l of sdwanLinks.value) {
    const key = `${l.device_name}||${l.health_check}`
    if (!map.has(key)) map.set(key, [])
    map.get(key)!.push(l)
  }
  return [...map.entries()].map(([key, rows]) => {
    const [device, check] = key.split("||")
    return {
      key, device, check, rows,
      // 探的是哪个地址 —— 放在图的标题上,这一块最常被问的一句
      server: rows.find((r) => r.server)?.server || "目标未报",
      protocol: rows.find((r) => r.protocol)?.protocol || "ping",
      down: rows.filter((r) => r.state === "dead"),
      bad: rows.filter((r) => r.sla_met === false && r.state !== "dead"),
    }
  })
  // **有问题的检查排前面** —— 大屏上要先看见坏的那张图
  .sort((a, b) =>
    (b.down.length ? 2 : b.bad.length ? 1 : 0) - (a.down.length ? 2 : a.bad.length ? 1 : 0)
    || a.key.localeCompare(b.key, "zh-CN"))
})

/**
 * 这条链路断了多久。`last_change` 为空时说"不知道多久"而不是"刚断" ——
 * 采集器是在**看到状态变化**时才写那个字段的,一条从加进来就一直断着的
 * 链路从没"变化"过。显示成"刚断"会让人去查一个错误的时间窗。
 */
function downFor(link: { state: string; last_change: string | null }): string {
  if (link.state !== 'dead') return ''
  if (!link.last_change) return '不知道断了多久'
  const secs = Math.max(0, (Date.now() - new Date(link.last_change).getTime()) / 1000)
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  if (d) return `已断 ${d}天${h}小时`
  if (h) return `已断 ${h}小时${m}分`
  return m ? `已断 ${m} 分钟` : '刚刚断的'
}

/** 和设备那边同一条:**被隐藏的里面有问题的要点名**,不能悄悄消失 */
const hiddenSdwanSummary = computed(() => {
  const hidden = everySdwanLink.value.filter((l) => hiddenSdwan.value.has(l.id))
  return {
    count: hidden.length,
    bad: hidden.filter((l) => l.state === 'dead' || l.sla_met === false),
  }
})

const SORT_OPTIONS = [
  { label: '按优先级', value: 'order' },
  { label: '按名称', value: 'name' },
  { label: '按状态(有问题的在前)', value: 'state' },
  { label: '按最后采集', value: 'collected' },
]

/** 接口按 kind 分三个桶给,拼起来才是完整的一份 */
const everyDevice = computed<DeviceCard[]>(() => {
  const d = devices.data.value
  if (!d) return []
  // ⚠ **拼完必须重排。**每个桶内是按优先级排好的,但直接拼起来之后整体
  // 不是优先级顺序:一台优先级 5 的交换机会排在优先级 1 的防火墙前面,
  // 因为它在前一个桶里
  return [...d.switches, ...d.firewalls, ...d.others]
})

/** 状态排序用的权重。**down 最前** —— 这个排法的全部意义就是把坏的顶上来 */
const STATE_RANK: Record<string, number> = { down: 0, degraded: 1, unknown: 2, up: 3 }

const allDevices = computed<DeviceCard[]>(() => {
  const list = everyDevice.value.filter((c) => !hiddenDevices.value.has(c.id))
  const sorted = [...list]
  if (deviceSort.value === 'name') {
    sorted.sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'))
  } else if (deviceSort.value === 'state') {
    // 同状态内**仍然按优先级** —— 否则同为 down 的几台每次刷新顺序都在变
    sorted.sort((a, b) =>
      (STATE_RANK[a.state] ?? 9) - (STATE_RANK[b.state] ?? 9)
      || (a.order ?? 0) - (b.order ?? 0) || a.id - b.id)
  } else if (deviceSort.value === 'collected') {
    // 没采过的排最后(null 当成最久以前),而不是排最前 —— 它不是"最新的"
    sorted.sort((a, b) =>
      new Date(b.last_collected_at || 0).getTime()
      - new Date(a.last_collected_at || 0).getTime())
  } else {
    sorted.sort((a, b) => (a.order ?? 0) - (b.order ?? 0) || a.id - b.id)
  }
  return sorted
})

/**
 * 被隐藏的设备里有没有**正出问题**的。
 *
 * ⚠ 这是这个功能唯一危险的地方:有人把一台设备从大屏上隐藏掉,然后它坏了,
 * 而大屏上一点痕迹都没有。所以隐藏了多少台要一直写着,**其中有问题的那几台
 * 要点名**。事件页和告警推送本来就不受这个开关影响,但大屏是最常被盯的
 * 那一块,不能让它骗人。
 */
const hiddenSummary = computed(() => {
  const hidden = everyDevice.value.filter((c) => hiddenDevices.value.has(c.id))
  const bad = hidden.filter((c) => c.state === 'down' || c.state === 'degraded'
    || (c.open_events ?? 0) > 0)
  return { count: hidden.length, bad }
})

/** 调度迟到 —— 图上的点变稀是因为这个,不是线路的问题。 */
const schedulerWarning = computed(() => {
  const s = overview.data.value?.scheduler
  if (!s || s.error) return s?.error ? `调度状态未知:${s.error}` : ''
  const overdue = (s.probe?.overdue || 0) + (s.device?.overdue || 0)
  return overdue > 0 ? `${overdue} 个采集任务已迟到,worker 可能不够` : ''
})
</script>

<template>
  <div class="dash">
    <!-- ============ 顶部统计 ============ -->
    <section class="top-bar">
      <div class="top-head">
        <div class="top-title cy-display">
          事件统计
          <span class="win-note">{{ WINDOW_OPTIONS.find((o) => o.value === windowHours)?.label }}</span>
        </div>
        <div class="top-actions">
          <NSelect
            v-model:value="windowHours" :options="WINDOW_OPTIONS" size="small"
            style="width: 132px" @update:value="overview.refresh()"
          />
          <span class="refresh-note" :class="{ stale: overview.isStale() }">
            {{ overview.error.value ? `刷新失败:${overview.error.value}` : `更新于 ${ago(overview.lastSuccess.value)}` }}
          </span>
        </div>
      </div>

      <!-- 需求:断线、丢包、异常、延迟、抖动 等次数都要在最上面显示 -->
      <div class="tiles">
        <StatTile
          v-for="tile in overview.data.value?.tiles || []"
          :key="tile.kind"
          :label="tile.label"
          :value="tile.count"
          unit="次"
          :color="TILE_COLORS[tile.kind]"
          :foot="tile.open > 0 ? `当前 ${tile.open} 条未恢复` : '全部已恢复'"
        />
        <StatTile
          label="线路可用率"
          :value="overview.data.value?.probes.availability ?? null"
          unit="%"
          :color="STATE.up"
          :dim-zero="false"
          :foot="`累计检测 ${int(overview.data.value?.probes.total_checks)} 次`"
        />
      </div>

      <!-- 第二排:当前状态分布 -->
      <div class="strip">
        <div class="strip-item">
          <span class="k">线路</span>
          <span class="v cy-mono">{{ overview.data.value?.probes.total ?? '—' }}</span>
          <span class="chips">
            <i class="chip" :style="{ '--c': STATE.up }">正常 {{ overview.data.value?.probes.up ?? 0 }}</i>
            <i class="chip" :style="{ '--c': STATE.degraded }">劣化 {{ overview.data.value?.probes.degraded ?? 0 }}</i>
            <i class="chip" :style="{ '--c': STATE.down }">中断 {{ overview.data.value?.probes.down ?? 0 }}</i>
            <i v-if="overview.data.value?.probes.unknown" class="chip" :style="{ '--c': STATE.unknown }">
              未知 {{ overview.data.value?.probes.unknown }}
            </i>
          </span>
        </div>
        <div class="strip-item">
          <span class="k">设备</span>
          <span class="v cy-mono">{{ overview.data.value?.devices.total ?? '—' }}</span>
          <span class="chips">
            <i class="chip" :style="{ '--c': STATE.up }">交换机 {{ overview.data.value?.devices.switches ?? 0 }}</i>
            <i class="chip" :style="{ '--c': 'var(--cy-violet)' }">防火墙 {{ overview.data.value?.devices.firewalls ?? 0 }}</i>
            <i v-if="overview.data.value?.devices.down" class="chip" :style="{ '--c': STATE.down }">
              失联 {{ overview.data.value?.devices.down }}
            </i>
          </span>
        </div>
        <div class="strip-item">
          <span class="k">服务器</span>
          <span class="v cy-mono">{{ overview.data.value?.servers.total ?? '—' }}</span>
          <span class="chips">
            <i class="chip" :style="{ '--c': STATE.up }">正常 {{ overview.data.value?.servers.up ?? 0 }}</i>
            <i v-if="overview.data.value?.servers.degraded" class="chip" :style="{ '--c': STATE.degraded }">
              劣化 {{ overview.data.value?.servers.degraded }}
            </i>
            <i v-if="overview.data.value?.servers.down" class="chip" :style="{ '--c': STATE.down }">
              失联 {{ overview.data.value?.servers.down }}
            </i>
            <RouterLink to="/servers" class="chip-link">明细 →</RouterLink>
          </span>
        </div>
        <div class="strip-item">
          <span class="k">事件</span>
          <span class="v cy-mono">{{ overview.data.value?.events.total ?? '—' }}</span>
          <span class="chips">
            <i class="chip" :style="{ '--c': STATE.down }">
              未恢复 {{ overview.data.value?.events.open ?? 0 }}
            </i>
            <i class="chip" :style="{ '--c': 'var(--cy-magenta)' }">
              严重 {{ overview.data.value?.events.critical_open ?? 0 }}
            </i>
            <i class="chip" :style="{ '--c': STATE.unknown }">
              设备侧 {{ overview.data.value?.events.device_total ?? 0 }}
            </i>
          </span>
        </div>
        <div v-if="schedulerWarning" class="sched-warn">⚠ {{ schedulerWarning }}</div>
        <!-- **一个悄悄坏掉的备份等于没有备份**,而这件事没有任何别的症状:
             页面照常打开、版本列表照常有内容,只是最新那个版本是三个月前的。
             所以它必须在大屏上占一行 -->
        <RouterLink
          v-if="overview.data.value?.backup.failed"
          to="/backups"
          class="sched-warn as-link"
        >
          ⚠ {{ overview.data.value.backup.failed }} 台设备的配置备份失败 —— 点这里看原因
        </RouterLink>
      </div>
    </section>

    <!-- ============ 一个监控类一个大图 ============ -->
    <section class="charts-head">
      <div class="cy-panel-title">线路监控图表</div>
      <div class="charts-actions">
        <NButtonGroup size="small">
          <NButton
            v-for="opt in METRIC_OPTIONS" :key="opt.value"
            :type="metric === opt.value ? 'primary' : 'default'"
            ghost @click="metric = opt.value"
          >
            {{ opt.label }}
          </NButton>
        </NButtonGroup>
        <NSelect
          v-model:value="chartMinutes" :options="SPAN_OPTIONS" size="small"
          style="width: 108px" @update:value="charts.refresh()"
        />
        <NTooltip>
          <template #trigger>
            <NButton size="small" ghost @click="charts.toggle()">
              {{ charts.paused.value ? '继续' : '暂停' }}
            </NButton>
          </template>
          暂停自动刷新,方便细看某个时间段
        </NTooltip>
      </div>
    </section>

    <div v-if="!charts.data.value?.groups.length && !charts.loading.value" class="cy-panel">
      <div class="cy-empty">
        还没有配置检测线路。到<b>配置中心</b>新建监控类和线路,大图会按监控类自动分块。
      </div>
    </div>

    <CyberPanel
      v-for="block in charts.data.value?.groups || []"
      :key="block.group.id"
      :title="block.group.name"
      :subtitle="`${block.summary.total} 条线路 · ${block.granularity === 'raw' ? '原始采样' : block.granularity + ' 聚合'}${block.summary.truncated ? ' · 仅显示前 12 条' : ''}`"
      :live="!charts.paused.value"
      :level="groupLevel(block.summary)"
      class="chart-panel"
    >
      <template #actions>
        <span v-if="block.summary.down" class="badge" :style="{ '--c': STATE.down }">
          {{ block.summary.down }} 条中断
        </span>
        <span v-if="block.summary.degraded" class="badge" :style="{ '--c': STATE.degraded }">
          {{ block.summary.degraded }} 条劣化
        </span>
        <span v-if="block.group.description" class="cy-panel-sub">{{ block.group.description }}</span>
      </template>

      <div class="chart-layout">
        <GroupChart :data="block" :metric="metric" :height="288" />

        <!-- 图右侧的线路清单:大图看趋势,清单看当前值 -->
        <div class="line-list">
          <div
            v-for="line in block.lines" :key="line.id"
            class="line-item" :class="{ bad: line.state === 'down' }"
          >
            <div class="line-l">
              <StateDot :state="line.state" />
              <div class="line-meta">
                <div class="line-name">
                  <!-- 优先级角标。**数字小的排在前面** —— 这一屏的顺序就是
                       按它排的,标出来才能回答"为什么这条在最上面" -->
                  <span class="prio" title="优先级(数字小的排在前面)">{{ line.order }}</span>
                  {{ line.name }}
                </div>
                <div class="line-host cy-mono">{{ endpoint(line.host, line.protocol, line.port) }}</div>
              </div>
            </div>
            <div class="line-r">
              <div class="line-nums">
                <span class="n cy-mono" :style="{ color: stateColor(line.state) }">{{ ms(line.last_rtt) }}</span>
                <span class="sub cy-mono">丢 {{ pct(line.last_loss, 0) }} · 抖 {{ ms(line.last_jitter) }}</span>
              </div>
              <Sparkline
                :values="line.series.slice(-40).map((p) => p[metric])"
                :color="stateColor(line.state)"
                :height="22"
              />
            </div>
            <div v-if="line.last_error" class="line-err" :title="line.last_error">
              {{ line.last_error }}
            </div>
          </div>
        </div>
      </div>
    </CyberPanel>

    <!-- ============ 设备 ============ -->
    <section v-if="everyDevice.length" class="charts-head">
      <div class="cy-panel-title">交换机 / 防火墙</div>
      <div class="charts-actions">
        <NSelect
          v-model:value="deviceSort" :options="SORT_OPTIONS" size="small"
          style="width: 168px"
        />
        <NButton size="small" ghost @click="pickerOpen = !pickerOpen">
          选择设备({{ allDevices.length }}/{{ everyDevice.length }})
        </NButton>
      </div>
      <span class="refresh-note" :class="{ stale: devices.isStale(60000) }">
        更新于 {{ ago(devices.lastSuccess.value) }}
      </span>
    </section>

    <!-- 选择框。**隐藏 ≠ 停止监控** —— 这句话必须在这儿,
         不写的话一定会有人用隐藏来"关掉"一台设备 -->
    <div v-if="pickerOpen" class="picker">
      <div class="picker-note">
        勾掉的设备<b>只是这一屏不画它</b> —— 它照样在采、照样开事件、照样推告警。
        要真的停,是<b>配置中心</b>里那个「启用」开关。<br>
        <span class="dim">
          这个选择<b>只存在这台浏览器里</b>:挂在墙上的大屏和你工位上的页面
          要看的东西不一样,存到服务器上的话两边会互相覆盖。
        </span>
      </div>
      <div class="picker-grid">
        <label v-for="c in everyDevice" :key="c.id" class="pick">
          <NCheckbox
            :checked="!hiddenDevices.has(c.id)"
            @update:checked="() => toggleDevice(c.id)"
          />
          <StateDot :state="c.state" />
          <span class="pick-name">{{ c.order }} · {{ c.name }}</span>
          <span class="dim small">{{ c.model_label }}</span>
        </label>
      </div>
      <div class="picker-foot">
        <NButton size="tiny" ghost @click="showAllDevices">全部显示</NButton>
      </div>
    </div>

    <!-- ⚠ **被隐藏的设备里有正出问题的,必须点名。**有人把一台设备藏掉、
         然后它坏了,而大屏上一点痕迹都没有 —— 那是这个功能唯一危险的地方 -->
    <div v-if="hiddenSummary.count" class="hidden-note" :class="{ bad: hiddenSummary.bad.length }">
      <template v-if="hiddenSummary.bad.length">
        ⚠ 隐藏了 {{ hiddenSummary.count }} 台,
        <b>其中 {{ hiddenSummary.bad.length }} 台正有问题</b>:
        <b>{{ hiddenSummary.bad.map((c) => c.name).join('、') }}</b>
        —— 它们没有停止监控,只是这一屏没画。
      </template>
      <template v-else>
        隐藏了 {{ hiddenSummary.count }} 台(都正常)。
      </template>
      <button class="linkish" @click="showAllDevices">全部显示</button>
    </div>

    <div class="dev-grid">
      <CyberPanel
        v-for="card in allDevices" :key="card.id"
        :title="`${card.order} · ${card.name}`"
        :subtitle="card.model_label"
        :level="card.state === 'down' ? 'critical' : card.state === 'degraded' ? 'warning' : 'normal'"
        :live="false"
      >
        <template #actions>
          <StateDot :state="card.state" label />
        </template>

        <div class="dev-id">
          <span class="cy-mono">{{ card.mgmt_ip }}</span>
          <span class="sep">·</span>
          <span>{{ card.kind === 'firewall' ? '防火墙' : card.kind === 'switch' ? '交换机' : '设备' }}</span>
          <span v-if="card.os_version" class="sep">·</span>
          <span v-if="card.os_version" class="cy-mono ver">{{ card.os_version }}</span>
          <span class="sep">·</span>
          <span class="method">{{ card.method.toUpperCase() }}</span>
        </div>

        <DeviceTrend :card="card" />

        <!-- 防火墙特有:会话数 -->
        <div v-if="card.sessions !== null" class="sessions">
          <MeterBar
            label="并发会话"
            :value="card.sessions"
            :max="card.thresholds.session_warn || card.sessions * 1.5 || 100"
            :warn="card.thresholds.session_warn"
            :show-value="false"
          />
          <span class="sess-num cy-mono">{{ int(card.sessions) }}</span>
        </div>

        <!-- 接口 Top -->
        <div v-if="card.interfaces.length" class="ifaces">
          <div class="ifaces-head">活动接口</div>
          <div v-for="iface in card.interfaces" :key="iface.name" class="iface">
            <span class="if-name cy-mono" :title="iface.alias">{{ iface.name }}</span>
            <span class="if-rate cy-mono">
              ↓{{ bps(iface.in_bps) }} <span class="dim">/</span> ↑{{ bps(iface.out_bps) }}
            </span>
            <span
              v-if="iface.util_in !== null" class="if-util cy-mono"
              :style="{ color: iface.util_in! > 80 ? STATE.down : iface.util_in! > 60 ? STATE.degraded : 'var(--cy-ink-3)' }"
            >{{ pct(Math.max(iface.util_in || 0, iface.util_out || 0), 0) }}</span>
            <span v-if="iface.errors > 0" class="if-err">错包 {{ iface.errors }}</span>
          </div>
        </div>

        <div class="dev-foot">
          <span>{{ card.last_collected_at ? `采集于 ${timeOf(card.last_collected_at)}` : '尚未采集' }}</span>
          <span v-if="card.open_events" class="badge" :style="{ '--c': STATE.down }">
            {{ card.open_events }} 条未恢复
          </span>
        </div>
        <div v-if="card.last_error" class="dev-err">{{ card.last_error }}</div>
      </CyberPanel>
    </div>

    <!-- ============ SD-WAN SLA ============ -->
    <section v-if="everySdwanLink.length" class="charts-head">
      <div class="cy-panel-title">
        SD-WAN SLA
        <!-- **这一块和上面那些线路测的不是同一段** —— 不写的话两个数
             对不上时人会以为其中一个坏了 -->
        <span class="sub-note">防火墙自己从出口探的,和上面的线路拨测不是同一段</span>
      </div>
      <div class="charts-actions">
        <NButtonGroup size="small">
          <NButton
            v-for="opt in SDWAN_METRIC_OPTIONS" :key="opt.value"
            :type="sdwanMetric === opt.value ? 'primary' : 'default'"
            ghost @click="sdwanMetric = opt.value as 'latency' | 'jitter' | 'loss'"
          >{{ opt.label }}</NButton>
        </NButtonGroup>
        <NButton size="small" ghost @click="sdwanPickerOpen = !sdwanPickerOpen">
          选择链路({{ sdwanLinks.length }}/{{ everySdwanLink.length }})
        </NButton>
        <RouterLink to="/sdwan" class="more-link">明细 →</RouterLink>
      </div>
      <span class="refresh-note" :class="{ stale: sdwan.isStale(120000) }">
        更新于 {{ ago(sdwan.lastSuccess.value) }}
      </span>
    </section>

    <div v-if="sdwanPickerOpen" class="picker">
      <div class="picker-note">
        勾掉的链路<b>只是这一屏不画它</b> —— 采集和告警都不受影响。
        <span class="dim">同样只存在这台浏览器里。</span>
      </div>
      <div class="picker-grid">
        <label v-for="l in everySdwanLink" :key="l.id" class="pick">
          <NCheckbox
            :checked="!hiddenSdwan.has(l.id)"
            @update:checked="() => toggleSdwan(l.id)"
          />
          <i class="sd-dot" :style="{ background: l.state === 'alive'
            ? (l.sla_met === false ? STATE.degraded : STATE.up) : STATE.down }"></i>
          <span class="pick-name">{{ l.device_name }} · {{ l.member }}</span>
          <span class="dim small">{{ l.health_check }}</span>
        </label>
      </div>
      <div class="picker-foot">
        <NButton size="tiny" ghost @click="showAllSdwan">全部显示</NButton>
      </div>
    </div>

    <div
      v-if="hiddenSdwanSummary.count" class="hidden-note"
      :class="{ bad: hiddenSdwanSummary.bad.length }"
    >
      <template v-if="hiddenSdwanSummary.bad.length">
        ⚠ 隐藏了 {{ hiddenSdwanSummary.count }} 条链路,
        <b>其中 {{ hiddenSdwanSummary.bad.length }} 条有问题</b>:
        <b>{{ hiddenSdwanSummary.bad.map((l) => `${l.device_name}/${l.member}`).join('、') }}</b>
      </template>
      <template v-else>隐藏了 {{ hiddenSdwanSummary.count }} 条链路(都正常)。</template>
      <button class="linkish" @click="showAllSdwan">全部显示</button>
    </div>

    <CyberPanel
      v-for="blk in sdwanBlocks" :key="blk.key"
      :title="blk.check"
      :subtitle="`${blk.device} · ${blk.protocol.toUpperCase()} ${blk.server} · ${blk.rows.length} 个出口`"
      :level="blk.down.length ? 'critical' : blk.bad.length ? 'warning' : 'normal'"
      :live="!sdwan.paused.value"
    >
      <template #actions>
        <!-- **断了多久**直接写在标题栏上 —— "有一条断了"回答不了
             "要不要现在冲过去","已断 2小时13分"可以 -->
        <span v-for="d in blk.down" :key="d.id" class="sd-down">
          {{ d.member }} {{ downFor(d) }}
        </span>
        <span v-if="!blk.down.length && blk.bad.length" class="sd-warn">
          {{ blk.bad.map((x) => x.member).join('、') }} SLA 未达标
        </span>
      </template>

      <div class="sd-body">
        <!-- 左:每个出口一行当前读数 -->
        <div class="sd-list">
          <div
            v-for="l in blk.rows" :key="l.id"
            class="sd-row" :class="{ bad: l.state === 'dead' || l.sla_met === false }"
          >
            <i class="sd-dot" :style="{ background: l.state === 'dead' ? STATE.down
              : l.sla_met === false ? STATE.degraded : STATE.up }"></i>
            <span class="sd-member cy-mono">{{ l.member }}</span>
            <span class="sd-vals cy-mono">
              {{ ms(l.latency_ms) }}
              <span class="dim">/</span> {{ ms(l.jitter_ms) }}
              <span class="dim">/</span> {{ pct(l.loss_pct, 1) }}
            </span>
            <!-- 三态照旧:sla_met 为 null 说"设备没报",不说"达标" -->
            <span
              class="sd-sla"
              :style="{ color: l.sla_met === false ? STATE.down
                : l.sla_met === true ? STATE.up : STATE.unknown }"
            >{{ l.sla_text }}</span>
          </div>
          <div class="sd-legend dim">延迟 / 抖动 / 丢包</div>
        </div>

        <!-- 右:曲线。**和线路大图同一套规矩** —— 断线画红竖带、
             时间不连续处断开、SLA 门限画虚线 -->
        <div class="sd-chart">
          <SdwanChart :links="blk.rows" :metric="sdwanMetric" :height="176" />
        </div>
      </div>
    </CyberPanel>
  </div>
</template>

<style scoped>
/* 优先级角标:小、暗、等宽 —— 它是"为什么这条排在这里"的答案,
   不是要盯着看的数据。做得显眼会和状态色抢注意力 */
.prio {
  display: inline-block;
  min-width: 16px;
  padding: 0 3px;
  margin-right: 5px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 9.5px;
  line-height: 1.5;
  text-align: center;
  color: var(--cy-ink-3);
  border: 1px solid var(--cy-line-soft);
  vertical-align: middle;
}

.dash { display: flex; flex-direction: column; gap: 16px; }

/* ---- 选择框 ---- */
.picker {
  border: 1px solid var(--cy-line-soft);
  background: rgba(var(--cy-raised-rgb), 0.5);
  padding: 9px 12px;
}
.picker-note {
  font-size: 11.5px; line-height: 1.65; color: var(--cy-ink-2);
  padding-bottom: 8px; margin-bottom: 8px;
  border-bottom: 1px solid var(--cy-line-soft);
}
.picker-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 3px 14px; max-height: 240px; overflow-y: auto;
}
.pick { display: flex; align-items: center; gap: 6px; font-size: 11.5px; cursor: pointer; }
.pick-name { color: var(--cy-ink); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.picker-foot { margin-top: 8px; }
.dim { color: var(--cy-ink-3); }
.small { font-size: 10.5px; }

/* 隐藏提示。**有问题的那一档要红** —— 见模板里的注释 */
.hidden-note {
  font-size: 11.5px; line-height: 1.6; color: var(--cy-ink-3);
  padding: 5px 10px; border-left: 2px solid var(--cy-line-soft);
}
.hidden-note.bad {
  color: var(--cy-degraded);
  border-left-color: var(--cy-degraded);
  background: rgba(var(--cy-degraded-rgb), 0.07);
}
.linkish {
  background: none; border: none; padding: 0 0 0 6px;
  color: var(--cy-cyan); cursor: pointer; font-size: 11.5px; text-decoration: underline;
}
.sub-note { font-size: 10.5px; color: var(--cy-ink-3); font-weight: 400; margin-left: 8px; }
.more-link { font-size: 11px; color: var(--cy-cyan); }

/* ---- SD-WAN:左边读数、右边曲线,和线路那一段同构 ---- */
.sd-body { display: grid; grid-template-columns: minmax(240px, 340px) 1fr; gap: 14px; }
@media (max-width: 900px) {
  .sd-body { grid-template-columns: 1fr; }
}
.sd-list { display: flex; flex-direction: column; gap: 2px; }
.sd-row {
  display: grid;
  grid-template-columns: 10px minmax(58px, auto) 1fr auto;
  align-items: center; gap: 8px;
  font-size: 11.5px; padding: 3px 6px;
  border-left: 2px solid transparent;
}
/* 有问题的那一行标出来 —— 一个检查下四五个出口,靠某个数字的颜色扫不过来 */
.sd-row.bad {
  border-left-color: var(--cy-down);
  background: rgba(var(--cy-down-rgb), 0.06);
}
.sd-dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }
.sd-member { color: var(--cy-ink); font-size: 12px; }
.sd-vals { color: var(--cy-ink-2); }
.sd-sla { font-size: 10.5px; white-space: nowrap; }
.sd-legend { font-size: 9.5px; padding: 3px 6px 0 26px; }
.sd-chart { min-width: 0; }
.sd-down {
  font-size: 10.5px; color: var(--cy-down);
  border: 1px solid var(--cy-down); padding: 0 6px;
}
.sd-warn { font-size: 10.5px; color: var(--cy-degraded); }

/* ---- 顶部 ---- */
.top-bar {
  background: linear-gradient(150deg, rgba(var(--cy-raised-rgb), 0.7), rgba(var(--cy-body-rgb), 0.85));
  border: 1px solid rgba(var(--cy-cyan-rgb), 0.13);
  border-top: 2px solid rgba(var(--cy-cyan-rgb), 0.5);
  padding: 13px 16px 14px;
  clip-path: polygon(0 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%);
}
.top-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.top-title {
  font-size: 14px;
  letter-spacing: 0.14em;
  color: var(--cy-ink);
  text-transform: uppercase;
  display: flex;
  align-items: baseline;
  gap: 10px;
}
.win-note {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  letter-spacing: 0.04em;
  color: var(--cy-ink-3);
  text-transform: none;
}
.top-actions { display: flex; align-items: center; gap: 12px; }
.refresh-note {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--cy-ink-3);
}
.refresh-note.stale { color: var(--cy-degraded); }

.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(158px, 1fr));
  gap: 10px;
}

.strip {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 26px;
  margin-top: 13px;
  padding-top: 12px;
  border-top: 1px solid rgba(var(--cy-cyan-rgb), 0.1);
  align-items: center;
}
.strip-item { display: flex; align-items: baseline; gap: 8px; }
.strip-item .k { font-size: 11px; color: var(--cy-ink-3); letter-spacing: 0.1em; }
.strip-item .v { font-size: 18px; font-weight: 700; color: var(--cy-ink); }
.chips { display: flex; gap: 6px; flex-wrap: wrap; }
.chip {
  font-size: 11px;
  font-style: normal;
  padding: 1px 6px;
  color: var(--c);
  border: 1px solid color-mix(in srgb, var(--c) 34%, transparent);
  background: color-mix(in srgb, var(--c) 9%, transparent);
}
.chip-link {
  font-size: 10.5px;
  color: var(--cy-cyan);
  text-decoration: none;
  letter-spacing: 0.04em;
}
.chip-link:hover { text-decoration: underline; }

.sched-warn.as-link {
  text-decoration: none;
  display: block;
  transition: background 0.15s ease;
}
.sched-warn.as-link:hover { background: rgba(var(--cy-degraded-rgb), 0.12); }

.sched-warn {
  font-size: 11px;
  color: var(--cy-degraded);
  margin-left: auto;
  font-family: 'JetBrains Mono', monospace;
}

/* ---- 图表区 ---- */
.charts-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-top: 4px;
  flex-wrap: wrap;
}
.charts-actions { display: flex; align-items: center; gap: 10px; }
.chart-panel { min-width: 0; }
.chart-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 316px;
  gap: 16px;
}
@media (max-width: 1180px) {
  .chart-layout { grid-template-columns: minmax(0, 1fr); }
}

.badge {
  font-size: 11px;
  padding: 1px 7px;
  color: var(--c);
  border: 1px solid color-mix(in srgb, var(--c) 40%, transparent);
  background: color-mix(in srgb, var(--c) 11%, transparent);
  white-space: nowrap;
}

/* ---- 线路清单 ---- */
.line-list {
  display: flex;
  flex-direction: column;
  gap: 1px;
  max-height: 288px;
  overflow-y: auto;
  padding-right: 2px;
}
.line-item {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 132px;
  gap: 10px;
  align-items: center;
  padding: 6px 8px;
  background: rgba(var(--cy-ink-rgb), 0.018);
  border-left: 2px solid transparent;
}
.line-item.bad {
  border-left-color: var(--cy-down);
  background: rgba(var(--cy-down-rgb), 0.055);
}
.line-l { display: flex; align-items: center; gap: 8px; min-width: 0; }
.line-meta { min-width: 0; }
.line-name {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--cy-ink);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.line-host {
  font-size: 10.5px;
  color: var(--cy-ink-3);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.line-r { display: flex; flex-direction: column; gap: 2px; }
.line-nums { display: flex; align-items: baseline; justify-content: space-between; gap: 6px; }
.line-nums .n { font-size: 13px; font-weight: 700; }
.line-nums .sub { font-size: 9.5px; color: var(--cy-ink-3); }
.line-err {
  grid-column: 1 / -1;
  font-size: 10.5px;
  color: var(--cy-down);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  font-family: 'JetBrains Mono', monospace;
}

/* ---- 设备 ---- */
.dev-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(370px, 1fr));
  gap: 14px;
}
.dev-id {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  font-size: 11.5px;
  color: var(--cy-ink-2);
  margin-bottom: 12px;
  padding-bottom: 9px;
  border-bottom: 1px solid rgba(var(--cy-cyan-rgb), 0.08);
}
.dev-id .sep { color: var(--cy-ink-3); }
.dev-id .ver { color: var(--cy-ink-3); }
.dev-id .method {
  font-size: 10px;
  letter-spacing: 0.08em;
  padding: 0 5px;
  color: var(--cy-cyan);
  border: 1px solid rgba(var(--cy-cyan-rgb), 0.3);
}

.sessions {
  display: flex;
  align-items: flex-end;
  gap: 10px;
  margin-top: 13px;
}
.sessions > :first-child { flex: 1; }
.sess-num { font-size: 14px; font-weight: 700; color: var(--cy-violet); white-space: nowrap; }

.ifaces {
  margin-top: 13px;
  padding-top: 10px;
  border-top: 1px solid rgba(var(--cy-cyan-rgb), 0.08);
}
.ifaces-head {
  font-size: 10.5px;
  letter-spacing: 0.12em;
  color: var(--cy-ink-3);
  text-transform: uppercase;
  margin-bottom: 6px;
}
.iface {
  display: grid;
  grid-template-columns: 96px minmax(0, 1fr) 42px;
  gap: 8px;
  align-items: center;
  font-size: 10.5px;
  padding: 2px 0;
}
.if-name { color: var(--cy-ink-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.if-rate { color: var(--cy-ink); text-align: right; }
.if-rate .dim { color: var(--cy-ink-3); }
.if-util { text-align: right; font-weight: 600; }
.if-err { grid-column: 1 / -1; color: var(--cy-degraded); font-size: 10px; }

.dev-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-top: 13px;
  padding-top: 9px;
  border-top: 1px solid rgba(var(--cy-cyan-rgb), 0.08);
  font-size: 10.5px;
  color: var(--cy-ink-3);
  font-family: 'JetBrains Mono', monospace;
}
.dev-err {
  margin-top: 6px;
  font-size: 10.5px;
  color: var(--cy-down);
  font-family: 'JetBrains Mono', monospace;
  word-break: break-all;
}
</style>
