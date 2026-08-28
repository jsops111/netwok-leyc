<script setup lang="ts">
import { computed, ref } from 'vue'
import { NButton, NButtonGroup, NSelect, NTooltip } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import StateDot from '@/components/cyber/StateDot.vue'
import MeterBar from '@/components/cyber/MeterBar.vue'
import GroupChart from '@/components/charts/GroupChart.vue'
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

const allDevices = computed<DeviceCard[]>(() => {
  const d = devices.data.value
  if (!d) return []
  return [...d.switches, ...d.firewalls, ...d.others]
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
                <div class="line-name">{{ line.name }}</div>
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
    <section v-if="allDevices.length" class="charts-head">
      <div class="cy-panel-title">交换机 / 防火墙</div>
      <span class="refresh-note" :class="{ stale: devices.isStale(60000) }">
        更新于 {{ ago(devices.lastSuccess.value) }}
      </span>
    </section>

    <div class="dev-grid">
      <CyberPanel
        v-for="card in allDevices" :key="card.id"
        :title="card.name"
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
  </div>
</template>

<style scoped>
.dash { display: flex; flex-direction: column; gap: 16px; }

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
