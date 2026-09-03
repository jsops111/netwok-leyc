<script setup lang="ts">
import { computed, h, ref } from 'vue'
import {
  NButton, NButtonGroup, NDataTable, NSelect, NSwitch, NTag, NTooltip, useMessage,
} from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import StateDot from '@/components/cyber/StateDot.vue'
import SdwanChart from '@/components/charts/SdwanChart.vue'
import { api } from '@/api'
import type { SdwanLinkRow } from '@/api'
import { usePolling } from '@/composables/usePolling'
import { ago, bps, dateTimeOf, int, ms, num, pct } from '@/composables/useFormat'
import { STATE } from '@/theme'

/**
 * SD-WAN 性能 SLA。
 *
 * ## ⚠ 它和大屏上那些延迟测的**不是同一段**
 *
 * `/`(监控大屏)的 latency / loss / jitter 是**这个平台自己**从部署点
 * 探出来的;这一页是**防火墙自己**从它的出口探出来的
 * (FortiOS 的 health-check,默认 500ms 一拍,比平台快得多)。
 *
 * 同一条运营商线路,两边测出来的数**不一样是正常的** —— 路径不同。
 * 而两边都有才分得清:
 *
 *   防火墙侧正常、平台侧不通  → 我们到防火墙这一段的问题
 *   两边都不通              → 那条线路真的断了
 *
 * **所以这一页不是拨测的替代,是另一个视角。**这句话写在页面顶部,
 * 不然两个数对不上的时候人会以为其中一个坏了。
 *
 * ## 达标判定以设备为准
 *
 * FortiOS 允许一个健康检查配**多档 SLA**,选路按档走 —— 它比我们更清楚
 * 它按哪一档选路,所以"达标没达标"以 `sla_met` 为准,平台不重算。
 * 平台自己那两个门限是给"设备说达标但数字已经很难看"准备的
 * (FortiOS 的门限常常配得很松),页面上会标明那是**平台的线不是设备的**。
 *
 * ## 三态
 *
 * `sla_met` 为 `null` 是**设备没报**,不是"达标"。显示成达标就是替设备
 * 做一个它没做的判断 —— 和「命中计数三态」「unknown 不是绿色」同一条。
 */

const message = useMessage()
const hours = ref(6)
const problemOnly = ref(false)

const board = usePolling(
  () => api.sdwanBoard(hours.value).then((r) => r.data), 30_000)
const data = computed(() => board.data.value)
const totals = computed(() => data.value?.totals ?? null)

const HOUR_OPTIONS = [
  { label: '近 1 小时', value: 1 },
  { label: '近 6 小时', value: 6 },
  { label: '近 24 小时', value: 24 },
  { label: '近 7 天', value: 168 },
]

const shownDevices = computed(() => {
  const list = data.value?.devices ?? []
  if (!problemOnly.value) return list
  return list
    .map((d) => ({ ...d, links: d.links.filter(isProblem) }))
    .filter((d) => d.links.length)
})

/**
 * 这条链路有问题吗。**`sla_met === null` 不算有问题** ——
 * 那是"设备没报判定",不是"未达标"。算进去的话一台没配 SLA 目标的
 * 防火墙会整页飘红。
 */
function isProblem(link: SdwanLinkRow): boolean {
  return link.state === 'dead' || link.sla_met === false
}

/**
 * 这条链路断了多久。
 *
 * `last_change` 是**状态变化那一刻**的时间戳(采集器在状态翻转时写的)。
 * 所以"断了多久"= 现在 - last_change,前提是它现在是 dead。
 *
 * ⚠ **`last_change` 为空时说"不知道多久",不说"刚断"** ——
 * 采集器是在**看到状态变化**时才写这个字段的,而一条从加进来就一直断着
 * 的链路从没"变化"过,它的 last_change 是空的。显示成"刚断 0 分钟"
 * 会让人以为刚出的事,从而去查一个错误的时间窗。
 */
function downFor(link: SdwanLinkRow): string {
  if (link.state !== 'dead') return ''
  if (!link.last_change) return '不知道断了多久(从没观测到状态变化)'
  const secs = Math.max(0, (Date.now() - new Date(link.last_change).getTime()) / 1000)
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  if (d) return `已断 ${d} 天 ${h} 小时`
  if (h) return `已断 ${h} 小时 ${m} 分`
  if (m) return `已断 ${m} 分钟`
  return '刚刚断的(不到 1 分钟)'
}

/** 按健康检查分组 —— 一个检查一张图,线 = 各个出口 */
function byCheck(links: SdwanLinkRow[]) {
  const map = new Map<string, SdwanLinkRow[]>()
  for (const l of links) {
    if (!map.has(l.health_check)) map.set(l.health_check, [])
    map.get(l.health_check)!.push(l)
  }
  return [...map.entries()].map(([name, rows]) => ({
    name,
    rows,
    // 检测服务器写在图的标题上 —— **这一页最常被问的就是"探的是哪个地址"**
    server: rows.find((r) => r.server)?.server || '设备没报',
    protocol: rows.find((r) => r.protocol)?.protocol || '',
    down: rows.filter((r) => r.state === 'dead'),
  }))
}

const metric = ref<'latency' | 'jitter' | 'loss'>('latency')
const METRIC_OPTIONS = [
  { label: '延迟', value: 'latency' },
  { label: '抖动', value: 'jitter' },
  { label: '丢包', value: 'loss' },
]

function stateColor(state: string): string {
  if (state === 'alive') return STATE.up
  if (state === 'dead') return STATE.down
  return STATE.unknown
}

/**
 * 延迟色。**没有全局阈值** —— 每台设备的门限不一样。
 * 这里只按"设备自己的判定"上色:未达标或不通就是红的,
 * 平台自己那条额外门限在告警里体现,不在这一列上色
 * (两套线在同一个格子里上色,人分不出这个红是谁判的)。
 */
function latencyColorOf(link: SdwanLinkRow): string {
  if (link.latency_ms === null) return 'var(--cy-ink-3)'
  if (link.state === 'dead' || link.sla_met === false) return STATE.down
  return 'var(--cy-ink)'
}

/**
 * 链路表的列。**顺序和标签跟 FortiGate 自己那张
 * 「网络 → SD-WAN → 性能 SLA」表对齐** —— 名称 / 检测服务器 / 成员 /
 * 丢包 / 延迟 / 抖动 / 状态。
 *
 * 这不是审美问题:同一条链路在防火墙上叫「检测服务器」、在这儿叫
 * 「探测目标」,列的顺序还反着,人在两个屏之间来回对的时候必然出错。
 * **跟着设备的说法走。**
 */
/**
 * 门限那一行小字。
 *
 * **`null` 时什么都不显示,不写"门限 0"** —— FortiOS 里门限配 0 的意思是
 * "这一档不看这个指标",显示成"门限 0ms"会让人以为要求抖动必须是 0,
 * 那是永远达不到的。后端已经把 0 折成 null 了,这里只负责不无中生有。
 */
function thrText(value: number | null, unit: string) {
  if (value === null || value === undefined) return null
  return h('div', { style: 'font-size:9.5px;color:var(--cy-ink-3)' }, `门限 ${value}${unit}`)
}

const linkColumns: DataTableColumns<SdwanLinkRow> = [
  { title: '名称', key: 'health_check', sorter: 'default', minWidth: 120,
    render: (r) => h('span', { class: 'mono' }, r.health_check) },
  // 「检测服务器」——**这一列是这一页的题眼**:健康检查探的是哪个地址
  { title: '检测服务器', key: 'server', sorter: 'default', minWidth: 130,
    render: (r) => h('span', { class: 'mono' }, r.server || '设备没报') },
  // 「出口」= FortiOS 里的 member。**这一列回答"从哪个口出去"** ——
  // 一个健康检查同时探所有出口,而 SLA 是按出口判的
  { title: '出口', key: 'member', sorter: 'default', minWidth: 110,
    render: (r) => h('span', { class: 'mono strong' }, r.member) },
  // 丢包在延迟前面 —— FortiGate 就是这个顺序,跟着设备的说法走
  { title: '丢包', key: 'loss_pct', sorter: 'default', width: 100, className: 'num',
    render: (r) => h('div', [
      h('div', {
        class: 'mono',
        style: `color:${(r.loss_pct ?? 0) >= 100 ? STATE.down
          : (r.loss_pct ?? 0) > 0 ? STATE.degraded : 'var(--cy-ink)'}`,
      }, pct(r.loss_pct, 2)),
      thrText(r.sla_loss_threshold, '%'),
    ]) },
  { title: '延迟', key: 'latency_ms', sorter: 'default', width: 104, className: 'num',
    render: (r) => h('div', [
      h('div', { class: 'mono', style: `color:${latencyColorOf(r)}` }, ms(r.latency_ms)),
      // **门限**。一条 186ms 的线算不算超,取决于设备上配的门限是 100 还是
      // 500 —— 那个数不摆在旁边的话,人得自己去防火墙翻配置
      thrText(r.sla_latency_threshold, 'ms'),
    ]) },
  { title: '抖动', key: 'jitter_ms', sorter: 'default', width: 100, className: 'num',
    render: (r) => h('div', [
      h('div', { class: 'mono' }, ms(r.jitter_ms)),
      thrText(r.sla_jitter_threshold, 'ms'),
    ]) },
  { title: '状态', key: 'state', sorter: 'default', width: 150,
    render: (r) => h('div', [
      h('div', {
        style: `font-size:11.5px;font-weight:700;color:${stateColor(r.state)}`,
      }, r.state_label),
      // **断了多久** —— "不通"三个字回答不了"要不要现在冲过去",
      // 而"已断 2 小时 13 分"可以
      r.state === 'dead'
        ? h('div', { style: `font-size:10px;color:${STATE.down}` }, downFor(r))
        : null,
    ]) },
  // SLA 达标是「性能 SLA」这个功能的**结论列**,所以留着。三态各有说法,
  // 文案由后端拼(null 说"设备没报",不是"达标")
  { title: 'SLA', key: 'sla_met', width: 148,
    sorter: (a, b) => Number(a.sla_met ?? -1) - Number(b.sla_met ?? -1),
    render: (r) => h(NTooltip, null, {
      trigger: () => h('span', {
        style: `font-size:11px;color:${
          r.sla_met === false ? STATE.down : r.sla_met === true ? STATE.up : STATE.unknown}`,
      }, r.sla_text),
      default: () => r.sla_met === null
        ? '设备没有报这一项 —— 可能没配 SLA 目标,或者这个固件不给。不等于达标'
        : '这是设备自己的判定:它比我们更清楚它按哪一档选路',
    }) },
]

// 会话数、带宽、延迟趋势、状态变化时间**不做成列**。
// 这一页要回答的是"探 8.8.8.8 走哪个口、那个口好不好",十一列摊开之后
// 那三个数反而找不到了 —— 它们挂在行的 title 上,鼠标停一下就有。

const VERDICT_TEXT: Record<string, string> = {
  ok: '全部达标',
  warn: '有链路 SLA 未达标',
  crit: '有链路不通',
  unknown: '有链路读不到状态 —— 那不等于它们是好的',
}
</script>

<template>
  <div class="sd">
    <!-- ============ 这一页测的是哪一段 ============ -->
    <!-- **必须写在最上面。**两个数对不上的时候,人会以为其中一个坏了 -->
    <div class="lead">
      这一页的延迟 / 抖动 / 丢包是<b>防火墙自己</b>从它的出口探出来的
      (FortiOS 的 health-check,默认 500ms 一拍)。
      <b>监控大屏</b>上那些是<b>这个平台自己</b>从部署点探出来的 ——
      <b>同一条线两边的数不一样是正常的</b>,路径不同。<br>
      <span class="dim">
        两边都有才分得清:防火墙侧正常而平台侧不通 = 我们到防火墙这一段的问题;
        两边都不通 = 那条线路真的断了。<b>这一页不是拨测的替代,是另一个视角。</b>
      </span>
    </div>

    <div class="head">
      <div class="tiles">
        <StatTile label="SLA 链路" :value="totals?.links ?? 0" unit="条" :dim-zero="false"
                  :foot="`${totals?.devices ?? 0} 台防火墙`" />
        <StatTile label="不通" :value="totals?.dead ?? 0" unit="条" :color="STATE.down"
                  foot="探测失败,丢包 100%" />
        <StatTile label="SLA 未达标" :value="totals?.sla_bad ?? 0" unit="条"
                  :color="STATE.degraded" foot="设备自己的判定" />
        <!-- **设备没报判定的单独一栏** —— 显示成达标就是替设备做判断 -->
        <StatTile label="设备没报判定" :value="totals?.sla_unknown ?? 0" unit="条"
                  :color="STATE.unknown" foot="没配 SLA 目标 / 固件不给这一项" />
        <StatTile label="状态读不到" :value="totals?.unknown ?? 0" unit="条"
                  :color="STATE.unknown" foot="读不到 ≠ 是好的" />
        <StatTile label="最高延迟" :value="totals?.latency_max ?? null" unit="ms"
                  :color="STATE.degraded"
                  :foot="totals?.latency_max_link || '—'" />
      </div>
      <div class="actions">
        <NButtonGroup size="small">
          <NButton
            v-for="opt in METRIC_OPTIONS" :key="opt.value"
            :type="metric === opt.value ? 'primary' : 'default'"
            ghost @click="metric = opt.value as 'latency' | 'jitter' | 'loss'"
          >{{ opt.label }}</NButton>
        </NButtonGroup>
        <NSelect v-model:value="hours" :options="HOUR_OPTIONS" size="small"
                 style="width: 128px" @update:value="board.refresh" />
        <label class="tgl">
          <NSwitch v-model:value="problemOnly" size="small" />
          <span>只看有问题的</span>
        </label>
        <label class="tgl">
          <NSwitch :value="!board.paused.value" size="small" @update:value="board.toggle" />
          <span>{{ board.paused.value ? '已暂停' : '自动刷新' }}</span>
        </label>
        <NButton size="tiny" ghost :loading="board.loading.value" @click="board.refresh">
          刷新
        </NButton>
      </div>
    </div>

    <div v-if="data" class="verdict" :style="{ color: {
      ok: STATE.up, warn: STATE.degraded, crit: STATE.down, unknown: STATE.unknown,
    }[data.verdict] }">
      <i class="dot" :style="{ background: {
        ok: STATE.up, warn: STATE.degraded, crit: STATE.down, unknown: STATE.unknown,
      }[data.verdict] }"></i>
      {{ VERDICT_TEXT[data.verdict] }}
      <span class="dim">· 数据于 {{ dateTimeOf(data.generated_at) }}</span>
    </div>

    <!-- 开了开关但没采到的设备。**"没采到"不是"没配"** -->
    <div v-if="data?.devices_without_data.length" class="warn-note">
      <b>{{ data.devices_without_data.map((d) => d.device_name).join('、') }}</b>
      开了 SD-WAN 采集但<b>一条链路都没采到</b>。这不等于它们没配 SD-WAN ——
      可能是 API 权限不够、这个固件的端点名不一样,或者真的没配。
      <div v-for="d in data.devices_without_data" :key="d.device_id" class="dim small">
        {{ d.device_name }}:{{ d.last_error || '(没有错误信息)' }}
      </div>
    </div>

    <!-- ============ 按设备分组 ============ -->
    <CyberPanel
      v-for="dev in shownDevices" :key="dev.device_id"
      :title="dev.device_name"
      :subtitle="`${dev.mgmt_ip} · ${dev.vdom} · ${dev.links.length} 条链路 · ${(dev.method || '?').toUpperCase()} 通道`"
      :level="dev.links.some((l) => l.state === 'dead') ? 'critical'
        : dev.links.some((l) => l.sla_met === false) ? 'warning' : 'normal'"
    >
      <template #actions>
        <StateDot :state="dev.state" label />
        <span class="dim small">采集于 {{ ago(dev.synced_at) }}</span>
      </template>

      <!-- SSH 通道拿不到的东西比拿得到的多,说出来 -->
      <div v-if="dev.method === 'ssh'" class="note">
        这台走的是 <b>SSH</b> 通道(<code>diagnose sys sdwan health-check</code>)——
        <b>拿不到带宽、会话数、SLA 档数总数</b>,而且那条命令的输出格式在
        FortiOS 大版本间有出入。配上 API Token 能拿全。
      </div>
      <div v-if="dev.last_error" class="err">{{ dev.last_error }}</div>

      <!-- ============ 图:一个健康检查一张 ============ -->
      <div
        v-for="ck in byCheck(dev.links)" :key="ck.name"
        class="chart-box" :class="{ bad: ck.down.length }"
      >
        <div class="chart-head">
          <b>{{ ck.name }}</b>
          <!-- **探的是哪个地址** —— 这一页最常被问的一句,放在图的标题上 -->
          <span class="probe">
            {{ ck.protocol ? ck.protocol.toUpperCase() : 'PING' }}
            <b class="mono2">{{ ck.server }}</b>
          </span>
          <span class="dim">{{ ck.rows.length }} 个出口</span>
          <!-- **断了多久**,直接写在图上 —— "有一条断了"回答不了
               "要不要现在冲过去","已断 2 小时 13 分"可以 -->
          <span v-for="d in ck.down" :key="d.id" class="down-chip">
            {{ d.member }} {{ downFor(d) }}
          </span>
        </div>
        <SdwanChart :links="ck.rows" :metric="metric" :height="200" />
      </div>

      <!-- **列和 FortiGate 自己那张 Performance SLA 表对齐**:
           名称 / 检测服务器 / 成员 / 丢包 / 延迟 / 抖动 / 状态 ——
           同一个东西在两个地方叫两个名字、排两种顺序,人对不上 -->
      <NDataTable
        :columns="linkColumns" :data="dev.links" size="small"
        :bordered="false" :single-line="false" :scroll-x="1000"
        :row-props="(r: SdwanLinkRow) => ({
          class: isProblem(r) ? 'bad-row' : '',
          title: [
            `协议 ${r.protocol || '未报'}`,
            `会话 ${int(r.session_count)}`,
            `带宽 ↓${bps(r.rx_bps)} / ↑${bps(r.tx_bps)}`,
            r.last_change ? `状态变化于 ${ago(r.last_change)}` : '',
          ].filter(Boolean).join('  ·  '),
        })"
      />

      <!-- 这台的未恢复告警 -->
      <div v-if="dev.alerts.length" class="alerts">
        <div v-for="(a, i) in dev.alerts" :key="i" class="alert">
          <b>{{ a.kind_label }}</b>{{ a.message }}
          <span class="dim">{{ ago(a.started_at) }}</span>
        </div>
      </div>

      <!-- 平台自己那两个门限 —— **说清楚不是设备的 SLA** -->
      <div v-if="dev.sla_latency_warn_ms || dev.sla_loss_warn_pct" class="note">
        这台还配了<b>平台自己的门限</b>(不是设备的 SLA):
        <template v-if="dev.sla_latency_warn_ms">延迟 ≥ {{ dev.sla_latency_warn_ms }}ms</template>
        <template v-if="dev.sla_latency_warn_ms && dev.sla_loss_warn_pct"> / </template>
        <template v-if="dev.sla_loss_warn_pct">丢包 ≥ {{ dev.sla_loss_warn_pct }}%</template>
        —— 设备说达标但数字已经很难看时也会告警。
      </div>
    </CyberPanel>

    <div v-if="data && !shownDevices.length" class="cy-empty">
      <template v-if="problemOnly">没有有问题的 SD-WAN 链路。</template>
      <template v-else>
        还没有 SD-WAN 数据。到<b>配置中心 → 网络设备</b>,给 FortiGate 打开
        <b>「采集 SD-WAN SLA」</b> —— <b>强烈建议同时配上 API Token</b>:
        <code>monitor/virtual-wan/health-check</code> 一次给全部成员的
        延迟/抖动/丢包/达标情况,而 SSH 那条命令拿不到带宽和 SLA 档数,
        输出格式在大版本间还有出入。
      </template>
    </div>
  </div>
</template>

<style scoped>
.sd { display: flex; flex-direction: column; gap: 14px; }

.lead {
  font-size: 11.5px;
  line-height: 1.75;
  color: var(--cy-ink-2);
  padding: 7px 12px;
  border-left: 2px solid var(--cy-cyan);
  background: color-mix(in srgb, var(--cy-cyan) 6%, transparent);
}
.dim { color: var(--cy-ink-3); }
.small { font-size: 10.5px; }
.sm { font-size: 11px !important; }

.head { display: flex; align-items: flex-end; justify-content: space-between; gap: 14px; flex-wrap: wrap; }
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px;
  flex: 1;
  min-width: 320px;
}
.actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.tgl { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: var(--cy-ink-2); }

.verdict { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 700; }
.verdict .dot { width: 9px; height: 9px; border-radius: 50%; }

.warn-note, .note, .err {
  font-size: 11.5px;
  line-height: 1.65;
  padding: 6px 11px;
  border-left: 2px solid;
}
.warn-note {
  color: var(--cy-degraded);
  border-left-color: var(--cy-degraded);
  background: color-mix(in srgb, var(--cy-degraded) 7%, transparent);
}
.note {
  color: var(--cy-ink-2);
  border-left-color: var(--cy-line);
  background: color-mix(in srgb, var(--cy-raised) 55%, transparent);
  margin-bottom: 10px;
}
.err {
  color: var(--cy-down);
  border-left-color: var(--cy-down);
  background: color-mix(in srgb, var(--cy-down) 6%, transparent);
  margin-bottom: 10px;
}
.note code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10.5px;
  color: var(--cy-cyan);
}

.chart-box {
  border: 1px solid var(--cy-line-soft);
  border-left: 3px solid var(--cy-line);
  padding: 8px 10px 4px;
  margin-bottom: 10px;
  background: color-mix(in srgb, var(--cy-raised) 35%, transparent);
}
/* 有出口断着的那张图整块标红 —— 一台设备下好几个健康检查时,
   靠图里那道红竖带找不过来 */
.chart-box.bad { border-left-color: var(--cy-down); }
.chart-head {
  display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap;
  font-size: 12px; color: var(--cy-ink); margin-bottom: 2px;
}
.chart-head .probe { font-size: 11px; color: var(--cy-ink-3); }
.mono2 {
  font-family: 'JetBrains Mono', monospace;
  color: var(--cy-cyan);
  font-size: 11.5px;
}
.down-chip {
  font-size: 10.5px;
  color: var(--cy-down);
  border: 1px solid var(--cy-down);
  padding: 0 6px;
}

:deep(.mono) {
  font-size: 12px;
  font-family: 'JetBrains Mono', monospace;
  color: var(--cy-ink-2);
}
:deep(.mono.strong) { color: var(--cy-ink); font-weight: 700; }
/* 有问题的行整行淡红 —— 一屏几十条链路时,靠某一格的颜色找不过来 */
:deep(.bad-row td) { background: color-mix(in srgb, var(--cy-down) 7%, transparent) !important; }



.alerts { display: flex; flex-direction: column; gap: 3px; margin-top: 10px; }
.alert {
  font-size: 11px;
  line-height: 1.6;
  color: var(--cy-ink-2);
  border-left: 2px solid var(--cy-degraded);
  padding-left: 8px;
}
.alert b { color: var(--cy-degraded); margin-right: 6px; }
</style>
