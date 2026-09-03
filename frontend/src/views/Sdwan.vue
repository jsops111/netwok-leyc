<script setup lang="ts">
import { computed, ref } from 'vue'
import { NButton, NSelect, NSwitch, NTag, NTooltip, useMessage } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import StateDot from '@/components/cyber/StateDot.vue'
import Sparkline from '@/components/charts/Sparkline.vue'
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

function stateColor(state: string): string {
  if (state === 'alive') return STATE.up
  if (state === 'dead') return STATE.down
  return STATE.unknown
}

/** 延迟色。**没有全局阈值** —— 每台设备的门限不一样,所以按那台自己的判 */
function latencyColor(link: SdwanLinkRow, warn: number | null): string {
  if (link.latency_ms === null) return 'var(--cy-ink-3)'
  if (link.state === 'dead') return STATE.down
  if (link.sla_met === false) return STATE.down
  if (warn && link.latency_ms >= warn) return STATE.degraded
  return 'var(--cy-ink)'
}

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

      <div class="links">
        <div
          v-for="link in dev.links" :key="link.id"
          class="link" :class="{ bad: isProblem(link) }"
        >
          <div class="l-head">
            <i class="l-dot" :style="{ background: stateColor(link.state) }"></i>
            <div class="l-name">
              <div class="l-member">{{ link.member }}</div>
              <div class="l-check">{{ link.health_check }}</div>
            </div>
            <NTag size="tiny" :bordered="false" :style="{ color: stateColor(link.state) }">
              {{ link.state_label }}
            </NTag>
            <!-- 达标三态,文案由后端给 —— null 说"设备没报",不显示成达标 -->
            <NTooltip>
              <template #trigger>
                <NTag
                  size="tiny" :bordered="false"
                  :style="{ color: link.sla_met === false ? STATE.down
                    : link.sla_met === true ? STATE.up : STATE.unknown }"
                >{{ link.sla_text }}</NTag>
              </template>
              {{ link.sla_met === null
                ? '设备没有报这一项 —— 可能没配 SLA 目标,或者这个固件不给。不等于达标'
                : '这是设备自己的判定:它比我们更清楚它按哪一档选路' }}
            </NTooltip>
          </div>

          <div class="l-nums">
            <div class="n">
              <span class="n-k">延迟</span>
              <b :style="{ color: latencyColor(link, dev.sla_latency_warn_ms) }">
                {{ ms(link.latency_ms) }}
              </b>
            </div>
            <div class="n">
              <span class="n-k">抖动</span>
              <b>{{ ms(link.jitter_ms) }}</b>
            </div>
            <div class="n">
              <span class="n-k">丢包</span>
              <b :style="{ color: (link.loss_pct ?? 0) > 0 ? STATE.degraded : 'var(--cy-ink)' }">
                {{ pct(link.loss_pct, 1) }}
              </b>
            </div>
            <div class="n">
              <span class="n-k">会话</span>
              <!-- SSH 通道拿不到 → null,显示 — 而不是 0 -->
              <b>{{ int(link.session_count) }}</b>
            </div>
            <div class="n">
              <span class="n-k">带宽 ↓/↑</span>
              <b class="sm">{{ bps(link.rx_bps) }} / {{ bps(link.tx_bps) }}</b>
            </div>
          </div>

          <!-- 延迟趋势。**手写 SVG 的 Sparkline** —— 一屏几十条链路,
               每条 init 一个 echarts 会让首屏卡好几秒 -->
          <Sparkline
            v-if="link.series?.length"
            :values="link.series.map((p) => p.latency)"
            :color="isProblem(link) ? STATE.down : 'var(--cy-cat-1)'"
            :height="26"
          />
          <div v-else class="dim small">这段时间没有采样</div>

          <div class="l-foot">
            <span class="dim">
              {{ link.server ? `探测目标 ${link.server}` : '探测目标未报' }}
              {{ link.protocol ? ` · ${link.protocol}` : '' }}
            </span>
            <span v-if="link.last_change" class="dim">
              状态变化于 {{ ago(link.last_change) }}
            </span>
          </div>
        </div>
      </div>

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

.links {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 10px;
}
.link {
  border: 1px solid var(--cy-line-soft);
  border-left: 3px solid var(--cy-line);
  padding: 8px 10px;
  display: flex;
  flex-direction: column;
  gap: 6px;
  background: color-mix(in srgb, var(--cy-raised) 40%, transparent);
}
.link.bad { border-left-color: var(--cy-down); }

.l-head { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; }
.l-dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }
.l-name { flex: 1; min-width: 0; }
.l-member {
  font-size: 12.5px;
  color: var(--cy-ink);
  font-family: 'JetBrains Mono', monospace;
}
.l-check { font-size: 10px; color: var(--cy-ink-3); }

.l-nums { display: grid; grid-template-columns: repeat(5, 1fr); gap: 5px; }
.n { display: flex; flex-direction: column; gap: 1px; }
.n-k { font-size: 9.5px; color: var(--cy-ink-3); }
.n b {
  font-size: 13px;
  font-family: 'JetBrains Mono', monospace;
  color: var(--cy-ink);
}

.l-foot {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  font-size: 10px;
  border-top: 1px solid var(--cy-line-soft);
  padding-top: 5px;
  flex-wrap: wrap;
}

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
