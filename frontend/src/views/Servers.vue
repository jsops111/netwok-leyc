<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { NButton, NButtonGroup, NSelect, NTag, useMessage } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import StateDot from '@/components/cyber/StateDot.vue'
import MeterBar from '@/components/cyber/MeterBar.vue'
import ServerChart from '@/components/charts/ServerChart.vue'
import type { ServerMetric } from '@/components/charts/ServerChart.vue'
import Sparkline from '@/components/charts/Sparkline.vue'
import { api, errText } from '@/api'
import type { ServerCard, ServerDetail } from '@/api'
import { usePolling } from '@/composables/usePolling'
import { ago, bps, bytes, int, num, pct, timeOf, uptime } from '@/composables/useFormat'
import { STATE, valueColor } from '@/theme'

/**
 * 服务器监控页。
 *
 * 一台服务器一块面板:左边**基本信息 + 四个指标条**,右边**趋势图**
 * (流量 / CPU / 内存 / 负载 切换)。展开后还能看挂载点明细、网卡列表、
 * 进程 Top。
 *
 * **一次刷新只打一个接口**(`/dashboard/servers/`)—— 和大屏同一条规矩:
 * 别改成每台一个请求,几十台 × 每 20 秒会把 gunicorn 打满。
 * 展开某一台时才额外拉一次它的明细(挂载点/进程/网卡),
 * 那些东西塞进列表接口会让响应大十几倍,而它们只在展开时才被看。
 *
 * **算不出来的值一律显示 —,不显示 0。**CPU 使用率靠两拍 /proc/stat 相减,
 * 所以刚加进来的服务器第一拍必然没有 CPU —— 那时候显示 0% 的意思是
 * "这台机器很闲",而真相是"还没算出来"。后端把原因放在 cpu_pending 里,
 * 页面直接把那句话显示出来。
 */

const message = useMessage()

const spanHours = ref(3)
const metric = ref<ServerMetric>('net')
const expanded = ref<number | null>(null)
const detail = ref<ServerDetail | null>(null)
const detailLoading = ref(false)
const busy = ref(0)

const cards = usePolling(() => api.serverCards(spanHours.value).then((r) => r.data), 20000)

const SPAN_OPTIONS = [
  { label: '最近 1 小时', value: 1 },
  { label: '最近 3 小时', value: 3 },
  { label: '最近 12 小时', value: 12 },
  { label: '最近 24 小时', value: 24 },
  { label: '最近 7 天', value: 168 },
]
const METRIC_OPTIONS = [
  { label: '流量', value: 'net' as const },
  { label: 'CPU', value: 'cpu' as const },
  { label: '内存', value: 'mem' as const },
  { label: '负载', value: 'load' as const },
]

const servers = computed<ServerCard[]>(() => cards.data.value?.servers || [])

/** 展开某一台时才拉明细 —— 挂载点/进程/网卡只在这时候才被看。 */
async function toggle(server: ServerCard) {
  if (expanded.value === server.id) {
    expanded.value = null
    detail.value = null
    return
  }
  expanded.value = server.id
  detail.value = null
  detailLoading.value = true
  try {
    const { data } = await api.serverDetail(server.id)
    detail.value = data
  } catch (e) {
    message.error(errText(e))
  } finally {
    detailLoading.value = false
  }
}

// 展开着的时候切换时间跨度会重拉列表,明细也跟着刷一次
watch(spanHours, () => cards.refresh())

async function collectNow(server: ServerCard) {
  busy.value = server.id
  try {
    await api.collectServerNow(server.id)
    message.success('已排入下一拍')
  } catch (e) {
    message.error(errText(e))
  } finally {
    busy.value = 0
  }
}

async function test(server: ServerCard) {
  busy.value = server.id
  try {
    const { data } = await api.testServer(server.id)
    if (data.ok) message.success(data.detail, { duration: 8000 })
    else message.error(data.detail, { duration: 10000 })
  } catch (e) {
    message.error(errText(e))
  } finally {
    busy.value = 0
  }
}

/** 四个指标条的配置。**每核负载**单独一档 —— 绝对值没有可比性。 */
function meters(card: ServerCard) {
  return [
    { key: 'cpu', label: 'CPU', value: card.cpu, max: 100, unit: '%',
      warn: card.thresholds.cpu_warn, crit: card.thresholds.cpu_crit },
    { key: 'mem', label: '内存', value: card.mem, max: 100, unit: '%',
      warn: card.thresholds.mem_warn, crit: card.thresholds.mem_crit },
    { key: 'disk', label: '磁盘', value: card.disk, max: 100, unit: '%',
      warn: card.thresholds.disk_warn, crit: card.thresholds.disk_crit },
    { key: 'load', label: '负载/核', value: card.load_per_core,
      max: Math.max(card.thresholds.load_crit * 1.2, 2), unit: '',
      warn: card.thresholds.load_warn, crit: card.thresholds.load_crit },
  ]
}

function cardLevel(state: string) {
  if (state === 'down') return 'critical' as const
  if (state === 'degraded') return 'warning' as const
  return 'normal' as const
}

const totals = computed(() => cards.data.value)
</script>

<template>
  <div class="srv">
    <!-- ============ 顶部统计 ============ -->
    <section class="head">
      <div class="tiles">
        <StatTile label="服务器" :value="totals?.total ?? null" unit="台"
                  :dim-zero="false"
                  :foot="`SSH 采集 · 更新于 ${ago(cards.lastSuccess.value)}`" />
        <StatTile label="正常" :value="totals?.up ?? null" unit="台" :color="STATE.up" />
        <StatTile label="劣化" :value="totals?.degraded ?? null" unit="台" :color="STATE.degraded"
                  foot="通但有指标超阈值" />
        <StatTile label="失联" :value="totals?.down ?? null" unit="台" :color="STATE.down"
                  foot="SSH 登不上去" />
      </div>
      <div class="actions">
        <NButtonGroup size="small">
          <NButton
            v-for="opt in METRIC_OPTIONS" :key="opt.value"
            :type="metric === opt.value ? 'primary' : 'default'"
            ghost @click="metric = opt.value"
          >
            {{ opt.label }}
          </NButton>
        </NButtonGroup>
        <NSelect v-model:value="spanHours" :options="SPAN_OPTIONS" size="small" style="width: 132px" />
        <NButton size="small" ghost @click="cards.toggle()">
          {{ cards.paused.value ? '继续刷新' : '暂停刷新' }}
        </NButton>
      </div>
    </section>

    <div v-if="cards.error.value" class="warn-line">刷新失败:{{ cards.error.value }}(显示的是上一次的数据)</div>

    <div v-if="!servers.length && !cards.loading.value" class="cy-panel">
      <div class="cy-empty">
        还没有服务器。到<b>配置中心 → 服务器</b>添加 —— 只要一个能登录的
        SSH 账号,不用在机器上装任何东西。<br>
        采集读的是 <code>/proc</code> 和 <code>df</code>,只支持 Linux / 类 Unix。
      </div>
    </div>

    <!-- ============ 一台一块面板 ============ -->
    <CyberPanel
      v-for="card in servers" :key="card.id"
      :title="card.name"
      :subtitle="card.hostname && card.hostname !== card.name ? card.hostname : card.host"
      :level="cardLevel(card.state)"
      :live="!cards.paused.value && card.state !== 'down'"
      class="srv-panel"
    >
      <template #actions>
        <StateDot :state="card.state" label />
        <span v-if="card.open_events" class="badge" :style="{ '--c': STATE.down }">
          {{ card.open_events }} 条未恢复
        </span>
        <NButton size="tiny" ghost :loading="busy === card.id" @click="test(card)">测试</NButton>
        <NButton size="tiny" ghost @click="collectNow(card)">立即采集</NButton>
        <NButton size="tiny" ghost @click="toggle(card)">
          {{ expanded === card.id ? '收起明细' : '展开明细' }}
        </NButton>
      </template>

      <div class="srv-body">
        <!-- 左:基本信息 + 指标条 -->
        <div class="left">
          <div class="info">
            <span class="cy-mono">{{ card.host }}</span>
            <span v-if="card.os_name" class="sep">·</span>
            <span v-if="card.os_name">{{ card.os_name }}</span>
            <span v-if="card.kernel" class="sep">·</span>
            <span v-if="card.kernel" class="cy-mono dim">{{ card.kernel }}</span>
          </div>
          <div class="info">
            <span v-if="card.cpu_cores">{{ card.cpu_cores }} 核</span>
            <span v-if="card.mem_total_bytes" class="sep">·</span>
            <span v-if="card.mem_total_bytes">{{ bytes(card.mem_total_bytes) }} 内存</span>
            <span v-if="card.role" class="sep">·</span>
            <span v-if="card.role">{{ card.role }}</span>
            <span v-if="card.site" class="sep">·</span>
            <span v-if="card.site">{{ card.site }}</span>
          </div>

          <div class="meters">
            <div v-for="m in meters(card)" :key="m.key" class="meter">
              <MeterBar
                :label="m.label"
                :value="m.value ?? 0"
                :max="m.max"
                :warn="m.warn"
                :crit="m.crit"
                :show-value="false"
              />
              <span class="meter-num cy-mono"
                    :style="{ color: m.value === null ? 'var(--cy-ink-3)' : valueColor(m.value, m.warn, m.crit) }">
                {{ m.value === null ? '—' : m.key === 'load' ? num(m.value, 2) : pct(m.value, 0) }}
              </span>
            </div>
          </div>

          <!-- 流量:入/出各一个数 + 一条 sparkline -->
          <div class="net">
            <div class="net-head">
              <span class="k">流量</span>
              <span v-if="card.primary_interface" class="cy-mono dim">{{ card.primary_interface }}</span>
            </div>
            <div class="net-nums cy-mono">
              <span>↓ {{ bps(card.net_in_bps) }}</span>
              <span class="dim">/</span>
              <span>↑ {{ bps(card.net_out_bps) }}</span>
            </div>
            <Sparkline
              :values="card.trend.slice(-40).map((p) => p.net_in)"
              color="var(--cy-cat-1)"
              :height="20"
            />
          </div>

          <div class="foot">
            <span>{{ card.last_collected_at ? `采集于 ${timeOf(card.last_collected_at)}` : '尚未采集' }}</span>
            <span class="dim">每 {{ card.interval }}s</span>
          </div>
          <div v-if="card.last_error" class="err">{{ card.last_error }}</div>
        </div>

        <!-- 右:趋势图 -->
        <div class="right">
          <ServerChart
            :points="card.trend"
            :metric="metric"
            :interval="card.interval"
            :warn="metric === 'cpu' ? card.thresholds.cpu_warn
              : metric === 'mem' ? card.thresholds.mem_warn
              : metric === 'load' ? card.thresholds.load_warn : null"
            :crit="metric === 'cpu' ? card.thresholds.cpu_crit
              : metric === 'mem' ? card.thresholds.mem_crit
              : metric === 'load' ? card.thresholds.load_crit : null"
            :cores="card.cpu_cores"
            :height="216"
          />
          <div v-if="!card.trend.length" class="no-data">
            这段时间没有采集到数据 —— 服务器刚加进来,或者采集停了
          </div>
        </div>
      </div>

      <!-- ============ 明细(展开才拉) ============ -->
      <div v-if="expanded === card.id" class="detail">
        <div v-if="detailLoading" class="detail-loading">读取明细…</div>
        <template v-else-if="detail">
          <div v-if="detail.cpu_pending" class="note">{{ detail.cpu_pending }}</div>
          <div v-for="(n, i) in detail.notes" :key="i" class="note">{{ n }}</div>

          <div class="detail-grid">
            <!-- 挂载点 -->
            <div class="block">
              <div class="block-head">
                {{ detail.esxi ? '数据存储' : '挂载点' }}
                <span class="dim">
                  按占用率排,阈值判的是最满的那个{{ detail.esxi ? ';bootbank 不计入' : '' }}
                </span>
              </div>
              <div v-if="!detail.mounts.length" class="dim small">
                {{ detail.esxi ? '没有采到数据存储信息' : '没有采到挂载点信息' }}
              </div>
              <div v-for="m in detail.mounts" :key="m.mount" class="mount">
                <span class="mount-path cy-mono" :title="m.fs">{{ m.mount }}</span>
                <span class="mount-bar">
                  <MeterBar
                    :label="''" :value="m.pct ?? 0" :max="100"
                    :warn="detail.server.disk_warn_pct" :crit="detail.server.disk_crit_pct"
                    :show-value="false"
                  />
                </span>
                <span class="mount-num cy-mono"
                      :style="{ color: valueColor(m.pct, detail.server.disk_warn_pct, detail.server.disk_crit_pct) }">
                  {{ pct(m.pct, 0) }}
                </span>
                <span class="mount-size cy-mono dim">
                  {{ bytes(m.used_bytes) }} / {{ bytes(m.total_bytes) }}
                </span>
              </div>
            </div>

            <!-- 网卡 -->
            <div class="block">
              <div class="block-head">
                {{ detail.esxi ? '物理上行口' : '网卡' }}
                <span class="dim">
                  {{ detail.esxi
                    ? '只有 vmnic 是物理口,vSwitch / vmk 不在流量表里'
                    : '主网卡才计入流量统计,虚拟口会把同一份流量数几遍' }}
                </span>
              </div>
              <div v-for="iface in detail.interfaces" :key="iface.id" class="nic">
                <span class="nic-name cy-mono">{{ iface.if_name }}</span>
                <NTag v-if="iface.is_primary" size="tiny" :bordered="false" type="info">主</NTag>
                <NTag v-else-if="iface.is_virtual" size="tiny" :bordered="false">虚拟</NTag>
                <span class="nic-rate cy-mono">
                  ↓{{ bps(iface.in_bps) }} <span class="dim">/</span> ↑{{ bps(iface.out_bps) }}
                </span>
                <span v-if="iface.in_err_delta || iface.out_err_delta" class="nic-err">
                  错包 {{ (iface.in_err_delta || 0) + (iface.out_err_delta || 0) }}
                </span>
              </div>
            </div>

            <!-- 进程 Top + 其它数字 -->
            <div class="block">
              <!-- ESXi 上没有"进程"这个层级(有 world,但那不是人要看的东西),
                   换成「这台宿主上正在跑哪些虚拟机」—— 同一个位置,同一个问题:
                   出事的时候要知道影响到谁 -->
              <template v-if="detail.esxi">
                <div class="block-head">
                  虚拟机
                  <span class="dim">
                    <!-- null 和 0 必须分开:前者是没采到(vim-cmd 权限不够最常见),
                         后者是这台宿主真的空着 -->
                    {{ detail.esxi.vm_running === null
                      ? '没采到 —— 账号能跑 esxcli vm process list 吗'
                      : `运行中 ${detail.esxi.vm_running}${
                          detail.esxi.vm_registered !== null
                            ? ` / 已注册 ${detail.esxi.vm_registered}` : ''}` }}
                  </span>
                </div>
                <div v-if="detail.esxi.maintenance_mode" class="note">
                  这台在**维护模式**里 —— 上面的虚拟机应该已经迁走了,指标偏低是正常的
                </div>
                <div v-if="!detail.esxi.vm_names.length" class="dim small">
                  没有虚拟机清单(配置里可以关掉这一项)
                </div>
                <div v-for="(vm, i) in detail.esxi.vm_names" :key="i" class="proc">
                  <span class="proc-name cy-mono">{{ vm }}</span>
                </div>
              </template>
              <template v-else>
                <div class="block-head">
                  进程 Top
                  <span class="dim">按 CPU 排</span>
                </div>
                <div v-if="!detail.top_processes.length" class="dim small">
                  没有采集进程信息(配置里可以关掉这一项)
                </div>
                <div v-for="(proc, i) in detail.top_processes" :key="i" class="proc">
                  <span class="proc-name cy-mono">{{ proc.name }}</span>
                  <span class="proc-num cy-mono">CPU {{ num(proc.cpu, 1, '%') }}</span>
                  <span class="proc-num cy-mono dim">内存 {{ num(proc.mem, 1, '%') }}</span>
                </div>
              </template>

              <div class="block-head second">系统</div>
              <div class="kv-list">
                <div class="kv"><span>运行时长</span><b class="cy-mono">{{ uptime(detail.uptime_s) }}</b></div>

                <!-- 下面这几项 ESXi 全都没有。**写"不适用"而不是 —** ——
                     一个 — 会让人以为采集坏了,然后去查一个不存在的问题 -->
                <template v-if="detail.esxi">
                  <div class="kv"><span>CPU 主频池</span><b class="cy-mono">
                    {{ detail.esxi.cpu_used_mhz !== null && detail.esxi.cpu_total_mhz
                      ? `${detail.esxi.cpu_used_mhz} / ${detail.esxi.cpu_total_mhz} MHz` : '—' }}
                  </b></div>
                  <div class="kv"><span>物理规格</span><b class="cy-mono">
                    {{ [detail.esxi.cpu_packages ? `${detail.esxi.cpu_packages} 路` : '',
                        detail.server.cpu_cores ? `${detail.server.cpu_cores} 核` : '',
                        detail.esxi.cpu_threads ? `${detail.esxi.cpu_threads} 线程` : '']
                        .filter(Boolean).join(' / ') || '—' }}
                  </b></div>
                  <div class="kv"><span>硬件</span>
                    <b class="cy-mono">{{ detail.esxi.hw_platform || '—' }}</b>
                  </div>
                  <div class="kv"><span>负载</span><b class="cy-mono dim">ESXi 不提供</b></div>
                  <div class="kv"><span>iowait / Swap</span><b class="cy-mono dim">ESXi 不提供</b></div>
                </template>
                <template v-else>
                  <div class="kv"><span>负载</span><b class="cy-mono">
                    {{ num(detail.current.load1, 2) }} / {{ num(detail.current.load5, 2) }} / {{ num(detail.current.load15, 2) }}
                  </b></div>
                  <div class="kv"><span>iowait</span><b class="cy-mono">{{ pct(detail.current.iowait) }}</b></div>
                  <div class="kv">
                    <span>Swap</span>
                    <!-- 没开 swap 时后端给 null,显示 — 而不是 0% ——
                         0% 看着像"swap 很空闲",而事实是这台机器没有 swap -->
                    <b class="cy-mono">{{ detail.current.swap === null ? '— 未启用' : pct(detail.current.swap) }}</b>
                  </div>
                  <div class="kv"><span>进程数</span><b class="cy-mono">{{ int(detail.current.process_count) }}</b></div>
                  <div class="kv"><span>ESTABLISHED</span><b class="cy-mono">{{ int(detail.current.tcp_established) }}</b></div>
                </template>
              </div>
            </div>
          </div>
        </template>
      </div>
    </CyberPanel>
  </div>
</template>

<style scoped>
.srv { display: flex; flex-direction: column; gap: 14px; }

.head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 14px;
  flex-wrap: wrap;
}
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px;
  flex: 1;
  min-width: 320px;
}
.actions { display: flex; align-items: center; gap: 10px; }

.warn-line {
  font-size: 11.5px;
  color: var(--cy-degraded);
  padding: 5px 10px;
  border-left: 2px solid var(--cy-degraded);
  background: rgba(var(--cy-degraded-rgb), 0.06);
}

.srv-body { display: grid; grid-template-columns: minmax(280px, 360px) 1fr; gap: 18px; }
@media (max-width: 900px) {
  .srv-body { grid-template-columns: 1fr; }
}

.left { display: flex; flex-direction: column; gap: 8px; min-width: 0; }
.info {
  font-size: 11.5px;
  color: var(--cy-ink-2);
  display: flex;
  align-items: baseline;
  gap: 5px;
  flex-wrap: wrap;
}
.sep { color: var(--cy-ink-3); }
.dim { color: var(--cy-ink-3); }
.small { font-size: 11px; }

.meters { display: flex; flex-direction: column; gap: 5px; margin-top: 3px; }
.meter { display: grid; grid-template-columns: 1fr 54px; align-items: center; gap: 8px; }
.meter-num { font-size: 12px; font-weight: 700; text-align: right; }

.net { margin-top: 4px; }
.net-head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  font-size: 11px;
}
.net-head .k { color: var(--cy-ink-3); letter-spacing: 0.06em; }
.net-nums {
  display: flex;
  gap: 7px;
  font-size: 12.5px;
  color: var(--cy-ink);
  margin: 2px 0 3px;
}

.foot {
  display: flex;
  justify-content: space-between;
  font-size: 10.5px;
  color: var(--cy-ink-3);
  margin-top: auto;
  padding-top: 6px;
}
.err {
  font-size: 11px;
  color: var(--cy-down);
  word-break: break-all;
  line-height: 1.5;
}

.right { min-width: 0; position: relative; }
.no-data {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11.5px;
  color: var(--cy-ink-3);
}

/* ---- 明细 ---- */
.detail {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid rgba(var(--cy-cyan-rgb), 0.14);
}
.detail-loading { font-size: 11.5px; color: var(--cy-ink-3); }
.note {
  font-size: 11px;
  color: var(--cy-ink-2);
  padding: 5px 9px;
  margin-bottom: 8px;
  background: rgba(var(--cy-cyan-rgb), 0.05);
  border-left: 2px solid rgba(var(--cy-cyan-rgb), 0.4);
}
.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px;
}
.block { min-width: 0; }
.block-head {
  font-size: 11px;
  letter-spacing: 0.08em;
  color: var(--cy-cyan);
  margin-bottom: 6px;
  display: flex;
  gap: 8px;
  align-items: baseline;
  flex-wrap: wrap;
}
.block-head .dim { font-size: 10px; letter-spacing: 0; }
.block-head.second { margin-top: 12px; }

.mount {
  display: grid;
  grid-template-columns: minmax(70px, 1fr) 70px 44px auto;
  align-items: center;
  gap: 7px;
  font-size: 11px;
  padding: 1px 0;
}
.mount-path { color: var(--cy-ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.mount-num { text-align: right; font-weight: 700; }
.mount-size { font-size: 10px; }

.nic {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  padding: 1px 0;
  flex-wrap: wrap;
}
.nic-name { color: var(--cy-ink); min-width: 74px; }
.nic-rate { color: var(--cy-ink-2); margin-left: auto; }
.nic-err { color: var(--cy-degraded); font-size: 10px; }

.proc {
  display: grid;
  grid-template-columns: 1fr auto auto;
  gap: 9px;
  font-size: 11px;
  padding: 1px 0;
}
.proc-name { color: var(--cy-ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.proc-num { font-size: 10.5px; color: var(--cy-ink-2); }

.kv-list { display: flex; flex-direction: column; gap: 2px; }
.kv {
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: var(--cy-ink-3);
}
.kv b { color: var(--cy-ink-2); font-weight: 600; }

.badge {
  font-size: 10px;
  padding: 1px 6px;
  color: var(--c);
  border: 1px solid var(--c);
  letter-spacing: 0.04em;
}
</style>
