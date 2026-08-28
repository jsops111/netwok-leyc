<script setup lang="ts">
import { computed, h, ref, watch } from 'vue'
import {
  NButton, NDataTable, NInput, NModal, NSelect, NSpace, NTag, useMessage,
} from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import SeverityTag from '@/components/cyber/SeverityTag.vue'
import { api, errText } from '@/api'
import type { EventRow } from '@/api'
import { usePolling } from '@/composables/usePolling'
import { ago, dateTimeOf, duration, num } from '@/composables/useFormat'
import { useMetaStore } from '@/stores/meta'
import { SEVERITY, STATE, severityColor } from '@/theme'

/**
 * 事件记录页面。
 *
 * 需求原话:「要有一个事件报告,什么时候发生了什么事情、什么时候恢复的,tables 表」
 * 所以这一页的核心就是那张表,上面配一排汇总和排行。
 *
 * 分页在服务端做(DRF 分页),不是拉全量再前端分页 —— 事件表跑几个月就是
 * 几万行,全量拉一次浏览器直接卡死。
 */

const message = useMessage()
const meta = useMetaStore()

const hours = ref(24)
const filters = ref({
  severity: null as string | null,
  kind: null as string | null,
  source_type: null as string | null,
  // naive 的 Select 只接受 string/number,所以这里用字符串再映射成
  // 后端要的布尔 —— 直接用 boolean 会被 SelectMixedOption 的类型拒掉
  open: 'all' as 'all' | 'open' | 'resolved',
  keyword: '',
})
const page = ref(1)
const pageSize = ref(20)

const HOURS_OPTIONS = [
  { label: '最近 1 小时', value: 1 },
  { label: '最近 6 小时', value: 6 },
  { label: '最近 24 小时', value: 24 },
  { label: '最近 3 天', value: 72 },
  { label: '最近 7 天', value: 168 },
  { label: '最近 30 天', value: 720 },
]
const OPEN_OPTIONS = [
  { label: '全部', value: 'all' },
  { label: '仅未恢复', value: 'open' },
  { label: '仅已恢复', value: 'resolved' },
]

const queryParams = computed(() => ({
  hours: hours.value,
  page: page.value,
  page_size: pageSize.value,
  severity: filters.value.severity || undefined,
  kind: filters.value.kind || undefined,
  source_type: filters.value.source_type || undefined,
  open: filters.value.open === 'all' ? undefined : filters.value.open === 'open',
  keyword: filters.value.keyword || undefined,
  ordering: '-started_at',
}))

const events = usePolling(() => api.events(queryParams.value).then((r) => r.data), 15000)
const report = usePolling(() => api.eventReport(hours.value).then((r) => r.data), 30000)

// 筛选条件变了立刻重查,不等下一个轮询周期
watch([queryParams], () => void events.refresh())
watch(hours, () => void report.refresh())
watch(
  () => [filters.value.severity, filters.value.kind, filters.value.source_type, filters.value.open, filters.value.keyword],
  () => (page.value = 1),
)

// ---- 认领弹窗 ----
const ackModal = ref(false)
const ackTarget = ref<EventRow | null>(null)
const ackForm = ref({ by: '', note: '' })

function openAck(row: EventRow) {
  ackTarget.value = row
  ackForm.value = { by: '', note: '' }
  ackModal.value = true
}

async function submitAck() {
  if (!ackTarget.value) return
  try {
    await api.ackEvent(ackTarget.value.id, ackForm.value.by, ackForm.value.note)
    message.success('已认领')
    ackModal.value = false
    void events.refresh()
  } catch (e) {
    message.error(errText(e))
  }
}

async function renotify(row: EventRow) {
  try {
    const { data } = await api.renotify(row.id)
    message.success(data.detail || '已排入推送队列')
  } catch (e) {
    message.error(errText(e))
  }
}

const columns = computed<DataTableColumns<EventRow>>(() => [
  {
    title: '级别',
    key: 'severity',
    width: 74,
    render: (row) =>
      h('span', { style: 'display:flex;align-items:center' }, [
        h('i', { class: 'cy-row-sev', style: { '--sev': severityColor(row.severity) } }),
        h(SeverityTag, { severity: row.severity, label: row.severity_label }),
      ]),
  },
  {
    title: '类型',
    key: 'kind',
    width: 92,
    render: (row) => h('span', { style: 'font-size:12.5px' }, row.kind_label),
  },
  {
    title: '对象',
    key: 'source_name',
    minWidth: 190,
    render: (row) =>
      h('div', [
        h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, row.source_name),
        h(
          'div',
          { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
          `${row.source_type_label}${row.group_name ? ' · ' + row.group_name : ''}`,
        ),
      ]),
  },
  {
    title: '详情',
    key: 'message',
    minWidth: 240,
    render: (row) =>
      h('div', [
        h('div', { style: 'font-size:12px;color:var(--cy-ink-2);line-height:1.45' }, row.message || row.title),
        row.trigger_value !== null
          ? h(
              'div',
              { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace;margin-top:2px" },
              `实测 ${num(row.trigger_value, 1, row.unit)}${row.threshold !== null ? ` / 阈值 ${num(row.threshold, 0, row.unit)}` : ''} · 失败 ${row.fail_count} 次`,
            )
          : null,
      ]),
  },
  {
    title: '发生时间',
    key: 'started_at',
    width: 152,
    className: 'num',
    render: (row) =>
      h('div', [
        h('div', { style: 'font-size:11.5px' }, dateTimeOf(row.started_at)),
        h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' }, ago(row.started_at)),
      ]),
  },
  {
    title: '恢复时间',
    key: 'resolved_at',
    width: 152,
    className: 'num',
    render: (row) =>
      row.resolved_at
        ? h('div', [
            h('div', { style: 'font-size:11.5px' }, dateTimeOf(row.resolved_at)),
            h('div', { style: 'font-size:10px;color:var(--cy-up)' }, '已恢复'),
          ])
        : // 未恢复的显式标出来,不是留空 —— 留空看起来像数据缺失
          h(
            'span',
            { style: `color:${STATE.down};font-size:11.5px;font-weight:600` },
            '进行中',
          ),
  },
  {
    title: '持续',
    key: 'duration',
    width: 96,
    className: 'num',
    render: (row) =>
      h(
        'span',
        {
          style: `font-size:11.5px;color:${row.is_open ? STATE.down : 'var(--cy-ink-2)'}`,
        },
        // 未恢复的用实时时长(后端算的 live_duration_s)
        duration(row.is_open ? row.live_duration_s : row.duration_s),
      ),
  },
  {
    title: '推送',
    key: 'notified',
    width: 76,
    render: (row) => {
      const tags = []
      if (row.notified_alert) tags.push(h(NTag, { size: 'tiny', type: 'info', bordered: false }, () => '告警'))
      if (row.notified_recover) tags.push(h(NTag, { size: 'tiny', type: 'success', bordered: false }, () => '恢复'))
      if (!tags.length) tags.push(h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)' }, '未推送'))
      return h('div', { style: 'display:flex;gap:3px;flex-wrap:wrap' }, tags)
    },
  },
  {
    title: '处理',
    key: 'actions',
    width: 128,
    render: (row) =>
      h(NSpace, { size: 4 }, () => [
        row.acknowledged_at
          ? h(
              'span',
              { style: 'font-size:10.5px;color:var(--cy-up)', title: row.note },
              `${row.acknowledged_by} 已认领`,
            )
          : h(NButton, { size: 'tiny', ghost: true, onClick: () => openAck(row) }, () => '认领'),
        h(NButton, { size: 'tiny', text: true, onClick: () => renotify(row) }, () => '重推'),
      ]),
  },
])

/**
 * 分页配置。**放在 script 里而不是模板里** —— 模板表达式里对 ref 赋值
 * (`page = p`)不会解包,而且带 `;` 的语句块在模板编译期就是语法错误。
 */
const pagination = computed(() => ({
  page: page.value,
  pageSize: pageSize.value,
  itemCount: events.data.value?.count || 0,
  pageSizes: [20, 50, 100],
  showSizePicker: true,
  onUpdatePage: (p: number) => {
    page.value = p
  },
  onUpdatePageSize: (size: number) => {
    pageSize.value = size
    page.value = 1
  },
  prefix: ({ itemCount }: { itemCount?: number }) => `共 ${itemCount ?? 0} 条`,
}))

const summary = computed(() => report.data.value || null)
const kindRank = computed(() => summary.value?.by_kind?.slice(0, 6) || [])
const targetRank = computed(() => summary.value?.top_targets || [])
const deviceRank = computed(() => summary.value?.top_devices || [])
</script>

<template>
  <div class="ev">
    <!-- ============ 汇总 ============ -->
    <section class="sum-bar">
      <div class="sum-head">
        <div class="cy-panel-title">事件报告</div>
        <NSelect v-model:value="hours" :options="HOURS_OPTIONS" size="small" style="width: 132px" />
      </div>
      <div class="tiles">
        <StatTile label="事件总数" :value="summary?.total ?? null" unit="条" color="var(--cy-cyan)" :dim-zero="false" />
        <StatTile
          label="未恢复" :value="summary?.open ?? null" unit="条" :color="STATE.down"
          :foot="summary?.open ? '需要处理' : '全部已恢复'"
        />
        <StatTile label="已恢复" :value="summary?.resolved ?? null" unit="条" :color="STATE.up" />
        <StatTile
          label="平均持续" :value="summary ? duration(summary.duration.avg_s) : null"
          :color="STATE.degraded" :dim-zero="false"
          :foot="summary ? `最长 ${duration(summary.duration.max_s)}` : ''"
        />
        <StatTile
          label="累计故障时长" :value="summary ? duration(summary.duration.total_s) : null"
          color="var(--cy-violet)" :dim-zero="false"
        />
      </div>

      <div class="ranks">
        <div class="rank-block">
          <div class="rank-title">按类型</div>
          <div v-if="!kindRank.length" class="rank-empty">这段时间没有事件</div>
          <div v-for="item in kindRank" :key="item.kind" class="rank-row">
            <span class="rk-name">{{ item.label }}</span>
            <span class="rk-bar">
              <i :style="{ width: `${(item.count / (kindRank[0]?.count || 1)) * 100}%` }" />
            </span>
            <span class="rk-num cy-mono">{{ item.count }}</span>
          </div>
        </div>
        <div class="rank-block">
          <div class="rank-title">出事最多的线路</div>
          <div v-if="!targetRank.length" class="rank-empty">无</div>
          <div v-for="item in targetRank.slice(0, 6)" :key="item.target_id" class="rank-row">
            <span class="rk-name" :title="item.target__host">{{ item.target__name }}</span>
            <span class="rk-bar">
              <i class="warn" :style="{ width: `${(item.count / (targetRank[0]?.count || 1)) * 100}%` }" />
            </span>
            <span class="rk-num cy-mono">{{ item.count }}</span>
          </div>
        </div>
        <div class="rank-block">
          <div class="rank-title">出事最多的设备</div>
          <div v-if="!deviceRank.length" class="rank-empty">无</div>
          <div v-for="item in deviceRank.slice(0, 6)" :key="item.device_id" class="rank-row">
            <span class="rk-name" :title="item.device__mgmt_ip">{{ item.device__name }}</span>
            <span class="rk-bar">
              <i class="violet" :style="{ width: `${(item.count / (deviceRank[0]?.count || 1)) * 100}%` }" />
            </span>
            <span class="rk-num cy-mono">{{ item.count }}</span>
          </div>
        </div>
      </div>
    </section>

    <!-- ============ 事件表 ============ -->
    <CyberPanel
      title="事件明细"
      :subtitle="`共 ${events.data.value?.count ?? 0} 条 · 每 15 秒刷新`"
      :live="!events.paused.value"
      flush
    >
      <template #actions>
        <NSpace size="small" align="center">
          <NInput
            v-model:value="filters.keyword" size="small" placeholder="搜索标题或详情"
            clearable style="width: 168px"
          />
          <NSelect
            v-model:value="filters.severity" :options="meta.options('severity')" size="small"
            placeholder="级别" clearable style="width: 96px"
          />
          <NSelect
            v-model:value="filters.kind" :options="meta.options('event_kind')" size="small"
            placeholder="类型" clearable style="width: 118px"
          />
          <NSelect
            v-model:value="filters.source_type" :options="meta.options('source_type')" size="small"
            placeholder="来源" clearable style="width: 108px"
          />
          <NSelect v-model:value="filters.open" :options="OPEN_OPTIONS" size="small" style="width: 106px" />
        </NSpace>
      </template>

      <NDataTable
        :columns="columns"
        :data="events.data.value?.results || []"
        :loading="events.loading.value"
        :bordered="false"
        :single-line="false"
        size="small"
        :row-class-name="(row: EventRow) => (row.is_open ? 'row-open' : '')"
        :pagination="pagination"
        :scroll-x="1260"
      />
      <div v-if="events.error.value" class="tbl-err">刷新失败:{{ events.error.value }}</div>
    </CyberPanel>

    <!-- 认领弹窗 -->
    <NModal
      v-model:show="ackModal" preset="card" title="认领事件" style="width: 480px"
      :bordered="false"
    >
      <div v-if="ackTarget" class="ack">
        <div class="ack-title">{{ ackTarget.title }}</div>
        <div class="ack-msg">{{ ackTarget.message }}</div>
        <NInput v-model:value="ackForm.by" placeholder="认领人(留空记为匿名)" />
        <NInput
          v-model:value="ackForm.note" type="textarea" :rows="3"
          placeholder="处理备注 —— 写清楚做了什么,下次同样的事件有人能接着看"
        />
      </div>
      <template #footer>
        <NSpace justify="end">
          <NButton size="small" @click="ackModal = false">取消</NButton>
          <NButton size="small" type="primary" @click="submitAck">确认认领</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.ev { display: flex; flex-direction: column; gap: 16px; }

.sum-bar {
  background: linear-gradient(150deg, rgba(var(--cy-raised-rgb), 0.7), rgba(var(--cy-body-rgb), 0.85));
  border: 1px solid rgba(var(--cy-cyan-rgb), 0.13);
  border-top: 2px solid rgba(var(--cy-cyan-rgb), 0.5);
  padding: 13px 16px 14px;
  clip-path: polygon(0 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%);
}
.sum-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(158px, 1fr));
  gap: 10px;
}

.ranks {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 20px;
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px solid rgba(var(--cy-cyan-rgb), 0.1);
}
.rank-title {
  font-size: 10.5px;
  letter-spacing: 0.12em;
  color: var(--cy-ink-3);
  text-transform: uppercase;
  margin-bottom: 7px;
}
.rank-empty { font-size: 11.5px; color: var(--cy-ink-3); }
.rank-row {
  display: grid;
  grid-template-columns: 88px minmax(0, 1fr) 34px;
  gap: 8px;
  align-items: center;
  margin-bottom: 4px;
}
.rk-name {
  font-size: 11.5px;
  color: var(--cy-ink-2);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.rk-bar { height: 5px; background: rgba(var(--cy-ink-rgb), 0.055); }
.rk-bar i {
  display: block;
  height: 100%;
  background: var(--cy-cyan);
  box-shadow: 0 0 8px rgba(var(--cy-cyan-rgb), 0.5);
  transition: width 0.4s ease;
}
.rk-bar i.warn { background: var(--cy-degraded); box-shadow: 0 0 8px rgba(var(--cy-degraded-rgb), 0.5); }
.rk-bar i.violet { background: var(--cy-violet); box-shadow: 0 0 8px var(--cy-glow); }
.rk-num { font-size: 11.5px; color: var(--cy-ink); text-align: right; }

.tbl-err {
  padding: 8px 16px;
  font-size: 11.5px;
  color: var(--cy-degraded);
  font-family: 'JetBrains Mono', monospace;
}

.ack { display: flex; flex-direction: column; gap: 10px; }
.ack-title { font-size: 14px; font-weight: 600; color: var(--cy-ink); }
.ack-msg { font-size: 12px; color: var(--cy-ink-2); line-height: 1.5; }
</style>

<style>
/* 未恢复的行左侧一道红边 —— 整行染色会盖掉文字,只标边框 */
.n-data-table .row-open td:first-child {
  box-shadow: inset 2px 0 0 var(--cy-down);
}
</style>
