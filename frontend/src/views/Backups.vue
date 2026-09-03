<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import { NButton, NDataTable, NModal, NSelect, NSpace, NTag, useMessage } from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import StateDot from '@/components/cyber/StateDot.vue'
import { api, errText } from '@/api'
import type { BackupDiff, BackupVersion, DeviceRow } from '@/api'
import { useMetaStore } from '@/stores/meta'
import { ago, bytes, dateTimeOf, int } from '@/composables/useFormat'
import { STATE } from '@/theme'

/**
 * 配置备份页。
 *
 * ## 一行一个版本,不是一行一次备份
 *
 * 这是这一页最需要先说清楚的事:交换机的配置一年可能只改三次,而备份一天
 * 跑一次。按"每次备份一行"列出来的话,一年三百多行里只有三行有信息。
 * 所以后端**配置没变就不新增版本**,只把最新那行的「最后确认」往后推。
 * 于是这张表天然就是一份变更历史,行数 = 真实变更次数。
 *
 * 「最后确认 N 次」那一列就是"这个版本被连续确认了多少次没变"。
 *
 * ## 顶部那个「备份失败」必须显眼
 *
 * **一个悄悄坏掉的备份等于没有备份**,而这件事没有任何症状 ——
 * 页面照常打开、版本列表照常有内容,只是最新那个版本是三个月前的。
 * 所以失败台数放在顶部统计里,而不是藏在某台设备的详情里。
 */

const message = useMessage()
const meta = useMetaStore()

const loading = ref(false)
const devices = ref<DeviceRow[]>([])
const selected = ref<number | null>(null)
const versions = ref<BackupVersion[]>([])
const versionsLoading = ref(false)
const busy = ref(0)

// diff 弹窗
const diffOpen = ref(false)
const diffLoading = ref(false)
const diff = ref<BackupDiff | null>(null)
const diffTitle = ref('')

// 全文弹窗
const textOpen = ref(false)
const textLoading = ref(false)
const fullText = ref<BackupVersion | null>(null)

/** 开了备份的设备。没开的不列 —— 这一页只回答"备份怎么样了"。 */
const backupDevices = computed(() => devices.value.filter((d) => d.backup_enabled))
const currentDevice = computed(() => devices.value.find((d) => d.id === selected.value) || null)

const stats = computed(() => {
  const list = backupDevices.value
  return {
    total: list.length,
    failed: list.filter((d) => d.last_backup_status === 'failed').length,
    never: list.filter((d) => d.last_backup_status === 'never').length,
    off: devices.value.length - list.length,
    // 有未保存改动的台数。**只数 true** —— null 是"没检查过或不支持",
    // 把它算进"已保存"是在替设备做一个我们没验证过的保证
    unsaved: list.filter((d) => d.config_unsaved === true).length,
  }
})

// running vs startup 的差异明细
const unsavedOpen = ref(false)
const unsavedDevice = ref<DeviceRow | null>(null)

function showUnsaved(device: DeviceRow) {
  unsavedDevice.value = device
  unsavedOpen.value = true
}

async function loadDevices() {
  loading.value = true
  try {
    const { data } = await api.devices({ page_size: 200, ordering: 'order' })
    devices.value = data.results
    if (selected.value === null && backupDevices.value.length) {
      await select(backupDevices.value[0].id)
    }
  } catch (e) {
    message.error(errText(e))
  } finally {
    loading.value = false
  }
}

async function select(id: number) {
  selected.value = id
  versions.value = []
  versionsLoading.value = true
  try {
    const { data } = await api.deviceBackupInfo(id)
    versions.value = data.versions
  } catch (e) {
    message.error(errText(e))
  } finally {
    versionsLoading.value = false
  }
}

onMounted(async () => {
  await meta.load()
  await loadDevices()
})

async function backupNow(device: DeviceRow) {
  busy.value = device.id
  try {
    const { data } = await api.backupNow(device.id)
    message.success(data.detail, { duration: 6000 })
  } catch (e) {
    message.error(errText(e))
  } finally {
    busy.value = 0
  }
}

async function testChannel(device: DeviceRow) {
  busy.value = device.id
  try {
    const { data } = await api.testDeviceBackup(device.id)
    if (data.ok) message.success(data.detail, { duration: 10000 })
    else message.error(data.detail, { duration: 12000 })
  } catch (e) {
    message.error(errText(e))
  } finally {
    busy.value = 0
  }
}

// 当前正在看 diff 的版本,和对比基准 —— **基准可以换**:
// "和上一版比"回答"这次改了什么","和三个月前那版比"回答
// "从那次故障之后这台设备被动过什么",后者是复盘时真正要问的
const diffVersion = ref<BackupVersion | null>(null)
const diffAgainst = ref<number | null>(null)

/** 可选的对比基准:同一台设备里**比当前版本早**的那些。 */
const againstOptions = computed(() => {
  if (!diffVersion.value) return []
  const cur = diffVersion.value
  return versions.value
    .filter((v) => v.id !== cur.id && new Date(v.ts).getTime() <= new Date(cur.ts).getTime())
    .map((v) => ({
      label: `${dateTimeOf(v.ts)} · ${v.short_hash}${v.is_first ? '(基线)' : ''}`,
      value: v.id,
    }))
})

async function showDiff(version: BackupVersion, against?: number) {
  diffOpen.value = true
  diffLoading.value = true
  diff.value = null
  diffVersion.value = version
  diffAgainst.value = against ?? null
  diffTitle.value = `${currentDevice.value?.name || ''} · ${version.short_hash} 的变更`
  try {
    const { data } = await api.backupDiff(version.id, against)
    diff.value = data
    // 后端在 against 留空时自己找上一版,把它回填到选择框里,
    // 否则那个框是空的而下面明明显示着一份 diff
    if (against === undefined && data.from) diffAgainst.value = data.from
  } catch (e) {
    message.error(errText(e))
    diffOpen.value = false
  } finally {
    diffLoading.value = false
  }
}

function changeBase(id: number) {
  if (diffVersion.value) void showDiff(diffVersion.value, id)
}

async function showText(version: BackupVersion) {
  textOpen.value = true
  textLoading.value = true
  fullText.value = null
  try {
    const { data } = await api.backupVersion(version.id)
    fullText.value = data
  } catch (e) {
    message.error(errText(e))
    textOpen.value = false
  } finally {
    textLoading.value = false
  }
}

/** diff 的行分类,决定颜色。**只按行首字符分,不解析 hunk 内容。** */
function diffClass(line: string): string {
  if (line.startsWith('+++') || line.startsWith('---')) return 'meta'
  if (line.startsWith('@@')) return 'hunk'
  if (line.startsWith('+')) return 'add'
  if (line.startsWith('-')) return 'del'
  if (line.startsWith('...')) return 'trunc'
  return ''
}

const deviceColumns: DataTableColumns<DeviceRow> = [
  { title: '设备', key: 'name', sorter: 'default', minWidth: 150,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, r.name),
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
        `${r.mgmt_ip} · ${r.model_label || r.model}`),
    ]) },
  { title: '设备状态', key: 'state', sorter: 'default', width: 84,
    render: (r) => h(StateDot, { state: r.state, label: true }) },
  { title: '备份结果', key: 'last_backup_status', sorter: 'default', width: 148,
    render: (r) => {
      const color = r.last_backup_status === 'ok' ? STATE.up
        : r.last_backup_status === 'failed' ? STATE.down : STATE.unknown
      return h('div', [
        h('div', { style: `font-size:11.5px;font-weight:700;color:${color}` },
          meta.label('backup_status', r.last_backup_status)),
        h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' },
          r.last_backup_at ? ago(r.last_backup_at) : '还没跑过'),
      ])
    } },
  { title: '配置已保存?', key: 'config_unsaved', sorter: 'default', width: 128,
    render: (r) => {
      // 三态。**null 显示「未检查」,不显示「已保存」** ——
      // 后者是一个我们没验证过的保证
      if (r.config_unsaved === null) {
        const why = !r.profile_supports?.unsaved_check
          ? '这款型号没有「启动配置」的概念(FortiOS 改完即存)'
          : !r.backup_check_unsaved
            ? '这台设备关掉了未保存检查'
            : '还没检查过,或者上次检查没成功'
        return h('span', { style: 'font-size:10.5px;color:var(--cy-ink-3)', title: why }, '未检查')
      }
      if (!r.config_unsaved) {
        return h('span', { style: `font-size:11px;color:${STATE.up}`, title: 'running 和 startup 一致' },
          '已保存')
      }
      return h(NButton, {
        size: 'tiny', ghost: true, type: 'warning',
        title: '点开看 running 和 startup 差了哪些行',
        onClick: () => showUnsaved(r),
      }, () => `未保存 ${r.config_unsaved_lines ?? '?'} 行`)
    } },
  { title: '间隔', key: 'backup_interval_hours', sorter: 'default', width: 68, className: 'num',
    render: (r) => h('span', { style: 'font-size:11.5px' }, `${r.backup_interval_hours}h`) },
  { title: '保留', key: 'backup_keep', sorter: 'default', width: 62, className: 'num',
    render: (r) => h('span', { style: 'font-size:11.5px' }, `${r.backup_keep} 版`) },
  { title: '凭据', key: 'creds', width: 92,
    render: (r) => h('div', { style: 'display:flex;gap:3px;flex-wrap:wrap' }, [
      r.has_ssh_credential ? h(NTag, { size: 'tiny', bordered: false }, () => 'SSH') : null,
      // FortiGate 有 API Token 时备份优先走 API:那个端点给的是能直接
      // 回灌的备份文件,CLI 的 show 输出不是
      r.has_api_token ? h(NTag, { size: 'tiny', bordered: false, type: 'info' }, () => 'API') : null,
    ]) },
  { title: '最后错误', key: 'last_backup_error', sorter: 'default', minWidth: 180,
    render: (r) => h('span', {
      style: `font-size:10.5px;color:${r.last_backup_error ? STATE.down : 'var(--cy-ink-3)'};line-height:1.5`,
    }, r.last_backup_error || '—') },
  { title: '操作', key: 'act', width: 210, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', ghost: true, type: selected.value === r.id ? 'primary' : 'default',
        onClick: () => select(r.id) }, () => '看版本'),
      h(NButton, { size: 'tiny', ghost: true, loading: busy.value === r.id,
        onClick: () => testChannel(r) }, () => '测通道'),
      h(NButton, { size: 'tiny', ghost: true, onClick: () => backupNow(r) }, () => '立即备份'),
    ]) },
]

const versionColumns: DataTableColumns<BackupVersion> = [
  { title: '首次出现', key: 'ts', sorter: 'default', width: 152,
    render: (r) => h('div', [
      h('div', { style: "font-size:11.5px;font-family:'JetBrains Mono',monospace" }, dateTimeOf(r.ts)),
      h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' }, ago(r.ts)),
    ]) },
  { title: '版本', key: 'short_hash', sorter: 'default', width: 118,
    render: (r) => h('div', { style: 'display:flex;gap:5px;align-items:center' }, [
      h('span', { style: "font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--cy-cyan)" },
        r.short_hash),
      r.is_first ? h(NTag, { size: 'tiny', bordered: false }, () => '首版') : null,
    ]) },
  { title: '变更', key: 'change', sorter: 'default', width: 108,
    render: (r) => {
      if (r.is_first) {
        return h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, '基线')
      }
      // 首版之外一定有 diff 计数;没有说明是老数据,显示 — 而不是 0
      if (r.lines_added === null && r.lines_removed === null) {
        return h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, '—')
      }
      return h('span', { style: "font-size:11.5px;font-family:'JetBrains Mono',monospace" }, [
        h('span', { style: `color:${STATE.up}` }, `+${r.lines_added ?? 0}`),
        ' ',
        h('span', { style: `color:${STATE.down}` }, `-${r.lines_removed ?? 0}`),
      ])
    } },
  { title: '最后确认', key: 'last_seen_at', sorter: 'default', width: 150,
    render: (r) => h('div', [
      h('div', { style: 'font-size:11px;color:var(--cy-ink-2)' }, ago(r.last_seen_at)),
      // seen_count = 这个版本被连续确认了多少次没变。1 次 = 刚出现
      h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' }, `确认 ${int(r.seen_count)} 次`),
    ]) },
  { title: '大小', key: 'size_bytes', sorter: 'default', width: 118, className: 'num',
    render: (r) => h('div', [
      h('div', { style: "font-size:11px;font-family:'JetBrains Mono',monospace" }, bytes(r.size_bytes)),
      h('div', { style: 'font-size:10px;color:var(--cy-ink-3)' }, `${int(r.line_count)} 行`),
    ]) },
  { title: '通道', key: 'method', sorter: 'default', width: 62,
    render: (r) => h(NTag, { size: 'tiny', bordered: false }, () => r.method.toUpperCase()) },
  { title: '操作', key: 'act', width: 200, fixed: 'right',
    render: (r) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', ghost: true, disabled: r.is_first,
        onClick: () => showDiff(r) }, () => '看变更'),
      h(NButton, { size: 'tiny', ghost: true, onClick: () => showText(r) }, () => '看全文'),
      // 下载走普通链接,不经过 axios —— 会话是 cookie,浏览器直接带上,
      // 而且这样能用后端设的文件名
      h('a', {
        href: api.backupDownloadUrl(r.id),
        class: 'dl-link',
        download: '',
      }, '下载'),
    ]) },
]
</script>

<template>
  <div class="bk">
    <!-- ============ 顶部统计 ============ -->
    <div class="tiles">
      <StatTile label="已开启备份" :value="stats.total" unit="台" :dim-zero="false"
                :foot="stats.off ? `另有 ${stats.off} 台未开启` : '全部设备都开了'" />
      <StatTile label="备份失败" :value="stats.failed" unit="台" :color="STATE.down"
                foot="一个悄悄坏掉的备份等于没有备份" />
      <StatTile label="从未备份" :value="stats.never" unit="台" :color="STATE.unknown"
                foot="刚开启,还没到第一个周期" />
      <StatTile label="配置未保存" :value="stats.unsaved" unit="台" :color="STATE.degraded"
                foot="改了但没 write memory —— 设备一重启就丢" />
      <StatTile
        label="当前设备版本数"
        :value="selected === null ? null : versions.length"
        unit="个"
        :dim-zero="false"
        foot="配置没变不新增版本,所以版本数 = 变更次数"
      />
    </div>

    <!-- ============ 设备列表 ============ -->
    <CyberPanel
      title="配置备份"
      :subtitle="`${stats.total} 台已开启 · 交换机 / 路由器 / 防火墙`"
      flush
    >
      <template #actions>
        <NButton size="small" ghost :loading="loading" @click="loadDevices()">刷新</NButton>
      </template>
      <NDataTable
        :columns="deviceColumns" :data="backupDevices" :loading="loading"
        size="small" :bordered="false" :single-line="false" :scroll-x="1260"
        :pagination="{ pageSize: 10 }"
      />
      <div v-if="!backupDevices.length && !loading" class="cy-empty">
        还没有设备开启配置备份。到<b>配置中心 → 网络设备</b>编辑设备,
        打开「启用配置备份」—— 需要 SSH 凭据(FortiGate 也可以只填 API Token)。<br>
        备份走的是 <code>show running-config</code> / FortiOS 的 <code>show</code>,
        <b>和采集通道无关</b>:一台用 SNMP 采指标的交换机照样能备份配置。
      </div>
    </CyberPanel>

    <!-- ============ 版本列表 ============ -->
    <CyberPanel
      v-if="currentDevice"
      :title="`${currentDevice.name} 的配置版本`"
      subtitle="一行一个版本 —— 配置没变不会新增行,只把「最后确认」往后推"
      flush
    >
      <template #actions>
        <span class="hint">
          保留最近 {{ currentDevice.backup_keep }} 个版本 · 每 {{ currentDevice.backup_interval_hours }} 小时检查一次
        </span>
      </template>
      <NDataTable
        :columns="versionColumns" :data="versions" :loading="versionsLoading"
        size="small" :bordered="false" :single-line="false" :scroll-x="960"
        :pagination="{ pageSize: 15 }"
      />
      <div v-if="!versions.length && !versionsLoading" class="cy-empty">
        这台设备还没有任何版本。点「立即备份」跑一次,或者等下一个备份周期。<br>
        备份不通的话先点「测通道」—— 它的报错是指向性的(权限不足 / 需要 enable / 型号不支持)。
      </div>
    </CyberPanel>

    <!-- ============ diff 弹窗 ============ -->
    <NModal
      v-model:show="diffOpen" preset="card" :bordered="false"
      :title="diffTitle" style="width: min(1100px, 96vw)"
    >
      <div v-if="diffLoading" class="modal-loading">读取差异…</div>
      <template v-else-if="diff">
        <div class="diff-head">
          <template v-if="diff.from">
            <span class="cy-mono">{{ dateTimeOf(diff.from_ts) }}</span>
            <span class="arrow">→</span>
            <span class="cy-mono">{{ dateTimeOf(diff.to_ts) }}</span>
            <span class="counts cy-mono">
              <b class="add">+{{ diff.lines_added ?? 0 }}</b>
              <b class="del">-{{ diff.lines_removed ?? 0 }}</b>
            </span>
          </template>
          <span v-else>{{ diff.detail }}</span>
        </div>
        <!-- 换基准:和上一版比是"这次改了什么",和更早的版本比是
             "从那时候起这台设备被动过什么" —— 复盘时问的是后者 -->
        <div v-if="againstOptions.length" class="base-pick">
          <span class="bp-label">对比基准</span>
          <NSelect
            :value="diffAgainst" :options="againstOptions" size="small"
            style="width: 300px" @update:value="changeBase"
          />
          <span class="bp-hint">选更早的版本 → 看"从那时起这台设备被动过什么"</span>
        </div>
        <!-- 比对的是**清洗过**的文本:每次导出都变的时间戳/字节数行已经去掉了,
             否则每个 diff 的头几行都是噪声,真改动藏在后面 -->
        <div class="diff-note">
          比对的是清洗后的文本(去掉了每次导出都变的时间戳、字节数、ntp clock-period 之类)。
          下载下来的是原始文本,能直接回灌。
        </div>
        <pre v-if="diff.lines.length" class="diff"><code
          v-for="(line, i) in diff.lines" :key="i"
          :class="diffClass(line)"
        >{{ line }}</code></pre>
        <div v-else-if="diff.from" class="cy-empty">两个版本的清洗后内容完全一致</div>
      </template>
      <template #footer>
        <NSpace justify="end">
          <NButton size="small" @click="diffOpen = false">关闭</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- ============ 未保存的配置 ============ -->
    <NModal
      v-model:show="unsavedOpen" preset="card" :bordered="false"
      :title="`${unsavedDevice?.name || ''} · 未保存的配置`"
      style="width: min(1000px, 95vw)"
    >
      <template v-if="unsavedDevice">
        <div class="diff-head">
          <span>
            running-config 和 startup-config 相差
            <b class="del">{{ unsavedDevice.config_unsaved_lines }}</b> 行
          </span>
          <span class="counts">检查于 {{ dateTimeOf(unsavedDevice.config_checked_at) }}</span>
        </div>
        <div class="diff-note">
          设备**一重启这些改动就没了**。登上去执行
          <code>write memory</code>(或 <code>copy running-config startup-config</code>)。<br>
          如果这里长期显示"未保存"而你确认已经保存过,那是 running 和 startup 之间
          天生的无害差异 —— 把那几行的正则加到型号画像的
          <code>backup_volatile</code> 里,**不要把这个检查关掉**。
        </div>
        <pre v-if="unsavedDevice.unsaved_diff?.length" class="diff"><code
          v-for="(line, i) in unsavedDevice.unsaved_diff" :key="i"
          :class="diffClass(line)"
        >{{ line }}</code></pre>
        <div v-else class="cy-empty">这次没有留下 diff 明细(下一个备份周期会补上)</div>
      </template>
      <template #footer>
        <NSpace justify="end">
          <NButton size="small" @click="unsavedOpen = false">关闭</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- ============ 全文弹窗 ============ -->
    <NModal
      v-model:show="textOpen" preset="card" :bordered="false"
      :title="`配置全文 · ${fullText?.short_hash || ''}`" style="width: min(1100px, 96vw)"
    >
      <div v-if="textLoading" class="modal-loading">读取全文…</div>
      <template v-else-if="fullText">
        <div class="diff-head">
          <span class="cy-mono">{{ dateTimeOf(fullText.ts) }}</span>
          <span class="counts cy-mono">{{ int(fullText.line_count) }} 行 · {{ bytes(fullText.size_bytes) }}</span>
        </div>
        <pre class="full"><code>{{ fullText.content }}</code></pre>
      </template>
      <template #footer>
        <NSpace justify="end">
          <a v-if="fullText" :href="api.backupDownloadUrl(fullText.id)" class="dl-link" download>下载</a>
          <NButton size="small" @click="textOpen = false">关闭</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.bk { display: flex; flex-direction: column; gap: 14px; }
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 10px;
}
.hint { font-size: 10.5px; color: var(--cy-ink-3); }
.modal-loading { font-size: 12px; color: var(--cy-ink-3); padding: 12px 0; }

.diff-head {
  display: flex;
  align-items: baseline;
  gap: 9px;
  font-size: 11.5px;
  color: var(--cy-ink-2);
  flex-wrap: wrap;
}
.arrow { color: var(--cy-cyan); }
.counts { margin-left: auto; display: flex; gap: 8px; font-size: 11.5px; }
.counts .add { color: var(--cy-up); }
.counts .del { color: var(--cy-down); }

.base-pick {
  display: flex;
  align-items: center;
  gap: 9px;
  margin: 9px 0 4px;
  flex-wrap: wrap;
}
.bp-label { font-size: 11px; color: var(--cy-ink-3); letter-spacing: 0.05em; }
.bp-hint { font-size: 10px; color: var(--cy-ink-3); }

.diff-note {
  font-size: 10.5px;
  color: var(--cy-ink-3);
  line-height: 1.6;
  margin: 7px 0 9px;
  padding-left: 8px;
  border-left: 2px solid rgba(var(--cy-cyan-rgb), 0.35);
}

/* diff 和全文都是**数据区,不加任何动画** —— 读代码时底下在动会看错行 */
.diff, .full {
  margin: 0;
  max-height: 62vh;
  overflow: auto;
  background: rgba(var(--cy-body-rgb), 0.6);
  border: 1px solid rgba(var(--cy-cyan-rgb), 0.14);
  padding: 9px 11px;
}
.diff code, .full code {
  display: block;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11.5px;
  line-height: 1.65;
  white-space: pre;
  color: var(--cy-ink-2);
}
.diff code.add { color: var(--cy-up); background: rgba(var(--cy-up-rgb), 0.09); }
.diff code.del { color: var(--cy-down); background: rgba(var(--cy-down-rgb), 0.09); }
.diff code.hunk { color: var(--cy-violet); }
.diff code.meta { color: var(--cy-ink-3); }
.diff code.trunc { color: var(--cy-degraded); }

.dl-link {
  font-size: 11px;
  color: var(--cy-cyan);
  text-decoration: none;
  border: 1px solid rgba(var(--cy-cyan-rgb), 0.45);
  padding: 1px 7px;
  line-height: 18px;
  transition: background 0.15s ease;
}
.dl-link:hover { background: rgba(var(--cy-cyan-rgb), 0.12); }
</style>
