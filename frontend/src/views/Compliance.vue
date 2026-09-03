<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import { NButton, NDataTable, NSwitch, NTag, useMessage } from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import SeverityTag from '@/components/cyber/SeverityTag.vue'
import { api, errText } from '@/api'
import type { ComplianceRow } from '@/api'
import { ago } from '@/composables/useFormat'
import { STATE } from '@/theme'

/**
 * 配置合规基线。
 *
 * ## 「基线」和「diff」回答的是两个问题
 *
 * 配置备份的 diff 告诉你**变了什么**;基线告诉你**缺了什么**。
 * 后者更容易被忽略,因为它没有任何症状:telnet 一直开着、community 还是
 * `public`、口令是明文、日志没往外送、NTP 没配所以日志时间是错的 ——
 * 设备跑得好好的,直到出事时才发现没有可用的日志,或者审计时被一条条挑出来。
 *
 * 这一页跑在**已经备份下来的配置**上,不需要任何新采集。
 *
 * ## 「没检查」必须和「没问题」分开
 *
 * 两种情况会 `checked=false`:这个厂商还没有规则、或者这台设备还没有备份。
 * 两种都**不等于合规** —— 页面上单独一档灰色显示,而不是混进"0 条问题"里。
 * 一个 0 条问题的设备如果其实是没检查过,那这一页就是在骗人。
 *
 * ## 每条发现都带「怎么改」
 *
 * 一条不知道怎么修的告警等于噪声。所以展开每条都有 why(为什么这是问题)
 * 和 fix(该敲什么命令),以及**命中的具体行号**。
 */

const message = useMessage()
const loading = ref(false)
const rows = ref<ComplianceRow[]>([])
const totals = ref<Record<string, number> | null>(null)
const ruleTotal = ref(0)
const expanded = ref<number[]>([])
const hideClean = ref(true)

async function load() {
  loading.value = true
  try {
    const { data } = await api.compliance()
    rows.value = data.devices
    totals.value = data.totals
    ruleTotal.value = data.rule_total
    // 默认展开有严重问题的那些 —— 那是要立刻看的
    expanded.value = data.devices.filter((d) => d.critical > 0).map((d) => d.device_id)
  } catch (e) {
    message.error(errText(e))
  } finally {
    loading.value = false
  }
}

onMounted(load)

/** 有问题的排前面,没检查的排最后 —— 没检查的不是"好",但也不是待办 */
const visible = computed(() => {
  const list = [...rows.value].sort((a, b) => {
    if (a.checked !== b.checked) return a.checked ? -1 : 1
    return (b.critical * 100 + b.warning * 10 + b.info) - (a.critical * 100 + a.warning * 10 + a.info)
  })
  return hideClean.value ? list.filter((d) => !d.checked || d.findings.length) : list
})

const columns: DataTableColumns<ComplianceRow> = [
  { type: 'expand',
    expandable: (r) => r.findings.length > 0 || !r.checked,
    renderExpand: (r) => {
      if (!r.checked) {
        return h('div', { class: 'reason' }, r.reason)
      }
      return h('div', { class: 'findings' }, r.findings.map((f) =>
        h('div', { class: 'finding', key: f.key }, [
          h('div', { class: 'f-head' }, [
            h(SeverityTag, { severity: f.severity }),
            h('span', { class: 'f-label' }, f.label),
            h('span', { class: 'f-kind' },
              f.kind === 'missing' ? '(从来没配)' : `(${f.hit_count} 处)`),
          ]),
          h('div', { class: 'f-why' }, f.why),
          h('div', { class: 'f-fix' }, [h('b', null, '怎么改:'), ` ${f.fix}`]),
          f.hits.length
            ? h('div', { class: 'f-hits' }, f.hits.map((hit) =>
                h('div', { class: 'f-hit', key: hit.line }, [
                  h('span', { class: 'f-line' }, `第 ${hit.line} 行`),
                  h('code', null, hit.text),
                ])))
            : null,
        ]),
      ))
    } },
  { title: '设备', key: 'device_name', sorter: 'default', minWidth: 170,
    render: (r) => h('div', [
      h('div', { style: 'font-size:12.5px;color:var(--cy-ink)' }, r.device_name),
      h('div', { style: "font-size:10.5px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
        `${r.mgmt_ip} · ${r.model_label}`),
    ]) },
  { title: '厂商', key: 'vendor_label', sorter: 'default', width: 88,
    render: (r) => h('span', { style: 'font-size:11.5px;color:var(--cy-ink-2)' }, r.vendor_label) },
  { title: '结论', key: 'verdict', sorter: 'default', width: 172,
    render: (r) => {
      // **没检查 ≠ 合规。**单独一档灰色,不混进"0 条问题"
      if (!r.checked) {
        return h('span', {
          style: 'font-size:11px;color:var(--cy-ink-3)', title: r.reason,
        }, r.supported ? '未检查(没有备份)' : '未检查(没有规则)')
      }
      if (!r.findings.length) {
        return h('span', { style: `font-size:11.5px;font-weight:700;color:${STATE.up}` },
          `${r.passed} 条规则全部通过`)
      }
      return h('div', { style: 'display:flex;gap:4px;flex-wrap:wrap' }, [
        r.critical
          ? h(NTag, { size: 'tiny', bordered: false,
              style: `color:${STATE.down};border:1px solid ${STATE.down}` }, () => `严重 ${r.critical}`)
          : null,
        r.warning
          ? h(NTag, { size: 'tiny', bordered: false,
              style: `color:${STATE.degraded};border:1px solid ${STATE.degraded}` }, () => `警告 ${r.warning}`)
          : null,
        r.info
          ? h(NTag, { size: 'tiny', bordered: false }, () => `提示 ${r.info}`)
          : null,
      ])
    } },
  { title: '通过 / 规则', key: 'passed', sorter: 'default', width: 104, className: 'num',
    render: (r) => r.checked
      ? h('span', { style: "font-size:11.5px;font-family:'JetBrains Mono',monospace" },
          `${r.passed} / ${r.rule_count}`)
      : h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, `— / ${r.rule_count}`),
  },
  { title: '基于哪份配置', key: 'backup_at', sorter: 'default', minWidth: 148,
    render: (r) => r.backup_at
      ? h('div', [
          h('div', { style: 'font-size:11px;color:var(--cy-ink-2)' }, ago(r.backup_at)),
          h('div', { style: "font-size:10px;color:var(--cy-ink-3);font-family:'JetBrains Mono',monospace" },
            r.backup_hash),
        ])
      : h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, '没有备份'),
  },
]
</script>

<template>
  <div class="comp">
    <div class="tiles">
      <StatTile label="已检查" :value="totals?.checked ?? null" unit="台" :dim-zero="false"
                :foot="totals?.not_checked ? `另有 ${totals.not_checked} 台未检查` : '全部设备都检查了'" />
      <StatTile label="严重" :value="totals?.critical ?? null" unit="项" :color="STATE.down"
                foot="telnet / 默认 community / 明文口令这一类" />
      <StatTile label="警告" :value="totals?.warning ?? null" unit="项" :color="STATE.degraded"
                foot="没配 NTP / 日志没外送 / 没配 AAA" />
      <StatTile label="完全通过" :value="totals?.clean ?? null" unit="台" :color="STATE.up"
                :foot="`共 ${ruleTotal} 条基线规则`" />
    </div>

    <CyberPanel
      title="配置合规基线"
      subtitle="在已经备份下来的配置上跑 —— 备份的 diff 告诉你「变了什么」,基线告诉你「缺了什么」"
      flush
    >
      <template #actions>
        <label class="tgl">
          <NSwitch v-model:value="hideClean" size="small" />
          <span>只看有问题的</span>
        </label>
        <NButton size="small" ghost :loading="loading" @click="load()">重新检查</NButton>
      </template>

      <NDataTable
        v-model:expanded-row-keys="expanded"
        :columns="columns" :data="visible" :loading="loading"
        :row-key="(r: ComplianceRow) => r.device_id"
        size="small" :bordered="false" :single-line="false" :scroll-x="920"
      />
      <div v-if="!visible.length && !loading" class="cy-empty">
        <template v-if="rows.length">
          所有已检查的设备都通过了基线 —— 关掉「只看有问题的」看完整清单。
        </template>
        <template v-else>
          还没有设备可以检查。基线跑在**备份下来的配置**上,所以先到
          <b>配置中心 → 网络设备</b>打开「启用配置备份」,备一次之后回来看。<br>
          目前有规则的厂商:<b>Cisco</b> / <b>Fortinet</b> ——
          别的厂商会显示「未检查(没有规则)」,那**不等于合规**。
        </template>
      </div>
    </CyberPanel>
  </div>
</template>

<style scoped>
.comp { display: flex; flex-direction: column; gap: 14px; }
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 10px;
}
.tgl {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11.5px;
  color: var(--cy-ink-2);
  cursor: pointer;
}

.comp :deep(.reason) {
  font-size: 11.5px;
  color: var(--cy-ink-3);
  line-height: 1.7;
  padding: 4px 2px;
}
.comp :deep(.findings) { display: flex; flex-direction: column; gap: 12px; padding: 4px 2px; }
.comp :deep(.finding) {
  padding-left: 9px;
  border-left: 2px solid rgba(var(--cy-cyan-rgb), 0.3);
}
.comp :deep(.f-head) {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 3px;
}
.comp :deep(.f-label) { font-size: 12.5px; color: var(--cy-ink); font-weight: 600; }
.comp :deep(.f-kind) { font-size: 10.5px; color: var(--cy-ink-3); }
.comp :deep(.f-why) { font-size: 11px; color: var(--cy-ink-2); line-height: 1.65; }
.comp :deep(.f-fix) { font-size: 11px; color: var(--cy-ink-2); line-height: 1.65; margin-top: 2px; }
.comp :deep(.f-fix b) { color: var(--cy-cyan); }
.comp :deep(.f-hits) { margin-top: 5px; display: flex; flex-direction: column; gap: 1px; }
.comp :deep(.f-hit) { display: flex; gap: 9px; align-items: baseline; }
.comp :deep(.f-line) {
  font-size: 10px;
  color: var(--cy-ink-3);
  min-width: 56px;
  font-family: 'JetBrains Mono', monospace;
}
.comp :deep(.f-hit code) {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--cy-degraded);
  word-break: break-all;
}
</style>
