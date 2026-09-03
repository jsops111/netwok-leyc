<script setup lang="ts">
import { computed, h, onMounted, ref } from 'vue'
import { NButton, NDataTable, NInput, NSwitch, NTag, useMessage } from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import CyberPanel from '@/components/cyber/CyberPanel.vue'
import StatTile from '@/components/cyber/StatTile.vue'
import StateDot from '@/components/cyber/StateDot.vue'
import { api, errText } from '@/api'
import type { AclBoard, PolicyRow } from '@/api'
import { ago, dateTimeOf, int } from '@/composables/useFormat'
import { STATE } from '@/theme'

/**
 * Cisco 访问控制(ACL)—— **和 FortiGate 的策略页分开的一页**。
 *
 * 两者存在同一张表(它们回答同一个问题:谁到谁、什么服务、放行还是拒绝),
 * 但**看的方式完全不一样**,而那三个差别塞进策略页里说不清楚:
 *
 * 1. **ACL 不带接口对。**FortiGate 的一条策略自带源/目的接口,而 ACL 只是
 *    一张规则表 —— 它作用在哪要看 `ip access-group`。所以这一页的第一层是
 *    **ACL 名字**,并且显示"绑在哪几个接口的哪个方向"。
 * 2. **一个接口都没绑的 ACL 完全不生效。**这是 FortiGate 上不存在的状态,
 *    而它是这一页最值得先看见的一条 —— 有人配了忘了挂上去。
 * 3. **末尾那条 `deny ip any any` 是隐含的**,`show` 里不出现。我们补出来了
 *    (否则人看着一张全是 permit 的表会以为没写到的流量是放行的),
 *    但它必须标出来 —— 否则人会去设备上找这一行然后找不到。
 *
 * 还有一条掩码上的差别,在后端处理完了但值得知道:**IOS 的 ACL 用通配符
 * 掩码,object-group 用子网掩码**,同一台设备上两种混着用。页面上看到的
 * 一律是 CIDR。
 */

const message = useMessage()
const board = ref<AclBoard | null>(null)
const loading = ref(false)
const keyword = ref('')
const problemOnly = ref(false)
const hideImplicit = ref(false)
const expanded = ref<string | null>(null)

async function load() {
  loading.value = true
  try {
    const { data } = await api.aclBoard()
    board.value = data
    // 默认展开第一个**有问题的** ACL —— 一台核心交换机上十几个 ACL,
    // 全折叠等于什么都看不见,而全展开又是一屏规则
    for (const dev of data.devices) {
      const bad = dev.acls.find((a) => a.unbound || a.wide_open || a.no_log)
      if (bad) { expanded.value = `${dev.device_id}/${bad.name}`; break }
    }
  } catch (e) {
    message.error(errText(e))
  } finally {
    loading.value = false
  }
}
onMounted(load)

const totals = computed(() => board.value?.totals ?? null)

const shownDevices = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  return (board.value?.devices ?? [])
    .map((dev) => ({
      ...dev,
      acls: dev.acls.filter((a) => {
        if (problemOnly.value && !(a.unbound || a.wide_open || a.no_log)) return false
        if (!kw) return true
        return a.name.toLowerCase().includes(kw)
          || dev.device_name.toLowerCase().includes(kw)
          || a.bindings.some((b) => b.interface.toLowerCase().includes(kw))
      }),
    }))
    .filter((dev) => dev.acls.length)
})

function toggle(key: string) {
  expanded.value = expanded.value === key ? null : key
}

function rulesOf(acl: AclBoard['devices'][0]['acls'][0]): PolicyRow[] {
  return hideImplicit.value ? acl.rules.filter((r) => !r.implicit) : acl.rules
}

/** 规则表的列。**顺序就是匹配顺序** —— ACL 是先匹配先生效 */
const ruleColumns: DataTableColumns<PolicyRow> = [
  { title: '行号', key: 'policy_id', sorter: 'default', width: 72, className: 'num',
    render: (r) => h('span', {
      class: 'mono',
      // 隐含那一条的行号是**我们编的**(排在最后一条真规则之后),
      // 设备上没有这个号 —— 标出来
      title: r.implicit ? '这个行号是平台编的,设备上没有这一行' : '设备上的行号',
      style: r.implicit ? 'color:var(--cy-ink-3)' : '',
    }, String(r.policy_id)) },
  { title: '动作', key: 'action', sorter: 'default', width: 92,
    render: (r) => h('div', { style: 'display:flex;gap:4px;align-items:center' }, [
      h(NTag, {
        size: 'tiny', bordered: false,
        style: `color:${r.action === 'accept' ? STATE.up : STATE.down};`
          + `border:1px solid ${r.action === 'accept' ? STATE.up : STATE.down}`,
      }, () => (r.action === 'accept' ? 'permit' : 'deny')),
      // **隐含规则必须标出来** —— 否则人会去设备上找这一行然后找不到
      r.implicit
        ? h(NTag, {
            size: 'tiny', bordered: false,
            style: 'color:var(--cy-ink-3);border:1px dashed var(--cy-ink-3)',
            title: '每个 ACL 末尾都有这一条,show 的输出里不显示 —— 平台补出来的',
          }, () => '隐含')
        : null,
    ]) },
  { title: '源', key: 'src_addr', sorter: 'default', minWidth: 150,
    render: (r) => h('span', { class: 'mono' }, (r.src_addr || []).join(', ') || 'any') },
  { title: '目的', key: 'dst_addr', sorter: 'default', minWidth: 150,
    render: (r) => h('span', { class: 'mono' }, (r.dst_addr || []).join(', ') || 'any') },
  { title: '服务', key: 'service', sorter: 'default', minWidth: 110,
    render: (r) => h('span', { class: 'mono' }, (r.service || []).join(', ') || 'IP') },
  { title: '日志', key: 'log_traffic', width: 76,
    render: (r) => (r.log_traffic
      ? h('span', { style: 'font-size:11px;color:var(--cy-ink-2)' }, 'log')
      // **IOS 的 ACE 默认不记日志** —— 放行且不记日志的那一类要标出来
      : h('span', {
          style: `font-size:11px;color:${r.logging_off ? STATE.degraded : 'var(--cy-ink-3)'}`,
          title: r.logging_off ? '放行但不记日志 —— 出事之后查不出来源' : '',
        }, r.logging_off ? '不记录' : '—')) },
  { title: '风险', key: 'permissive_level', width: 96,
    render: (r) => (r.permissive_level === 'critical'
      ? h(NTag, {
          size: 'tiny', bordered: false,
          style: `color:${STATE.down};border:1px solid ${STATE.down}`,
          title: '源/目的/服务都是任意的 permit —— 等于这个 ACL 在这里没有限制,'
            + '而且它后面的规则全都到不了',
        }, () => '过宽')
      : r.permissive_level === 'warning'
        ? h(NTag, {
            size: 'tiny', bordered: false,
            style: `color:${STATE.degraded};border:1px solid ${STATE.degraded}`,
          }, () => '偏宽')
        : h('span', { style: 'font-size:11px;color:var(--cy-ink-3)' }, '—')) },
  { title: '命中', key: 'hit_count', sorter: 'default', width: 110, className: 'num',
    render: (r) => {
      // 三态。**null 是"未知"不是 0** —— 老 IOS 不带 matches
      if (r.hit_count === null) {
        return h('span', {
          style: 'font-size:10.5px;color:var(--cy-ink-3)',
          title: '这一行没有 matches 计数(隐含规则,或者这个固件不报)',
        }, '未知')
      }
      return h('span', {
        class: 'mono',
        style: `font-weight:700;color:${r.hit_count === 0 ? STATE.degraded : 'var(--cy-ink)'}`,
        // **IOS 的 matches 是自设备启动以来的累计**,而且 clear 会归零 ——
        // 和 FortiGate 的命中数语义不完全一样,别直接拿去下"从未用过"的结论
        title: 'IOS 的 matches 是自设备启动以来的累计,'
          + '`clear ip access-list counters` 会归零',
      }, r.hit_count === 0 ? '从未命中' : int(r.hit_count))
    } },
]
</script>

<template>
  <div class="acl">
    <!-- 这一页和策略页的区别,写在最上面 —— 两个页面看着像同一种东西 -->
    <div class="lead">
      Cisco 的访问控制。和<b>防火墙策略</b>那一页是<b>两种不同的东西</b>:
      FortiGate 的一条策略<b>自带源/目的接口对</b>,而 ACL 只是一张规则表 ——
      <b>它作用在哪要看 <code>ip access-group</code></b>。所以这一页按
      <b>ACL 分组</b>,并且显示每个 ACL 绑在哪几个接口的哪个方向。<br>
      <span class="dim">
        规则的<b>顺序就是匹配顺序</b>(先匹配先生效);每个 ACL 末尾那条
        <code>deny ip any any</code> 是<b>隐含的</b>,设备的 <code>show</code>
        里不显示 —— 平台补出来了并标着「隐含」。
      </span>
    </div>

    <div class="head">
      <div class="tiles">
        <StatTile label="设备" :value="totals?.devices ?? 0" unit="台" :dim-zero="false" />
        <StatTile label="ACL" :value="totals?.acls ?? 0" unit="个" :dim-zero="false" />
        <StatTile label="规则" :value="totals?.rules ?? 0" unit="条" :dim-zero="false"
                  foot="不含补出来的隐含规则" />
        <!-- **这一格最该先看** —— 没绑接口的 ACL 完全不生效 -->
        <StatTile label="没绑接口" :value="totals?.unbound_acls ?? 0" unit="个"
                  :color="STATE.down" foot="一个接口都没绑 = 完全不生效" />
        <StatTile label="过宽的 permit" :value="totals?.wide_open ?? 0" unit="条"
                  :color="STATE.down" foot="permit ip any any —— 后面的规则全到不了" />
        <StatTile label="放行不记日志" :value="totals?.no_log ?? 0" unit="条"
                  :color="STATE.degraded" foot="出事之后查不出来源" />
      </div>
      <div class="actions">
        <NButton size="tiny" ghost :loading="loading" @click="load">刷新</NButton>
      </div>
    </div>

    <div v-if="board?.devices_without_data.length" class="warn-note">
      <b>{{ board.devices_without_data.map((d) => d.device_name).join('、') }}</b>
      开了同步但<b>一条 ACL 都没拿到</b>。这不等于它们没有 ACL ——
      可能是 SSH 连不上、账号权限不够(<code>show ip access-lists</code> 要
      enable 或对应特权级),或者真的没配。
      <div v-for="d in board.devices_without_data" :key="d.device_id" class="dim small">
        {{ d.device_name }}:{{ d.last_error || '(没有错误信息)' }}
      </div>
    </div>

    <div class="filters">
      <NInput v-model:value="keyword" size="small" clearable
              placeholder="搜 ACL 名 / 设备 / 接口" style="width: 240px" />
      <label class="tgl">
        <NSwitch v-model:value="problemOnly" size="small" />
        <span>只看有问题的 ACL</span>
      </label>
      <label class="tgl">
        <NSwitch v-model:value="hideImplicit" size="small" />
        <span>隐藏隐含规则</span>
      </label>
    </div>

    <CyberPanel
      v-for="dev in shownDevices" :key="dev.device_id"
      :title="dev.device_name"
      :subtitle="`${dev.mgmt_ip} · ${dev.model_label} · ${dev.acls.length} 个 ACL · 同步于 ${dateTimeOf(dev.synced_at)}`"
      :level="dev.acls.some((a) => a.unbound || a.wide_open) ? 'warning' : 'normal'"
    >
      <template #actions>
        <StateDot :state="dev.state" label />
      </template>
      <div v-if="dev.last_error" class="err">{{ dev.last_error }}</div>

      <div
        v-for="acl in dev.acls" :key="acl.name"
        class="acl-box" :class="{ bad: acl.unbound || acl.wide_open }"
      >
        <div class="acl-head" @click="toggle(`${dev.device_id}/${acl.name}`)">
          <b class="mono2">{{ acl.name }}</b>
          <span class="dim">{{ acl.rule_count }} 条</span>
          <span class="dim">permit {{ acl.permit }} / deny {{ acl.deny }}</span>

          <!-- **绑定关系。**空的时候说的是"一个接口都没绑,不生效",
               这是这一页最该看见的一条 —— 不是留白 -->
          <span v-if="acl.bindings.length" class="bind">
            绑在
            <b v-for="(b, i) in acl.bindings" :key="i" class="mono2">
              {{ b.interface }} {{ b.direction }}{{ i < acl.bindings.length - 1 ? '、' : '' }}
            </b>
          </span>
          <span v-else class="bind unbound">
            ⚠ 一个接口都没绑 —— <b>这个 ACL 完全不生效</b>
          </span>

          <span v-if="acl.wide_open" class="chip crit">
            {{ acl.wide_open }} 条 permit ip any any
          </span>
          <span v-if="acl.no_log" class="chip warn">{{ acl.no_log }} 条不记日志</span>
          <!-- 命中统计三态:没有统计时那个筛选没有意义,说出来 -->
          <span v-if="acl.has_hit_stats && acl.never_hit" class="chip warn">
            {{ acl.never_hit }} 条从未命中
          </span>
          <span v-else-if="!acl.has_hit_stats" class="dim small">这个 ACL 没有命中计数</span>

          <span class="toggle">
            {{ expanded === `${dev.device_id}/${acl.name}` ? '收起' : '展开规则' }}
          </span>
        </div>

        <NDataTable
          v-if="expanded === `${dev.device_id}/${acl.name}`"
          :columns="ruleColumns" :data="rulesOf(acl)" size="small"
          :bordered="false" :single-line="false" :scroll-x="900"
          :row-props="(r: PolicyRow) => ({
            class: r.implicit ? 'implicit-row' : (r.permissive_level === 'critical' ? 'bad-row' : ''),
          })"
        />
      </div>
    </CyberPanel>

    <div v-if="board && !shownDevices.length" class="cy-empty">
      <template v-if="problemOnly || keyword">没有匹配的 ACL。</template>
      <template v-else>
        还没有同步到 Cisco 的 ACL。到<b>配置中心 → 网络设备</b>,给交换机
        (<b>核心交换机的 kind 是「交换机」不是「防火墙」,现在也能开了</b>)
        打开<b>「同步防火墙策略」</b>并填上 <b>SSH 凭据</b> ——
        Cisco 只能走 SSH,IOS 没有等价的只读 REST 接口。<br>
        <span class="dim">
          同步会一次拉四样:<code>show ip access-lists</code>(规则)、
          <code>access-group</code>(绑在哪个接口)、
          <code>ip nat inside source static</code>(映射,在「防火墙映射」页看)、
          <code>object-group</code>(主机组,在策略页的「对象查询」里查)。
        </span>
      </template>
    </div>
  </div>
</template>

<style scoped>
.acl { display: flex; flex-direction: column; gap: 14px; }

.lead {
  font-size: 11.5px; line-height: 1.75; color: var(--cy-ink-2);
  padding: 7px 12px;
  border-left: 2px solid var(--cy-cyan);
  background: color-mix(in srgb, var(--cy-cyan) 6%, transparent);
}
.dim { color: var(--cy-ink-3); }
.small { font-size: 10.5px; }
.lead code, .cy-empty code, .warn-note code {
  font-family: 'JetBrains Mono', monospace; font-size: 10.5px; color: var(--cy-cyan);
}

.head { display: flex; align-items: flex-end; justify-content: space-between; gap: 14px; flex-wrap: wrap; }
.tiles {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px; flex: 1; min-width: 320px;
}
.actions { display: flex; gap: 10px; }

.filters { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
.tgl { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: var(--cy-ink-2); }

.warn-note, .err {
  font-size: 11.5px; line-height: 1.65; padding: 6px 11px; border-left: 2px solid;
}
.warn-note {
  color: var(--cy-degraded); border-left-color: var(--cy-degraded);
  background: color-mix(in srgb, var(--cy-degraded) 7%, transparent);
}
.err {
  color: var(--cy-down); border-left-color: var(--cy-down);
  background: color-mix(in srgb, var(--cy-down) 6%, transparent);
  margin-bottom: 10px;
}

.acl-box {
  border: 1px solid var(--cy-line-soft);
  border-left: 3px solid var(--cy-line);
  margin-bottom: 8px;
}
/* 没绑接口 / 有 permit ip any any 的整块标红 —— 一台交换机上十几个 ACL,
   靠某一格的颜色找不过来 */
.acl-box.bad { border-left-color: var(--cy-down); }
.acl-head {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  padding: 7px 10px; cursor: pointer; font-size: 11.5px;
}
.acl-head:hover { background: color-mix(in srgb, var(--cy-cyan) 5%, transparent); }
.mono2 { font-family: 'JetBrains Mono', monospace; font-size: 12.5px; color: var(--cy-ink); }
.bind { font-size: 11px; color: var(--cy-ink-2); }
.bind .mono2 { font-size: 11px; color: var(--cy-cyan); }
.bind.unbound { color: var(--cy-down); }
.chip {
  font-size: 10.5px; padding: 0 6px; border: 1px solid;
}
.chip.crit { color: var(--cy-down); }
.chip.warn { color: var(--cy-degraded); }
.toggle { margin-left: auto; font-size: 11px; color: var(--cy-cyan); }

:deep(.mono) {
  font-size: 11.5px; font-family: 'JetBrains Mono', monospace; color: var(--cy-ink-2);
}
:deep(.bad-row td) { background: color-mix(in srgb, var(--cy-down) 7%, transparent) !important; }
/* 隐含那一行整行压暗 —— 它不是设备上真有的一行 */
:deep(.implicit-row td) { opacity: 0.62; }
</style>
