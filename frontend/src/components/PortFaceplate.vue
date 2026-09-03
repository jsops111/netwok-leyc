<script setup lang="ts">
import { computed, ref } from 'vue'
import { NTag } from 'naive-ui'
import type { FaceBank, FacePort, Faceplate } from '@/api'
import { STATE } from '@/theme'

/**
 * 端口面板图 —— **手写 SVG,不引图表库**(和 Sparkline 同一条:
 * 一个页面上可能同时画好几台设备,每个都 init 一个 echarts 实例
 * 会让首屏卡好几秒)。
 *
 * ## 一条压倒一切的规矩:画错的面板比没有面板危险
 *
 * 有人会照着这张图去机房拔线,**拔错的是别人的**。所以:
 *
 * - `schematic` / `verified` 那句话**必须原样显示在图上方**,不能收进
 *   一个要点开的提示里。让人自己决定信到什么程度,比给他一个不透明的
 *   判断可靠。
 * - 每个口上**永远画着接口名的短形式**,而且 hover / 点开都以名字为主 ——
 *   **名字才是印在设备上的东西**,位置不是。
 * - 没落到面板上的口(Vlan / Port-channel / Loopback)列在下面,
 *   不能悄悄丢掉:图上少一个口,人会以为那个口不存在。
 *
 * ## 颜色
 *
 * `admin_down` 是**灰色不是红色**。48 口交换机上一半的口是人为关掉的,
 * 全画红的话满屏是红,真正"该通没通"的那一个就淹在里面了 ——
 * 和「仅异常」筛选不算 admin down 是同一条规矩。
 */

const props = defineProps<{
  data: Faceplate
  /** 高亮这个接口(表格里选中的那一行) */
  activeId?: number | null
}>()

const emit = defineEmits<{ (e: 'pick', port: FacePort): void }>()

/** 悬停的口。点击选中由父组件管(它要同时滚动表格) */
const hovered = ref<FacePort | null>(null)

const STATE_COLOR: Record<string, string> = {
  up: STATE.up,
  down: STATE.down,
  // **不是红色** —— 见文件头
  admin_down: STATE.unknown,
  unknown: STATE.unknown,
}
const STATE_TEXT: Record<string, string> = {
  up: '已连通',
  down: '链路 down(管理是开的)',
  admin_down: '人为关闭',
  unknown: '状态未采到',
}

// ---- 几何。单位是 SVG 用户坐标,外层按 viewBox 自适应 ----
const W = 26          // 一个口的宽
const H = 20          // 一个口的高
const GAP = 3
const BANK_GAP = 22   // 两组口之间的间隔(物理面板上它们是分开的两块)
const PAD = 8
const LABEL_H = 13

function bankWidth(bank: FaceBank) {
  return bank.cols * W + Math.max(0, bank.cols - 1) * GAP
}
function bankHeight(bank: FaceBank) {
  return LABEL_H + bank.rows * H + Math.max(0, bank.rows - 1) * GAP
}

/** 每组的左上角 x —— 组是横着排的,和物理面板一致 */
const bankOffsets = computed(() => {
  const out: number[] = []
  let x = PAD
  for (const bank of props.data.banks) {
    out.push(x)
    x += bankWidth(bank) + BANK_GAP
  }
  return out
})

const viewBox = computed(() => {
  const banks = props.data.banks
  if (!banks.length) return '0 0 100 40'
  const width = bankOffsets.value[banks.length - 1] + bankWidth(banks[banks.length - 1]) + PAD
  const height = Math.max(...banks.map(bankHeight)) + PAD * 2
  return `0 0 ${width} ${height}`
})

function portX(bankIndex: number, port: FacePort) {
  return bankOffsets.value[bankIndex] + port.col * (W + GAP)
}
function portY(port: FacePort) {
  return PAD + LABEL_H + port.row * (H + GAP)
}

/** SFP 口画得扁一点 —— 形状本身就是"这是光口"的提示 */
function portH(bank: FaceBank) {
  return bank.shape === 'sfp' ? H - 5 : H
}

/**
 * 口上印的短名。`GigabitEthernet1/0/24` → `24`。
 * 名字太长时只留数字部分 —— 一个 26px 宽的方块塞不下全名,
 * 全名在 hover 和点开的信息里。
 */
function shortName(port: FacePort): string {
  const m = /(\d+)\s*$/.exec(port.if_name)
  return m ? m[1] : port.if_name.slice(-3)
}

const info = computed(() => hovered.value)

function bps(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—'
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps']
  let v = value
  let i = 0
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i += 1 }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}
</script>

<template>
  <div class="fp">
    <!-- **这句话必须原样显示,不能收进折叠里。**画错的面板比没有面板危险 -->
    <div v-if="data.note" class="fp-note" :class="{ hard: data.schematic }">
      {{ data.note }}
    </div>

    <div class="fp-head">
      <span class="fp-label">{{ data.label }}</span>
      <span class="fp-legend">
        <i :style="{ background: STATE.up }"></i>通 {{ data.counts.up }}
        <i :style="{ background: STATE.down }"></i>断 {{ data.counts.down }}
        <!-- 人为关闭单独一档、灰色 —— 它不是故障 -->
        <i :style="{ background: STATE.unknown }"></i>人为关闭 {{ data.counts.admin_down }}
        <template v-if="data.counts.unknown">
          <i :style="{ background: STATE.unknown, opacity: .5 }"></i>未采到 {{ data.counts.unknown }}
        </template>
      </span>
    </div>

    <div class="fp-box">
      <svg :viewBox="viewBox" class="fp-svg" role="img" aria-label="端口面板图">
        <g v-for="(bank, bi) in data.banks" :key="bank.label">
          <text
            :x="bankOffsets[bi]" :y="PAD + 8"
            class="fp-bank-label"
          >{{ bank.label }}<tspan v-if="bank.renumbered" class="fp-warn"> (顺序,非面板号)</tspan></text>

          <g
            v-for="p in bank.ports" :key="p.id"
            class="fp-port"
            :class="{ active: activeId === p.id }"
            @mouseenter="hovered = p"
            @mouseleave="hovered = null"
            @click="emit('pick', p)"
          >
            <rect
              :x="portX(bi, p)" :y="portY(p)"
              :width="W" :height="portH(bank)"
              :rx="bank.shape === 'sfp' ? 1.5 : 2.5"
              :fill="STATE_COLOR[p.state]"
              :fill-opacity="p.state === 'up' ? 0.9 : p.state === 'down' ? 0.9 : 0.34"
              :stroke="activeId === p.id ? 'var(--cy-cyan)' : STATE_COLOR[p.state]"
              :stroke-width="activeId === p.id ? 1.6 : 0.7"
            />
            <text
              :x="portX(bi, p) + W / 2"
              :y="portY(p) + portH(bank) / 2 + 3.4"
              class="fp-num"
              :class="{ dimtext: p.state !== 'up' && p.state !== 'down' }"
            >{{ shortName(p) }}</text>
            <!-- 原生 title:鼠标停住就有,不依赖任何 JS。
                 **信息以接口名为主** —— 名字才是印在设备上的 -->
            <title>{{ p.if_name }} · {{ STATE_TEXT[p.state] }}{{ p.if_alias ? ` · ${p.if_alias}` : '' }}</title>
          </g>
        </g>
      </svg>
    </div>

    <!-- 悬停信息条。**字段和 /interfaces 那张表是同一份** ——
         同一个口在两个地方显示不同的数,人看不出哪个是对的 -->
    <div class="fp-info" :class="{ empty: !info }">
      <template v-if="info">
        <b class="cy-mono">{{ info.if_name }}</b>
        <span :style="{ color: STATE_COLOR[info.state] }">{{ STATE_TEXT[info.state] }}</span>
        <span v-if="info.if_alias" class="dim">{{ info.if_alias }}</span>
        <span class="dim cy-mono">ifIndex {{ info.if_index }}</span>
        <span class="cy-mono">↓{{ bps(info.in_bps) }} / ↑{{ bps(info.out_bps) }}</span>
        <span v-if="info.speed_bps" class="dim cy-mono">协商 {{ bps(info.speed_bps) }}</span>
        <!-- 32 位计数器的速率是噪声,必须标出来(CLAUDE.md 第 6 条) -->
        <NTag
          v-if="info.counter_32bit" size="tiny" :bordered="false"
          :style="`color:${STATE.degraded};border:1px solid ${STATE.degraded}`"
        >32 位计数器,速率不可信</NTag>
        <span v-if="info.in_err_delta || info.out_err_delta" :style="{ color: STATE.degraded }">
          本周期错包 {{ (info.in_err_delta || 0) + (info.out_err_delta || 0) }}
        </span>
      </template>
      <template v-else>鼠标移到端口上看详情,点一下在下面的表里定位到它</template>
    </div>

    <!-- **不在面板上的口要列出来** —— 图上少一个口,人会以为它不存在 -->
    <div v-if="data.unplaced.length" class="fp-unplaced">
      <span class="dim">不在物理面板上({{ data.unplaced.length }}):</span>
      <button
        v-for="u in data.unplaced" :key="u.id"
        class="chip" :style="{ borderColor: STATE_COLOR[u.state] }"
        :title="`${u.if_name} · ${STATE_TEXT[u.state]}`"
        @click="emit('pick', u)"
      >{{ u.if_name }}</button>
    </div>
  </div>
</template>

<style scoped>
.fp { display: flex; flex-direction: column; gap: 7px; }

.fp-note {
  font-size: 11px;
  line-height: 1.6;
  color: var(--cy-ink-2);
  padding: 5px 10px;
  border-left: 2px solid var(--cy-line);
  background: rgba(var(--cy-raised-rgb), 0.5);
}
/* 完全没有型号画像时说得更重一点 —— 那张图的位置只表示顺序 */
.fp-note.hard {
  color: var(--cy-degraded);
  border-left-color: var(--cy-degraded);
  background: rgba(var(--cy-degraded-rgb), 0.07);
}

.fp-head {
  display: flex; align-items: center; justify-content: space-between;
  gap: 12px; flex-wrap: wrap;
}
.fp-label { font-size: 11px; color: var(--cy-ink-3); }
.fp-legend {
  display: flex; align-items: center; gap: 5px;
  font-size: 10.5px; color: var(--cy-ink-3);
}
.fp-legend i {
  width: 8px; height: 8px; border-radius: 2px; display: inline-block;
  margin-left: 6px;
}

.fp-box {
  border: 1px solid var(--cy-line-soft);
  background: rgba(var(--cy-body-rgb), 0.5);
  padding: 4px;
  overflow-x: auto;      /* 48 口的图在窄屏上要能横向滚,而不是把页面撑破 */
}
.fp-svg { display: block; width: 100%; min-width: 560px; height: auto; }

.fp-bank-label { font-size: 7px; fill: var(--cy-ink-3); }
.fp-warn { fill: var(--cy-degraded); }

/* 端口本身只在 hover 时有反馈 —— **数据区不做装饰性动画**,
   而 hover 是交互反馈,那一类是留着的(cyber.css 第 3 条) */
.fp-port { cursor: pointer; }
.fp-port rect { transition: stroke-width .12s ease, fill-opacity .12s ease; }
.fp-port:hover rect { stroke: var(--cy-cyan); stroke-width: 1.4; fill-opacity: 1; }

.fp-num {
  font-size: 7.5px;
  font-family: 'JetBrains Mono', monospace;
  text-anchor: middle;
  fill: var(--cy-on-state);
  pointer-events: none;
}
/* 灰底上用亮字 —— 底色暗的时候深色字读不出来(和 SeverityTag 的 ink 同理) */
.fp-num.dimtext { fill: var(--cy-ink-2); }

.fp-info {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  font-size: 11px; color: var(--cy-ink-2);
  min-height: 22px;
  padding: 3px 8px;
  border: 1px solid var(--cy-line-soft);
}
.fp-info.empty { color: var(--cy-ink-3); }
.dim { color: var(--cy-ink-3); }

.fp-unplaced { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; font-size: 10.5px; }
.chip {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  padding: 1px 6px;
  background: transparent;
  border: 1px solid;
  color: var(--cy-ink-2);
  cursor: pointer;
}
.chip:hover { color: var(--cy-ink); }
</style>
