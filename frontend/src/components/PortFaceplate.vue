<script setup lang="ts">
import { computed, ref } from 'vue'
import { NTag } from 'naive-ui'
import type { FaceBank, FacePort, Faceplate } from '@/api'
import { STATE } from '@/theme'

/**
 * 端口面板图 —— **手写 SVG,不引图表库**(和 Sparkline 同一条:一个页面上
 * 可能同时画好几台设备,每个都 init 一个 echarts 实例会让首屏卡好几秒)。
 *
 * ## 为什么是画的,不是照片
 *
 * 厂商的机箱照片有版权,而且**照片是死的** —— 它不知道哪个口现在是通的。
 * 这里画的是机箱本身(面板底、卡槽、RJ45 的卡扣缺口、SFP 笼子、端口分组、
 * 型号铭牌),端口的**状态**再叠上去。所以它既像实物,又是活的。
 *
 * 画到什么程度是有讲究的:**像到能对上实物,但不假装是照片**。
 * 一张画得太像照片的图会让人完全信任它的位置,而位置来自型号画像 ——
 * 那份画像可能还没在实机上核对过(见下面 `note`)。
 *
 * ## 一条压倒一切的规矩:画错的面板比没有面板危险
 *
 * 有人会照着这张图去机房拔线,**拔错的是别人的**。所以:
 *
 * - `schematic` / `verified` 那句话**必须原样显示在图上方**,不能收进
 *   一个要点开的提示里。
 * - 每个口上**永远印着面板号**,hover / 点开都以**接口名**为主 ——
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
  /** 高亮这个接口(表格里选中的那一行)。再点一次由父组件取消 */
  activeId?: number | null
}>()

const emit = defineEmits<{ (e: 'pick', port: FacePort): void }>()

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
const W = 22          // 一个口的宽
const H = 17          // 一个口的高
const GAP = 2.5       // 同组内的口间距
const GROUP = 6       // **每 6 个口一组** —— Catalyst 面板上就是这么分的,
                      // 组之间那条略宽的缝是数口时的锚点
const GROUP_GAP = 6
const BANK_GAP = 20   // 两组口之间(物理面板上是分开的两块)
const PAD = 10        // 机箱内边距
const PLATE = 74      // 左边那块型号铭牌的宽度
const LABEL_H = 11

function colOffset(col: number) {
  return col * (W + GAP) + Math.floor(col / GROUP) * GROUP_GAP
}
function bankWidth(bank: FaceBank) {
  return bank.cols ? colOffset(bank.cols - 1) + W : 0
}
function bankHeight(bank: FaceBank) {
  return LABEL_H + bank.rows * H + Math.max(0, bank.rows - 1) * GAP
}

/** 每组的左上角 x —— 组是横着排的,和物理面板一致 */
const bankOffsets = computed(() => {
  const out: number[] = []
  let x = PAD + PLATE
  for (const bank of props.data.banks) {
    out.push(x)
    x += bankWidth(bank) + BANK_GAP
  }
  return out
})

const boxW = computed(() => {
  const banks = props.data.banks
  if (!banks.length) return 300
  return bankOffsets.value[banks.length - 1] + bankWidth(banks[banks.length - 1]) + PAD
})
const boxH = computed(() => {
  const banks = props.data.banks
  return (banks.length ? Math.max(...banks.map(bankHeight)) : 40) + PAD * 2
})
const viewBox = computed(() => `0 0 ${boxW.value} ${boxH.value}`)

function portX(bankIndex: number, port: FacePort) {
  return bankOffsets.value[bankIndex] + colOffset(port.col)
}
function portY(bank: FaceBank, port: FacePort) {
  return PAD + LABEL_H + port.row * (H + GAP)
}
function portH(bank: FaceBank) {
  // SFP 笼子扁一点 —— 形状本身就是"这是光口"的提示
  return bank.shape === 'sfp' ? H - 4 : H
}

/**
 * RJ45 插座的轮廓:一个方口 + 卡扣缺口。
 *
 * **上下两排的缺口方向是反的** —— Catalyst 上排的口卡扣朝下、下排朝上
 * (两排是镜像装的)。这个细节值一画:它是"这张图对着实物画的"最直接的
 * 证据,而人对着实物数口时正是靠这个分辨上下排。
 */
function rjPath(x: number, y: number, h: number, flip: boolean): string {
  const w = W
  const nw = w * 0.36          // 缺口宽
  const nh = h * 0.26          // 缺口深
  const nx = x + (w - nw) / 2
  if (!flip) {
    // 缺口在下
    return `M${x} ${y} h${w} v${h - nh} h-${(w - nw) / 2} v${nh} h-${nw} v-${nh} h-${(w - nw) / 2} Z`
  }
  // 缺口在上
  return `M${x} ${y + nh} h${(w - nw) / 2} v-${nh} h${nw} v${nh} h${(w - nw) / 2} v${h - nh} h-${w} Z`
}

function shortName(port: FacePort): string {
  const m = /(\d+)\s*$/.exec(port.if_name)
  return m ? m[1] : port.if_name.slice(-3)
}

/** 铭牌上印什么 —— 厂商 + 型号,和实物上那块丝印一个意思 */
const plateText = computed(() => {
  const d = props.data.device
  return (d.model_label || d.model || '').replace(/^Cisco\s+/i, '') || d.name
})
const plateVendor = computed(() => {
  const v = (props.data.device.vendor || '').toLowerCase()
  if (v.includes('cisco')) return 'CISCO'
  if (v.includes('forti')) return 'FORTINET'
  return (props.data.device.vendor || '').toUpperCase()
})

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
        <defs>
          <!-- 机箱面板:上亮下暗的金属渐变 -->
          <linearGradient id="fp-chassis" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="var(--cy-raised)" />
            <stop offset="42%" stop-color="var(--cy-card)" />
            <stop offset="100%" stop-color="var(--cy-body)" />
          </linearGradient>
          <!-- 端口凹进去的那圈阴影 -->
          <linearGradient id="fp-socket" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="var(--cy-body)" />
            <stop offset="100%" stop-color="var(--cy-card)" />
          </linearGradient>
          <!-- 通风孔纹理:铭牌那块用 -->
          <pattern id="fp-vent" width="4" height="4" patternUnits="userSpaceOnUse">
            <circle cx="2" cy="2" r="0.7" fill="var(--cy-ink-3)" opacity="0.25" />
          </pattern>
        </defs>

        <!-- 机箱 -->
        <rect
          x="0.5" y="0.5" :width="boxW - 1" :height="boxH - 1" rx="3"
          fill="url(#fp-chassis)" stroke="var(--cy-line)" stroke-width="1"
        />
        <!-- 上沿高光:一条很淡的亮线,金属感全靠它 -->
        <line x1="3" y1="1.6" :x2="boxW - 3" y2="1.6" class="fp-gloss" />

        <!-- 左边铭牌:厂商 + 型号 + 两颗安装螺丝 + 通风孔 -->
        <g class="fp-plate">
          <rect
            :x="PAD - 4" :y="PAD - 4" :width="PLATE - 10" :height="boxH - PAD * 2 + 8"
            rx="2" fill="var(--cy-body)" stroke="var(--cy-line-soft)"
          />
          <rect
            :x="PAD - 1" :y="boxH - PAD - 10" :width="PLATE - 16" height="9"
            fill="url(#fp-vent)"
          />
          <text :x="PAD" :y="PAD + 6" class="fp-vendor">{{ plateVendor }}</text>
          <text :x="PAD" :y="PAD + 17" class="fp-model">{{ plateText }}</text>
          <!-- 状态灯:实物上那排 SYST/STAT。这里只画一颗,亮的是整机状态 -->
          <circle
            :cx="PAD + 3" :cy="PAD + 27" r="2.2"
            :fill="data.device.state === 'up' ? STATE.up
              : data.device.state === 'down' ? STATE.down : STATE.unknown"
          />
          <text :x="PAD + 9" :y="PAD + 29.5" class="fp-syst">SYST</text>
          <circle :cx="PAD - 1" :cy="PAD - 1" r="1.3" class="fp-screw" />
          <circle :cx="PAD + PLATE - 15" :cy="PAD - 1" r="1.3" class="fp-screw" />
        </g>

        <!-- 端口 -->
        <g v-for="(bank, bi) in data.banks" :key="bank.label">
          <text :x="bankOffsets[bi]" :y="PAD + 5" class="fp-bank-label">
            {{ bank.label }}<tspan v-if="bank.renumbered" class="fp-warn"> (顺序,非面板号)</tspan>
          </text>

          <!-- 每组 6 个口下面一条短横线 —— 实物上那条丝印分隔,数口靠它 -->
          <line
            v-for="g in Math.ceil(bank.cols / GROUP)" :key="`g${g}`"
            :x1="bankOffsets[bi] + colOffset((g - 1) * GROUP)"
            :x2="bankOffsets[bi] + colOffset(Math.min(g * GROUP, bank.cols) - 1) + W"
            :y1="PAD + LABEL_H + bank.rows * H + (bank.rows - 1) * GAP + 3"
            :y2="PAD + LABEL_H + bank.rows * H + (bank.rows - 1) * GAP + 3"
            class="fp-groupline"
          />

          <g
            v-for="p in bank.ports" :key="p.id"
            class="fp-port"
            :class="{ active: activeId === p.id }"
            @mouseenter="hovered = p"
            @mouseleave="hovered = null"
            @click="emit('pick', p)"
          >
            <!-- 插座底(凹进去的那圈) -->
            <rect
              :x="portX(bi, p) - 1" :y="portY(bank, p) - 1"
              :width="W + 2" :height="portH(bank) + 2" rx="1.5"
              fill="url(#fp-socket)" stroke="var(--cy-line-soft)" stroke-width="0.6"
            />
            <!-- 口本身。RJ45 画卡扣缺口,SFP 画扁笼子 -->
            <path
              v-if="bank.shape !== 'sfp'"
              :d="rjPath(portX(bi, p), portY(bank, p), portH(bank), p.row % 2 === 1)"
              :fill="STATE_COLOR[p.state]"
              :fill-opacity="p.state === 'up' || p.state === 'down' ? 0.88 : 0.3"
              :stroke="activeId === p.id ? 'var(--cy-cyan)' : STATE_COLOR[p.state]"
              :stroke-width="activeId === p.id ? 1.5 : 0.6"
            />
            <rect
              v-else
              :x="portX(bi, p)" :y="portY(bank, p)"
              :width="W" :height="portH(bank)" rx="1"
              :fill="STATE_COLOR[p.state]"
              :fill-opacity="p.state === 'up' || p.state === 'down' ? 0.88 : 0.3"
              :stroke="activeId === p.id ? 'var(--cy-cyan)' : STATE_COLOR[p.state]"
              :stroke-width="activeId === p.id ? 1.5 : 0.6"
            />
            <!-- 口号 -->
            <text
              :x="portX(bi, p) + W / 2"
              :y="portY(bank, p) + portH(bank) / 2 + 3"
              class="fp-num"
              :class="{ dimtext: p.state !== 'up' && p.state !== 'down' }"
            >{{ shortName(p) }}</text>
            <!-- 链路灯:通的口才亮。实物上每个 RJ45 上方那颗绿灯 -->
            <circle
              v-if="p.state === 'up'"
              :cx="portX(bi, p) + 2.6"
              :cy="portY(bank, p) + (p.row % 2 === 1 ? portH(bank) - 2.4 : 2.4)"
              r="1" :fill="STATE.up" class="fp-led"
            />
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
      <template v-else>
        鼠标移到端口上看详情,点一下只看它 —— <b>再点一下取消</b>
      </template>
    </div>

    <!-- **不在面板上的口要列出来** —— 图上少一个口,人会以为它不存在 -->
    <div v-if="data.unplaced.length" class="fp-unplaced">
      <span class="dim">不在物理面板上({{ data.unplaced.length }}):</span>
      <button
        v-for="u in data.unplaced" :key="u.id"
        class="chip" :class="{ on: activeId === u.id }"
        :style="{ borderColor: STATE_COLOR[u.state] }"
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
  background: color-mix(in srgb, var(--cy-raised) 55%, transparent);
}
/* 完全没有型号画像时说得更重一点 —— 那张图的位置只表示顺序 */
.fp-note.hard {
  color: var(--cy-degraded);
  border-left-color: var(--cy-degraded);
  background: color-mix(in srgb, var(--cy-degraded) 8%, transparent);
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
  /* 48 口的图在窄屏上要能横向滚,而不是把页面撑破 */
  overflow-x: auto;
  padding: 2px 0;
}
.fp-svg { display: block; width: 100%; min-width: 720px; height: auto; }

/* 机箱细节 */
.fp-gloss { stroke: var(--cy-ink-3); stroke-width: 0.6; opacity: 0.28; }
.fp-screw { fill: var(--cy-ink-3); opacity: 0.4; }
.fp-vendor {
  font-size: 6.5px;
  letter-spacing: 0.16em;
  fill: var(--cy-cyan);
  font-weight: 700;
}
.fp-model { font-size: 6px; fill: var(--cy-ink-3); }
.fp-syst { font-size: 5px; fill: var(--cy-ink-3); letter-spacing: 0.08em; }
.fp-groupline { stroke: var(--cy-ink-3); stroke-width: 0.7; opacity: 0.35; }

.fp-bank-label { font-size: 6.5px; fill: var(--cy-ink-3); }
.fp-warn { fill: var(--cy-degraded); }

/* 端口只在 hover 时有反馈 —— **数据区不做装饰性动画**,
   而 hover 是交互反馈,那一类是留着的(cyber.css 第 3 条) */
.fp-port { cursor: pointer; }
.fp-port path, .fp-port rect { transition: stroke-width .12s ease, fill-opacity .12s ease; }
.fp-port:hover path, .fp-port:hover > rect:last-of-type {
  stroke: var(--cy-cyan);
  stroke-width: 1.3;
}
.fp-led { opacity: 0.9; }

.fp-num {
  font-size: 6.5px;
  font-family: 'JetBrains Mono', monospace;
  text-anchor: middle;
  fill: var(--cy-on-state);
  pointer-events: none;
  font-weight: 700;
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
.chip.on { background: color-mix(in srgb, var(--cy-cyan) 18%, transparent); color: var(--cy-ink); }
</style>
