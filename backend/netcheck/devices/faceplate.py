"""
端口面板图的**布局计算** —— 纯函数,不碰网络也不碰库。

把设备上报的接口表摆到型号画像声明的面板几何上,得到每个口的
(排, 列) 和颜色档位。SVG 由前端画(手写,不引图表库 —— 和 Sparkline
同一条:一个页面上可能有好几台设备的面板)。

## 一条压倒一切的规矩:画错的面板比没有面板危险

有人会照着这张图去机房拔线,**拔错的是别人的**。所以:

1. **口的数量和名字永远来自设备**,画像里只声明几何。这样一台 C9300
   插了扩展模块之后图上就会多出那几个口,不用改代码;反过来,画像里
   写死"48 个口"而设备只报了 24 个的话,图上会凭空多出 24 个不存在的口。
2. **面板号不是 ifIndex。**`GigabitEthernet1/0/24` 面板上印的是 24,
   而它的 ifIndex 可能是任何数。拿 ifIndex 排会排出一个和实物对不上的图,
   而那个图**看起来完全正常** —— 这是这个功能最危险的失败方式。
3. **没有画像就明说是示意图。**认不出的型号仍然画(不画等于这个功能对
   通用设备完全没用),但**标明"按接口名排的示意图,不是真实面板布局"**,
   而且 `verified=False` 的画像也要标。让人自己决定信到什么程度,
   比给他一个不透明的判断可靠。
4. **没落到任何一组的口要列出来,不能悄悄丢掉。**图上少一个口,人会以为
   那个口不存在。

## 颜色档位

| 档位 | 含义 | 颜色 |
|---|---|---|
| `up` | admin up + link up | 绿 |
| `down` | **admin up 但 link down** —— 这才是"该通没通" | 红 |
| `admin_down` | 人为关掉的 | 灰 |
| `unknown` | 状态没采到 | 深灰 |

**`admin_down` 不能画成红色。**48 口交换机上一半的口是人为关掉的,
全画红的话满屏是红,真正断掉的那一个就淹在里面了 —— 和「仅异常」筛选
不算 admin down 是同一条规矩。
"""

from __future__ import annotations

import re

from .profiles import Faceplate, PortBank, Profile

#: 认不出型号时的兜底排布。**明确标成示意图** —— 见模块开头第 3 条
_FALLBACK_BANK = PortBank(
    label="接口",
    # 抓接口名末尾的数字当序号。抓不到的口落到"其他接口"里,不硬塞进图
    pattern=r"(\d+)\s*$",
    rows=2,
    column_major=True,
    shape="rj45",
)


def port_state(admin_up, oper_up) -> str:
    """
    一个口的档位。**admin_down 单独一档,不能并进 down** ——
    48 口交换机上一半的口是人为关掉的,并进去的话满屏是红,
    真正"该通没通"的那一个就看不见了。
    """

    if admin_up is None or oper_up is None:
        return "unknown"
    if not admin_up:
        return "admin_down"
    return "up" if oper_up else "down"


def _place(number: int, rows: int, column_major: bool, span: int) -> tuple[int, int]:
    """
    面板号 → (排, 列)。号从 1 开始,`span` 是这一组里最大的面板号。

    `column_major`(Catalyst 的接入口)是 **1 在左上、2 在左下、3 在第二列上**。
    按行优先排会得到一个横竖颠倒的图,而它**看起来完全正常** ——
    只有对着实物数才会发现,所以这个开关在画像里是显式的。

    行优先要知道**一排放几个**,所以要 `span` 而不是只看单个号:
    `rows=1` 的上行口一排放完(每个口 col 递增),写成 `index // rows`
    会把它们排成一竖列 —— 4 个 SFP 上行口在图上变成竖着的一条,和实物差得远。
    """

    index = max(0, number - 1)
    rows = max(1, rows)
    if column_major:
        return index % rows, index // rows
    per_row = max(1, -(-span // rows))            # ceil(span / rows)
    return index // per_row, index % per_row


def _match_bank(name: str, bank: PortBank) -> tuple[int | None, int] | None:
    """
    接口名 → `(堆叠成员号, 面板口号)`。不匹配返回 None。

    **一个捕获组 = 只有口号**(成员号为 None);
    **两个 = (成员号, 口号)** —— 堆叠必须这么写,见 `PortBank` 的说明。
    """

    m = re.match(bank.pattern, name) if bank.pattern.startswith("^") else re.search(bank.pattern, name)
    if not m:
        return None
    groups = m.groups()
    try:
        if len(groups) >= 2:
            return int(groups[0]), int(groups[1])
        return None, int(groups[0])
    except (IndexError, ValueError, TypeError):
        return None


def _emit_bank(bank: PortBank, entries: list, member: int | None,
               schematic: bool, out_banks: list) -> None:
    """把一个成员(或整组)的口摆好,追加成一块面板。"""

    # **按面板号排,不按 ifIndex** —— 见模块开头第 2 条
    entries.sort(key=lambda e: (e[0], str(e[1].get("if_name"))))
    # 分完成员之后口号还重复,那才是真的要重编(兜底排布的情形)
    renumber = schematic or len({n for n, _ in entries}) != len(entries)

    # 一排放几个要看**最大的面板号**,不是口的个数:一台 48 口交换机只有
    # 24 个口在线时,剩下 24 个位置应该是空的(那才和实物对得上)
    span = len(entries) if renumber else max(n for n, _ in entries)

    ports = []
    for seq, (number, row) in enumerate(entries, start=1):
        slot = seq if renumber else number
        r, c = _place(slot, bank.rows, bank.column_major, span)
        ports.append({
            **row, "row": r, "col": c,
            # 面板上印的那个号。重编号时这个数只是顺序,页面上
            # **要以接口名为准**(名字才是印在设备上的东西)
            "port_no": number,
            "state": port_state(row.get("admin_up"), row.get("oper_up")),
        })

    cols = max((p["col"] for p in ports), default=0) + 1
    out_banks.append({
        # 堆叠时**标出是第几台** —— 「成员 2 接入口」。不标的话两块一模一样
        # 的面板叠在一起,人分不出哪块是哪台
        "label": f"成员 {member} · {bank.label}" if member is not None else bank.label,
        "member": member,
        "rows": bank.rows,
        "cols": cols,
        "shape": bank.shape,
        # 重编过号的话,面板号和实物对不上 —— 说出来
        "renumbered": renumber,
        "ports": ports,
    })


def _finish(out_banks: list) -> None:
    """
    按 (成员号, 组名) 排一遍 —— 让「成员 1 接入口 / 成员 1 上行口 /
    成员 2 接入口 / 成员 2 上行口」这个顺序和机柜里从上往下的顺序一致。

    没有成员号的(非堆叠)保持原来的组顺序。
    """

    if any(b["member"] is not None for b in out_banks):
        out_banks.sort(key=lambda b: (b["member"] if b["member"] is not None else 0,
                                      0 if "接入" in b["label"] else 1))


def build(interfaces: list[dict], profile: Profile | None) -> dict:
    """
    interfaces 是 [{if_name, if_index, admin_up, oper_up, ...}, ...]
    (调用方从 DeviceInterface 取,字段原样带过来,这里只加位置和档位)。

    返回:
        {
          "verified": bool,        # 这是实测确认过的面板布局吗
          "schematic": bool,       # 这是示意图吗(没有型号画像时为 True)
          "label": str,
          "banks": [{label, rows, cols, shape, ports: [...]}],
          "unplaced": [...],       # 没落到任何一组的口。**必须列出来**
          "note": str,             # 页面上要照原样显示的那句话
        }
    """

    faceplate = profile.faceplate if profile else None
    schematic = faceplate is None
    banks = faceplate.banks if faceplate else (_FALLBACK_BANK,)

    placed_names: set[str] = set()
    out_banks = []

    for bank in banks:
        # 按**堆叠成员**分桶。成员号为 None 的(pattern 只有一个捕获组)
        # 全落进同一桶,行为和以前一样
        buckets: dict[int | None, list] = {}
        for row in interfaces:
            name = str(row.get("if_name") or "")
            if not name or name in placed_names:
                continue
            hit = _match_bank(name, bank)
            if hit is None:
                continue
            member, number = hit
            buckets.setdefault(member, []).append((number, row))
            placed_names.add(name)

        if not buckets:
            continue

        # **一个成员一块面板。**堆叠的两台是两台独立的交换机,画成一排的话
        # 人照着数第 30 个格子会落在另一台上 —— 照着它去拔线,拔的是别人的。
        #
        # **只有真的堆叠(多于一个成员)才加「成员 N」前缀** —— 单台交换机
        # 上标着「成员 1」是凭空多出来的概念,人会去想"那成员 2 呢"
        multi = len(buckets) > 1
        for member in sorted(buckets, key=lambda x: (x is None, x)):
            entries = buckets[member]
            _emit_bank(bank, entries, member if multi else None, schematic, out_banks)
    _finish(out_banks)

    # 没落到任何一组的口。**必须列出来** —— 图上少一个口,
    # 人会以为那个口不存在(Vlan / Port-channel / Loopback 都会落这里,
    # 它们本来就不在物理面板上,但仍然要能看到)
    unplaced = [
        {**row, "state": port_state(row.get("admin_up"), row.get("oper_up"))}
        for row in interfaces
        if str(row.get("if_name") or "") not in placed_names
    ]

    if schematic:
        note = (
            "**这是按接口名排的示意图,不是这款型号的真实面板布局。**"
            "画像里没有这款型号的面板几何(devices/profiles.py 的 faceplate)。"
            "位置只表示顺序 —— 找物理口请以**接口名**为准,那才是印在设备上的。"
        )
    elif not faceplate.verified:
        note = (
            "面板排布来自型号规格图,**没有在实机上核对过**。"
            "去机房动线之前请以**接口名**核对一遍 —— 名字是印在设备上的,位置不是。"
        )
    else:
        note = ""

    return {
        "verified": bool(faceplate and faceplate.verified),
        "schematic": schematic,
        "label": faceplate.label if faceplate else "按接口名排的示意布局",
        "banks": out_banks,
        "unplaced": unplaced,
        "note": note,
    }


def summarize(banks: list[dict]) -> dict:
    """图上那一行统计。**四档分开数** —— 见模块开头的颜色表。"""

    counts = {"up": 0, "down": 0, "admin_down": 0, "unknown": 0}
    for bank in banks:
        for port in bank["ports"]:
            counts[port["state"]] = counts.get(port["state"], 0) + 1
    counts["total"] = sum(counts[k] for k in ("up", "down", "admin_down", "unknown"))
    return counts
