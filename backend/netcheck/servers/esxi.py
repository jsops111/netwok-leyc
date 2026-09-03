"""
VMware ESXi 的采集命令与解析 —— **纯函数,不碰网络也不碰数据库**
(和 `linux.py` 同一个定位、同一套分段协议)。

## 为什么不能沿用 Linux 那套

VMkernel 的 `/proc` 是给 vmkernel 模块用的,**没有 `stat` / `meminfo` /
`loadavg` / `net/dev` / `cpuinfo`**,也没有 `/etc/os-release`。
而 ESXi Shell 是 busybox ash,`echo` 和 `for` 都跑得通 —— 于是拿 Linux 那条
命令去打一台 ESXi 的结果是:**分段标记全都出现了,每一段都是空的,
一个错误都没有**。采集器认为连上了,页面上这台机器是 UP、指标全是 `—`。
这是这个文件存在的全部理由(实测踩出来的,见 CLAUDE.md)。

## 数据来自哪

| 指标 | 来源 | 备注 |
|---|---|---|
| CPU / 内存使用率 | `vim-cmd hostsvc/hostsummary` 的 quickStats | hostd 自己算好的**当前值** |
| CPU 核数 / 主频 / 内存总量 | 同上的 hardware 段 | |
| 版本 / 厂商型号 | `esxcli system version get` / `hardware platform get` | |
| 数据存储用量 | `esxcli storage filesystem list` | 单位是字节,不用 df |
| 网卡与流量 | `esxcli network nic list` + `network nic stats get` | |
| 虚拟机 | `esxcli vm process list` / `vim-cmd vmsvc/getallvms` | 运行中 / 已注册 |
| 负载 | **没有** | ESXi 不提供 loadavg,留 None,不拿别的数凑 |

**CPU 使用率不需要两拍。**`overallCpuUsage` 是 MHz 当前值,除以
`cpuMhz × numCpuCores` 就是百分比 —— 所以 ESXi 主机第一拍就有 CPU 数据,
不像 Linux 要等第二拍的 jiffies 差值。口径不同(瞬时 vs 区间平均),
页面上要标出来,不能让人以为是同一个数。

## 为什么用 `vim-cmd hostsvc/hostsummary` 而不是 esxtop

`esxtop -b -n 1` 一次要跑好几秒、输出几百列 CSV,而且 batch 模式在没有 tty
的 SSH 会话里行为不稳。`hostsummary` 是 hostd 的一次本地 RPC,几十毫秒,
字段名从 5.5 到 8.0 没变过。
"""

from __future__ import annotations

import re

# 和 linux.py 共用同一个分段标记 —— 切分逻辑复用 linux.split_sections(),
# 两份实现会漂
from .linux import _mark  # noqa: PLC2701 —— 有意共用,不是私有 API 泄漏

# (段名, 命令)。**顺序即执行顺序**,网卡计数器尽量靠前:它和上一拍的
# 时间差算速率,前面挂一堆命令会让时间差比真实采样间隔长一点
_SECTIONS: list[tuple[str, str]] = [
    # 一次 RPC 拿到 CPU/内存用量 + 硬件规格 + uptime,是这里信息密度最高的一条
    ("summary", "vim-cmd hostsvc/hostsummary 2>/dev/null"),
    # 网卡清单和每块口的计数器。`sed -n '3,$p'` 跳掉表头和分隔线那两行;
    # 用 for 循环在**一次 exec 里**跑完,不为每块网卡多开一个 SSH channel
    ("nics", "esxcli network nic list 2>/dev/null"),
    (
        "nicstats",
        "for n in $(esxcli network nic list 2>/dev/null | sed -n '3,$p' | awk '{print $1}'); do "
        "echo \"@@NIC@@ $n\"; esxcli network nic stats get -n $n 2>/dev/null; done",
    ),
    ("version", "esxcli system version get 2>/dev/null"),
    ("platform", "esxcli hardware platform get 2>/dev/null"),
    ("cpu", "esxcli hardware cpu global get 2>/dev/null"),
    ("memory", "esxcli hardware memory get 2>/dev/null"),
    ("storage", "esxcli storage filesystem list 2>/dev/null"),
    ("hostname", "hostname 2>/dev/null"),
    ("kernel", "uname -sr 2>/dev/null"),
    # 已注册的虚拟机数(表头一行要减掉)。运行中的数量从 vmlist 段数出来
    ("vmregistered", "vim-cmd vmsvc/getallvms 2>/dev/null | sed -n '2,$p' | wc -l"),
]

# 运行中的虚拟机。放在可选段里的理由和 Linux 的 ps 一样:它是这条命令里
# 最慢的一段(要遍历所有 world),而不是每个人都需要
_VM_SECTION = ("vmlist", "esxcli vm process list 2>/dev/null")


def build_command(with_processes: bool = True) -> str:
    """把所有分段拼成一条命令。和 linux.build_command() 是同一套协议。"""

    sections = list(_SECTIONS) + ([_VM_SECTION] if with_processes else [])
    parts = []
    for name, command in sections:
        # echo 单独一条、用 ; 分隔 —— 用 && 的话某段命令失败会把后面所有段
        # 一起吞掉,而"某个 esxcli 命名空间在这个版本上不存在"是正常情况
        parts.append(f"echo '{_mark(name)}'")
        parts.append(command)
    return "; ".join(parts)


# ---------------------------------------------------------------- 通用解析


def parse_kv(text: str) -> dict[str, str]:
    """
    `esxcli xxx get` 的输出是缩进的 `Key: Value`,**跨版本比 --formatter=csv
    稳**:csv 的列名在 6.x / 7.x / 8.x 之间改过(比如内存那条从
    `Physical Memory` 变成 `MemorySize`),而 plain 输出的键名没动。

    键统一小写并去掉空格,取值时不用记原始大小写。
    """

    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower().replace(" ", "_")
        if not key or " " in key.replace("_", ""):
            continue
        out[key] = value.strip()
    return out


def _first_int(text: str) -> int | None:
    """从 `137254977536 Bytes` 这种值里取出第一个整数。"""

    if m := re.search(r"-?\d+", text or ""):
        try:
            return int(m.group(0))
        except ValueError:
            return None
    return None


def parse_int(text: str) -> int | None:
    first = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")
    return _first_int(first)


# ---------------------------------------------------------------- hostsummary

# vim-cmd 输出的是 vmodl 结构文本,不是 JSON,也没有稳定的缩进层级
# (同名字段在 runtime 和 summary 下都可能出现)。这里按字段名直接抓 ——
# 抓的这几个名字在 vim.host.Summary 里是**唯一的**,不会撞到别的结构上。
_SUMMARY_FIELDS = {
    "overall_cpu_mhz": r"\boverallCpuUsage\s*=\s*(\d+)",
    "overall_mem_mb": r"\boverallMemoryUsage\s*=\s*(\d+)",
    "uptime_s": r"\buptime\s*=\s*(\d+)",
    "cpu_mhz": r"\bcpuMhz\s*=\s*(\d+)",
    "cpu_cores": r"\bnumCpuCores\s*=\s*(\d+)",
    "cpu_threads": r"\bnumCpuThreads\s*=\s*(\d+)",
    "cpu_packages": r"\bnumCpuPkgs\s*=\s*(\d+)",
    "mem_total_bytes": r"\bmemorySize\s*=\s*(\d+)",
}
_RE_MODEL = re.compile(r'\bmodel\s*=\s*"([^"]*)"')
_RE_VENDOR = re.compile(r'\bvendor\s*=\s*"([^"]*)"')
_RE_MAINT = re.compile(r"\binMaintenanceMode\s*=\s*(true|false)")


def parse_hostsummary(text: str) -> dict:
    """
    `vim-cmd hostsvc/hostsummary` → CPU/内存使用率 + 硬件规格。

    **算不出百分比时不填 0。**`overallCpuUsage` 拿到了但 `cpuMhz × cores`
    没拿到,除法就做不了 —— 这时候留 None。填 0 的意思是"这台宿主没有负载",
    而真相是"我们没拿到分母",两件事在页面上必须分得开。
    """

    if not text.strip():
        return {}

    out: dict = {}
    for key, pattern in _SUMMARY_FIELDS.items():
        if m := re.search(pattern, text):
            out[key] = int(m.group(1))

    if m := _RE_MODEL.search(text):
        out["hw_model"] = m.group(1).strip()
    if m := _RE_VENDOR.search(text):
        out["hw_vendor"] = m.group(1).strip()
    if m := _RE_MAINT.search(text):
        out["maintenance_mode"] = m.group(1) == "true"

    # ---- CPU 使用率 ----
    total_mhz = (out.get("cpu_mhz") or 0) * (out.get("cpu_cores") or 0)
    used_mhz = out.get("overall_cpu_mhz")
    if total_mhz > 0 and used_mhz is not None:
        out["cpu_pct"] = round(min(100.0, used_mhz / total_mhz * 100), 2)
        out["cpu_total_mhz"] = total_mhz

    # ---- 内存使用率。quickStats 的单位是 MB(十进制 MiB),规格是字节 ----
    total_bytes = out.get("mem_total_bytes")
    used_mb = out.get("overall_mem_mb")
    if total_bytes and used_mb is not None:
        used_bytes = used_mb * 1024 * 1024
        out["mem_used_bytes"] = used_bytes
        out["mem_available_bytes"] = max(0, total_bytes - used_bytes)
        out["mem_pct"] = round(min(100.0, used_bytes / total_bytes * 100), 2)

    # ESXi 没有 swap 使用率这个概念(有 vmkernel swap,但那是**每台虚拟机**的,
    # 不是宿主级的百分比)。留 None —— 0% 会被读成"swap 很空闲"
    out["swap_pct"] = None
    return out


# ---------------------------------------------------------------- 版本 / 硬件


def parse_version(text: str) -> str:
    """`esxcli system version get` → "VMware ESXi 7.0.3 build-21930508"。"""

    kv = parse_kv(text)
    product = kv.get("product") or ""
    version = kv.get("version") or ""
    build = kv.get("build") or ""
    parts = [p for p in (product, version, build) if p]
    return " ".join(parts).strip()


def parse_platform(text: str) -> str:
    """`esxcli hardware platform get` → "Dell Inc. PowerEdge R740"。"""

    kv = parse_kv(text)
    vendor = kv.get("vendor_name") or ""
    product = kv.get("product_name") or ""
    if vendor and product.lower().startswith(vendor.lower()):
        return product.strip()
    return " ".join(p for p in (vendor, product) if p).strip()


def parse_cpu_global(text: str) -> int | None:
    """`esxcli hardware cpu global get` → 物理核数。hostsummary 拿不到时的退路。"""

    kv = parse_kv(text)
    return _first_int(kv.get("cpu_cores", ""))


def parse_memory(text: str) -> int | None:
    """`esxcli hardware memory get` → 物理内存字节数。同样是退路。"""

    kv = parse_kv(text)
    for key in ("physical_memory", "memorysize", "memory_size"):
        if key in kv and (value := _first_int(kv[key])) is not None:
            return value
    return None


# ---------------------------------------------------------------- 存储

# 只统计真正装虚拟机的存储。**bootbank 必须跳掉** —— ESXi 的两个引导分区
# 是 vfat、几百 MB、天生就用到八九成,算进来的话每台 ESXi 一加进来就直接
# 撞穿磁盘严重线,而那不是一个能行动的告警(没人能"清理" bootbank)
_STORAGE_TYPES = ("vmfs", "nfs", "vsan", "vvol", "ppfs")
_SKIP_VOLUME_NAMES = ("BOOTBANK1", "BOOTBANK2")


def parse_storage(text: str) -> list[dict]:
    """
    `esxcli storage filesystem list` → 数据存储用量,字段和 linux.parse_df()
    对齐(mount / fs / total_bytes / used_bytes / pct),这样上层不用分叉。

    ## 为什么不按列宽切

    第一版按表头下面那排 `----` 的位置定宽切列,实测**一格错位就全盘皆错**:
    某一列的值比它的分隔线宽一个字符,后面每一列都往右挪一格,于是
    `2199023255552` 被切成 `219902325555` —— 一个**小十倍但看起来完全正常**
    的容量,页面上没有任何迹象说明它是错的。

    所以改成按空白切:这张表里**只有 Volume Name 可能带空格**("datastore 1"
    是默认名之一),其余每一列都是单个 token。于是
    「前面 N 个 token + 后面 M 个 token,中间剩下的全是卷名」就能切对,
    和对齐完全无关。列的**身份**仍然从表头取,不写死顺序 —— 不同大版本
    列序有出入。

    Size / Free 的单位是**字节**,不是 KiB —— 这里不要再乘 1024。
    """

    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 2:
        return []

    sep_index = next(
        (
            i for i, ln in enumerate(lines[:3])
            if ln.strip() and set(ln.strip()) <= {"-", " "} and "-" in ln
        ),
        None,
    )
    if sep_index is None or sep_index == 0:
        return []

    # 表头的列名从分隔线的段落切 —— 表头这一行的列名一定落在自己的段落里
    # (段落宽度就是按最宽的那个值算的),所以只有表头这一行可以按列宽切
    header = lines[sep_index - 1]
    spans = [(m.start(), m.end()) for m in re.finditer(r"-+", lines[sep_index])]
    if len(spans) < 5:
        return []
    columns = [header[a:b].strip().lower() for a, b in spans]
    count = len(columns)

    def index_of(*names: str, default: int | None = None) -> int | None:
        for name in names:
            if name in columns:
                return columns.index(name)
        return default

    idx_name = index_of("volume name", default=1)
    idx_mount = index_of("mount point", default=0)
    idx_type = index_of("type")
    idx_mounted = index_of("mounted")
    idx_size = index_of("size")
    idx_free = index_of("free")
    if idx_size is None or idx_free is None or idx_name is None:
        return []

    tail = count - 1 - idx_name          # 卷名右边还有几列
    out: list[dict] = []
    for line in lines[sep_index + 1:]:
        parts = line.split()
        # 卷名可能是空的(未命名的卷),所以是 >= count - 1 而不是 >= count
        if len(parts) < count - 1:
            continue
        split_at = len(parts) - tail
        if split_at < idx_name:
            continue
        cells = parts[:idx_name] + [" ".join(parts[idx_name:split_at])] + parts[split_at:]
        if len(cells) != count:
            continue

        mount = cells[idx_mount]
        volume = cells[idx_name]
        fs_type = cells[idx_type].lower() if idx_type is not None else ""
        mounted = cells[idx_mounted].lower() if idx_mounted is not None else "true"
        total = _first_int(cells[idx_size])
        free = _first_int(cells[idx_free])

        if mounted not in ("true", "yes", "1"):
            continue                              # 没挂上的存储没有用量可言
        if fs_type and not fs_type.startswith(_STORAGE_TYPES):
            continue
        if volume.upper() in _SKIP_VOLUME_NAMES:
            continue
        if total is None or free is None or total <= 0:
            continue

        used = max(0, total - free)
        out.append({
            # 显示用卷名(datastore1),卷名为空才退回 /vmfs/volumes/<uuid> ——
            # 事件消息里要能直接行动,一串 UUID 没法直接行动
            "mount": (volume or mount or "?")[:120],
            "fs": mount or fs_type,
            "total_bytes": total,
            "used_bytes": used,
            "avail_bytes": free,
            # 和 linux.parse_df() 一致:used/(used+avail)
            "pct": round(used / (used + free) * 100, 2) if (used + free) else None,
        })
    return out


# ---------------------------------------------------------------- 网卡

_RE_NIC_MARK = re.compile(r"^@@NIC@@\s+(\S+)\s*$")


def parse_nic_list(text: str) -> dict[str, dict]:
    """
    `esxcli network nic list` → {vmnic0: {link, speed_mbps, mtu, driver}}。

    这里只按空白 split:vmnic 那张表的前几列(Name / PCI Device / Driver /
    Admin Status / Link Status / Speed)都不含空格,而后面的 Description
    含空格但我们不要它。
    """

    out: dict[str, dict] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        name = parts[0]
        if not name.startswith("vmnic") or name.startswith("-"):
            continue                              # 表头 / 分隔线
        link = parts[4].lower()
        out[name] = {
            "driver": parts[2],
            "admin_up": parts[3].lower() == "up",
            "link_up": link == "up",
            "speed_mbps": _first_int(parts[5]),
            "mtu": _first_int(parts[6]) if len(parts) > 6 else None,
        }
    return out


# `esxcli network nic stats get` 的字段名。**没有 ifHC 那种 32/64 位之分** ——
# 这些计数器是 vmkernel 里的 64 位无符号数,不会 34 秒回绕一次
_NIC_STAT_KEYS = {
    "in_octets": ("bytes_received", "receive_bytes"),
    "out_octets": ("bytes_sent", "send_bytes", "transmit_bytes"),
    "in_errors": ("total_receive_errors", "receive_errors"),
    "out_errors": ("total_transmit_errors", "transmit_errors"),
    "in_drops": ("receive_packets_dropped", "packets_received_dropped"),
    "out_drops": ("transmit_packets_dropped", "packets_sent_dropped"),
}


def parse_nic_stats(text: str, nic_list: dict[str, dict] | None = None) -> list[dict]:
    """
    那段 for 循环的输出 → 每块 vmnic 的累计计数器,字段和
    `linux.parse_netdev()` 对齐,这样上层的速率计算不用分叉。

    **ESXi 上没有"虚拟口"要排除。**vmnic 全是物理上行口 —— vSwitch、
    portgroup、vmk 都不在这张表里,所以不存在 Linux 上 docker0 / veth
    把同一份流量数两遍的问题,`is_virtual` 恒为 False。
    """

    nic_list = nic_list or {}
    out: list[dict] = []
    current: str | None = None
    buf: list[str] = []

    def flush():
        if current is None:
            return
        kv = parse_kv("\n".join(buf))
        row: dict = {"if_name": current, "is_virtual": False}
        for field, candidates in _NIC_STAT_KEYS.items():
            row[field] = next(
                (_first_int(kv[c]) for c in candidates if c in kv), None
            )
        # 收发字节一个都没有 = 这块口的 stats 没取到,整行丢掉。
        # 留着的话页面上是一块速率永远为 null 的网卡,看不出是采集问题
        if row["in_octets"] is None and row["out_octets"] is None:
            return
        row.update({
            k: v for k, v in (nic_list.get(current) or {}).items()
            if k in ("link_up", "admin_up", "speed_mbps")
        })
        out.append(row)

    for line in text.splitlines():
        if m := _RE_NIC_MARK.match(line.strip()):
            flush()
            current, buf = m.group(1), []
            continue
        if current is not None:
            buf.append(line)
    flush()
    return out


def pick_primary(rows: list[dict]) -> str:
    """
    自动挑主网卡:**累计收字节最多的那块 Up 上行口**。

    ESXi 上没有 `ip route` 那种"默认路由走哪块口"的直接答案 —— 管理流量走
    vmk0,而 vmk0 落到哪块 vmnic 上要翻 vSwitch 的 uplink 配置,几条命令
    还解析得很脆。按累计字节挑是稳的:那是**累计**计数器,一旦某块口领先
    就不会来回换,不会让流量图在两块网卡之间跳。

    按名字挑(vmnic0)不行 —— 很多机器上 vmnic0 是插着线但不带流量的备口,
    挑中它的表现是流量图长期是平的,而且看不出哪儿错了。
    """

    up = [r for r in rows if r.get("link_up")] or rows
    if not up:
        return ""
    return max(up, key=lambda r: (r.get("in_octets") or 0) + (r.get("out_octets") or 0))["if_name"]


# ---------------------------------------------------------------- 虚拟机

_RE_WORLD_ID = re.compile(r"^\s*World ID:\s*(\d+)", re.M)
_RE_DISPLAY_NAME = re.compile(r"^\s*Display Name:\s*(.+?)\s*$", re.M)


def parse_vm_processes(text: str) -> dict:
    """
    `esxcli vm process list` → {running: n, names: [...]}。

    数的是 `World ID:` 而不是块数:一个块里必然有且只有一行 World ID,
    而按空行分块在虚拟机名字里带空行时会错。

    **这是"正在跑"的数量,不是"已注册"的数量。**两个数都要给 ——
    差值就是关机的虚拟机,那是个有意义的数字。
    """

    ids = _RE_WORLD_ID.findall(text or "")
    names = [n.strip()[:64] for n in _RE_DISPLAY_NAME.findall(text or "")]
    return {"running": len(ids), "names": names[:20]}
