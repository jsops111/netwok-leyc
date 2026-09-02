"""
Linux 服务器的采集命令与解析 —— **纯函数,不碰网络也不碰数据库**。

## 为什么全部读 /proc,不解析 top / free / vmstat

`top` 和 `free` 的输出格式随发行版、版本和 locale 变:
`free` 在 procps 3.3.10 前后的列名就不一样(`-/+ buffers/cache` 那两行没了),
`top` 在中文 locale 下连表头都是中文的。而 `/proc/meminfo`、`/proc/stat`
是**内核 ABI**,字段只增不改,十几年没动过。

所以这里的规矩是:**能从 /proc 读的一律读 /proc**,只有磁盘用量走 `df`
(/proc 里没有挂载点的容量信息,`/proc/mounts` 只有挂载关系)。

## 一次采集就是一条命令

十几个 `/proc` 文件用一条命令读完,靠 `__NC__名字__` 标记分段。
分成十几次 exec_command 的话就是十几个 SSH channel、十几个来回 ——
一台机器采一轮从 200ms 变成 2 秒,而这是**每台每分钟**都要付的代价。
"""

from __future__ import annotations

import re

# 分段标记。取一个正常输出里绝不会出现的形状 —— 万一真的撞上了(比如
# 某个进程名里带这串字符),受影响的只是那一段,不会串到别的段
_MARK = "__NC__"


def _mark(name: str) -> str:
    return f"{_MARK}{name}{_MARK}"


# (段名, 命令)。**顺序即执行顺序**,而 stat/netdev 要尽量靠前:
# 它们是计数器,和上一拍的时间差算速率,前面挂着一堆命令会让时间差
# 比真实采样间隔长一点(误差在 60 秒间隔里可以忽略,但没必要故意引入)
_SECTIONS: list[tuple[str, str]] = [
    ("stat", "grep '^cpu ' /proc/stat"),
    ("netdev", "cat /proc/net/dev"),
    ("loadavg", "cat /proc/loadavg"),
    ("meminfo", "cat /proc/meminfo"),
    ("uptime", "cat /proc/uptime"),
    ("cores", "grep -c '^processor' /proc/cpuinfo"),
    ("hostname", "hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null"),
    ("kernel", "uname -sr 2>/dev/null"),
    ("os", "cat /etc/os-release 2>/dev/null"),
    # -x 是 GNU coreutils 的参数,BusyBox 的 df 不认 —— 不认就整条失败,
    # 由 || 退回不带过滤的版本,虚拟文件系统在 Python 侧再筛一遍
    ("df", "df -P -k -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -P -k"),
    ("route", "ip -o -4 route show default 2>/dev/null"),
    ("procs", "ls -d /proc/[0-9]* 2>/dev/null | wc -l"),
    # 状态字段是第 4 列、十六进制,01 = ESTABLISHED。
    # 用 awk 精确取第 4 列而不是 `grep ' 01 '` —— 后者会匹配到别的列
    ("tcp", "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '$4==\"01\"' | wc -l"),
]

_PS_SECTION = ("ps", "ps -eo pcpu,pmem,comm --sort=-pcpu 2>/dev/null | head -6")


def build_command(with_processes: bool = True) -> str:
    """把所有分段拼成一条命令。"""

    sections = list(_SECTIONS) + ([_PS_SECTION] if with_processes else [])
    parts = []
    for name, command in sections:
        # echo 单独一条,和命令用 ; 分隔 —— 用 && 的话某段命令失败会把
        # 后面所有段一起吞掉,而"某个文件读不到"是正常情况(没装 iproute2、
        # 容器里没有 /proc/net/tcp6),不该让整次采集变成空的
        parts.append(f"echo '{_mark(name)}'")
        parts.append(command)
    return "; ".join(parts)


def split_sections(text: str) -> dict[str, str]:
    """按标记切开。**没出现的段返回空字符串,不是 KeyError。**"""

    out: dict[str, str] = {}
    current: str | None = None
    buf: list[str] = []
    pattern = re.compile(rf"^{re.escape(_MARK)}(\w+){re.escape(_MARK)}\s*$")

    for line in text.splitlines():
        if m := pattern.match(line.strip()):
            if current is not None:
                out[current] = "\n".join(buf).strip()
            current = m.group(1)
            buf = []
            continue
        if current is not None:
            buf.append(line)
    if current is not None:
        out[current] = "\n".join(buf).strip()
    return out


# ---------------------------------------------------------------- 基本信息


_RE_OS_PRETTY = re.compile(r'^PRETTY_NAME="?([^"\n]+)"?', re.M)
_RE_OS_NAME = re.compile(r'^NAME="?([^"\n]+)"?', re.M)


def parse_os(text: str) -> str:
    if m := _RE_OS_PRETTY.search(text):
        return m.group(1).strip()
    if m := _RE_OS_NAME.search(text):
        return m.group(1).strip()
    return ""


def parse_int(text: str) -> int | None:
    first = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")
    try:
        return int(first)
    except ValueError:
        return None


def parse_uptime(text: str) -> float | None:
    """/proc/uptime 第一个数是开机至今的秒数(带小数)。"""

    try:
        return float(text.split()[0])
    except (IndexError, ValueError):
        return None


def parse_loadavg(text: str) -> tuple[float | None, float | None, float | None]:
    try:
        parts = text.split()
        return float(parts[0]), float(parts[1]), float(parts[2])
    except (IndexError, ValueError):
        return None, None, None


def parse_meminfo(text: str) -> dict:
    """
    /proc/meminfo → 字节。

    **用 MemAvailable 算已用,不用 MemFree。**MemFree 把页缓存算成"已用",
    于是任何一台正常干活的 Linux 都显示 90%+ 内存占用 —— 那个数字每次都会
    引来一次"内存要爆了"的误报。MemAvailable 是内核自己算的"还能给应用多少",
    这才是该看的数(内核 3.14 以后都有;没有的话退回 free+buffers+cached)。
    """

    values: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        num = parts[1].strip().split()
        if not num:
            continue
        try:
            values[parts[0].strip()] = int(num[0]) * 1024  # meminfo 单位是 kB
        except ValueError:
            continue

    total = values.get("MemTotal")
    if not total:
        return {}

    available = values.get("MemAvailable")
    if available is None:
        available = (
            values.get("MemFree", 0) + values.get("Buffers", 0) + values.get("Cached", 0)
        )
    used = max(0, total - available)

    out = {
        "mem_total_bytes": total,
        "mem_available_bytes": available,
        "mem_used_bytes": used,
        "mem_pct": round(used / total * 100, 2),
    }
    swap_total = values.get("SwapTotal") or 0
    if swap_total:
        swap_free = values.get("SwapFree", 0)
        out["swap_total_bytes"] = swap_total
        out["swap_pct"] = round((swap_total - swap_free) / swap_total * 100, 2)
    else:
        # 没开 swap 时**不要填 0%** —— 0% 看着像"swap 很空闲",
        # 而事实是这台机器没有 swap,是两件不同的事
        out["swap_pct"] = None
    return out


# ---------------------------------------------------------------- CPU


def parse_cpu_jiffies(text: str) -> dict | None:
    """
    /proc/stat 的 `cpu` 汇总行 → 各态 jiffies。

    这是**累计计数器**,不是使用率。使用率要两拍相减,见 cpu_delta()。
    """

    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] != "cpu":
            continue
        # user nice system idle iowait irq softirq steal guest guest_nice
        # 老内核只有前 7 个,新内核 10 个 —— 按位置取,取到几个算几个
        try:
            nums = [int(x) for x in parts[1:]]
        except ValueError:
            return None
        if len(nums) < 5:
            return None
        keys = ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"]
        out = {k: nums[i] for i, k in enumerate(keys) if i < len(nums)}
        # guest / guest_nice 已经被算进 user / nice 里了,再加一遍是重复计数
        out["total"] = sum(out.values())
        return out
    return None


def cpu_delta(previous: dict | None, current: dict | None) -> tuple[float | None, float | None]:
    """
    两拍 jiffies → (CPU 使用率 %, iowait %)。

    返回 (None, None) 的三种情况,**都不能填 0**:
      - 没有上一拍(刚加进来的服务器,第一拍必然如此)
      - 计数器变小了 —— 机器重启过,这一拍的差值是假的
      - 时间差里 total 没动 —— 采集间隔太短或时钟异常

    0% 的含义是"CPU 全空闲",和"我们算不出来"完全是两件事:
    前者会让人以为这台机器很闲。
    """

    if not previous or not current:
        return None, None
    total_delta = current["total"] - previous["total"]
    if total_delta <= 0:
        return None, None
    # 任何一个分量倒退 = 重启(计数器从 0 重新开始)
    for key, value in current.items():
        if value < previous.get(key, 0):
            return None, None

    idle_delta = (current.get("idle", 0) - previous.get("idle", 0)) + (
        current.get("iowait", 0) - previous.get("iowait", 0)
    )
    busy = max(0, total_delta - idle_delta)
    iowait_delta = current.get("iowait", 0) - previous.get("iowait", 0)
    return (
        round(min(100.0, busy / total_delta * 100), 2),
        round(min(100.0, iowait_delta / total_delta * 100), 2),
    )


# ---------------------------------------------------------------- 网卡

# 虚拟口:容器/虚拟机宿主上这些口会把同一份流量再数一遍。
# **它们只是不计入"总流量",仍然会被采集和展示** —— docker0 上多少流量
# 本身是有用的信息,只是不能和 eth0 相加。
_VIRTUAL_PATTERNS = (
    r"^lo$", r"^docker\d*$", r"^veth", r"^br-", r"^virbr", r"^vnet\d*$",
    r"^tun\d*$", r"^tap\d*$", r"^cni\d*$", r"^flannel", r"^cali", r"^kube",
    r"^dummy\d*$", r"^nerdctl", r"^ifb\d*$", r"^gre\d*$", r"^sit\d*$",
)
_VIRTUAL_RE = re.compile("|".join(_VIRTUAL_PATTERNS))


def is_virtual_interface(name: str) -> bool:
    return bool(_VIRTUAL_RE.match(name.strip()))


def parse_netdev(text: str) -> list[dict]:
    """
    /proc/net/dev → 每块网卡的累计计数器。

    格式(前两行是表头):
        Inter-|   Receive                    |  Transmit
         face |bytes packets errs drop fifo frame compressed multicast|bytes ...
        eth0: 12345 67 0 0 0 0 0 0  8910 11 0 0 0 0 0 0

    网卡名和数字之间的冒号**可能没有空格**(名字长的时候),
    所以按第一个冒号切,不能按空白切。
    """

    out: list[dict] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        name = name.strip()
        if not name or name.lower().startswith("face"):
            continue
        fields = rest.split()
        if len(fields) < 16:
            continue
        try:
            out.append({
                "if_name": name,
                "in_octets": int(fields[0]),
                "in_errors": int(fields[2]),
                "in_drops": int(fields[3]),
                "out_octets": int(fields[8]),
                "out_errors": int(fields[10]),
                "out_drops": int(fields[11]),
                "is_virtual": is_virtual_interface(name),
            })
        except ValueError:
            continue
    return out


_RE_DEFAULT_DEV = re.compile(r"\bdev\s+(\S+)")


def parse_default_interface(text: str) -> str:
    """
    `ip -o -4 route show default` → 默认路由那块网卡。

    多条默认路由(多出口)时取第一条 —— `ip route` 已经按 metric 排好序,
    第一条就是当前生效的那条。

    **注意 br0 这种情况**:虚拟机宿主机的默认路由常常走网桥,而 br0 按名字
    是"虚拟口"。它仍然是这台机器对外的那块网卡,所以主网卡由路由决定,
    不由名字决定(见 collector 里 is_primary 的赋值)。
    """

    for line in text.splitlines():
        if m := _RE_DEFAULT_DEV.search(line):
            return m.group(1).strip()
    return ""


# ---------------------------------------------------------------- 磁盘

# 不是"真磁盘"的挂载点。df 已经 -x 过一批,但 BusyBox 的 df 不支持 -x,
# 而且容器/k8s 节点上还有一堆按路径才认得出来的
_SKIP_MOUNT_PREFIXES = (
    "/proc", "/sys", "/dev", "/run", "/snap", "/boot/efi",
    "/var/lib/docker/", "/var/lib/containerd/", "/var/lib/kubelet/",
    "/var/lib/rancher/", "/nix/store",
)
_SKIP_FS = {"tmpfs", "devtmpfs", "squashfs", "overlay", "overlay2", "none", "udev", "ramfs"}


def _skip_mount(mount: str) -> bool:
    """
    前缀匹配要**按路径段**比,不能直接 startswith。

    `startswith("/dev")` 会把 `/devdata`(一个真实的数据盘)也跳掉,
    而那正是最该被监控的那块 —— 数据盘满了才是半夜被叫起来的原因。
    """

    return any(mount == p.rstrip("/") or mount.startswith(p.rstrip("/") + "/")
               for p in _SKIP_MOUNT_PREFIXES)


def parse_df(text: str) -> list[dict]:
    """
    `df -P -k` → 挂载点用量。

    `-P` 是关键:不加的话长设备名会**折行**,于是一行变两行,解析出来全是错的。
    `-k` 固定单位为 1KiB,不受 DF_BLOCK_SIZE / POSIXLY_CORRECT 影响。

    去重按 (设备, 总量):bind mount 和 btrfs 子卷会让同一块盘出现多次,
    不去重的话"占用率最高的挂载点"很可能是同一块盘的第二个名字。
    """

    out: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for line in text.splitlines()[1:]:            # 第一行是表头
        parts = line.split()
        if len(parts) < 6:
            continue
        # "Mounted on" 里可能有空格,所以挂载点取剩下的全部
        fs, blocks, used, avail, _capacity = parts[0], parts[1], parts[2], parts[3], parts[4]
        mount = " ".join(parts[5:])
        if fs in _SKIP_FS or _skip_mount(mount):
            continue
        try:
            total_bytes = int(blocks) * 1024
            used_bytes = int(used) * 1024
            avail_bytes = int(avail) * 1024
        except ValueError:
            continue
        if total_bytes <= 0:
            continue
        key = (fs, total_bytes)
        if key in seen:
            continue
        seen.add(key)
        # 用 used/(used+avail) 而不是 used/total:ext4 默认给 root 留 5%,
        # total 包含那部分保留空间,按 total 算出来的占用率会比 df 自己报的
        # Capacity 低几个百分点 —— 页面上的数字要和运维 `df -h` 看到的一致
        denominator = used_bytes + avail_bytes
        out.append({
            "mount": mount,
            "fs": fs,
            "total_bytes": total_bytes,
            "used_bytes": used_bytes,
            "avail_bytes": avail_bytes,
            "pct": round(used_bytes / denominator * 100, 2) if denominator else None,
        })
    return out


# ---------------------------------------------------------------- 进程


def parse_ps(text: str) -> list[dict]:
    """`ps -eo pcpu,pmem,comm --sort=-pcpu | head -6` → Top 进程。"""

    out: list[dict] = []
    for line in text.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        if parts[0].upper().startswith("%") or parts[0].upper() == "PCPU":
            continue                              # 表头
        try:
            out.append({
                "cpu": float(parts[0]),
                "mem": float(parts[1]),
                "name": parts[2].strip()[:64],
            })
        except ValueError:
            continue
    return out[:5]
