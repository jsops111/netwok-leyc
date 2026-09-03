"""
服务器采集的入口:SSH 连上去 → 读一批 /proc → 算速率 → 写库 → 判阈值 → 事件。

和 `devices/collector.py` 是同一套骨架,但**没有通道降级** —— 服务器只有
SSH 一条路。连不上就是连不上,不存在"换个通道再试"。

三条和 devices 一致、不能改回去的规则:

1. **计数器倒退时丢弃这一拍的速率**(重启/回绕),不取绝对值 ——
   取绝对值会在流量图上画出一根冲天的假尖峰,而那种尖峰会被当成真的
   流量突发去排查(见 `_rate()`)。
2. **算不出来的指标留 None,不填 0。**CPU 第一拍必然算不出来
   (没有上一拍的 jiffies),填 0 的意思是"CPU 全空闲",那是假数据。
3. **失败也写一行样本。**reachable=False 的那些行是服务器可用率的分母。

## 两套系统,一个出口

`os_type` 决定走 `linux.py` 还是 `esxi.py`。两个模块**都只负责"拼命令 +
解析文本"**,而且解析出来的是**同一个扁平 dict**(cpu_pct / mem_pct /
disk_pct / _interfaces / ...)—— 所以下面的速率计算、写样本、阈值判定、
事件那一整段是共用的,分叉只在 `_collect_raw()` 里那一个 if。

分叉点故意只有一个:多一个分叉就多一个"Linux 改了 ESXi 忘了改"的地方,
而那种漏改在页面上的表现是某一类机器的某个指标悄悄变空。
"""

from __future__ import annotations

import io
import logging
import socket
import time

import paramiko
from django.utils import timezone

from netcheck.events import engine as event_engine
from netcheck.models import (
    EventKind,
    LinkState,
    Server,
    ServerInterface,
    ServerOS,
    ServerSample,
    Severity,
)

from . import esxi, linux

log = logging.getLogger("netcheck.server")


class ServerError(Exception):
    """采集失败。服务器只有一条通道,所以这个异常等价于"这台机器采不到"。"""


# =========================================================================
# SSH
# =========================================================================


def _load_key(server: Server):
    """
    私钥不知道是哪种,依次试。Ed25519 放最前 —— 新机器上生成的默认就是它。

    带口令的私钥必须把 passphrase 传进去,否则 paramiko 抛的是
    "not a valid ... key" 这种和口令毫无关系的错,人会去怀疑密钥格式。
    """

    passphrase = server.ssh_key_passphrase or None
    last_error = ""
    for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return key_cls.from_private_key(io.StringIO(server.ssh_private_key), password=passphrase)
        except paramiko.PasswordRequiredException:
            raise ServerError("私钥带口令,但「私钥口令」是空的") from None
        except Exception as exc:  # noqa: BLE001 —— 试下一种
            last_error = str(exc)
            continue
    hint = "(口令不对?)" if passphrase else ""
    raise ServerError(f"私钥解析失败{hint},试过 Ed25519 / RSA / ECDSA:{last_error[:80]}")


def _connect(server: Server) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    # 不校验主机密钥:这是监控系统,被监控的机器可能重装、可能换 IP,
    # 而 known_hosts 不匹配会让采集**静默停止**。要防中间人得靠管理网隔离,
    # 不是靠这里报一个没人看的错。
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    timeout = server.timeout_ms / 1000
    kwargs: dict = {
        "hostname": server.host,
        "port": server.ssh_port,
        "username": server.ssh_username,
        "timeout": timeout,
        "banner_timeout": max(15.0, timeout),
        "auth_timeout": max(15.0, timeout),
        # 不读本机的 ~/.ssh 也不连 agent:worker 容器里没有它们,
        # 而 look_for_keys=True 会让每次连接多几次无用的认证尝试,
        # 在开了 MaxAuthTries 的机器上还可能提前被踢
        "look_for_keys": False,
        "allow_agent": False,
    }
    if server.ssh_private_key:
        kwargs["pkey"] = _load_key(server)
    else:
        kwargs["password"] = server.ssh_password

    try:
        client.connect(**kwargs)
    except paramiko.AuthenticationException:
        raise ServerError("SSH 认证失败,检查用户名 / 密码 / 私钥") from None
    except (socket.timeout, TimeoutError):
        raise ServerError(f"SSH 连接超时(>{server.timeout_ms}ms)") from None
    except socket.gaierror as exc:
        raise ServerError(f"地址解析失败:{server.host}({exc})") from exc
    except paramiko.SSHException as exc:
        raise ServerError(f"SSH 协议错误:{exc}") from exc
    except OSError as exc:
        # Connection refused / No route to host 都落在这里
        raise ServerError(f"SSH 网络错误:{exc}") from exc
    return client


def _run(client: paramiko.SSHClient, command: str, timeout: float) -> tuple[str, str]:
    """
    跑一条命令,**stdout 和 stderr 分开返回**。

    合并的话 stderr 里的 `df: unrecognized option` 之类会掉进某个分段的
    正文里,把那一段的解析搞坏。stderr 单独留着写进 extra —— 采集"成功但
    某段是空的"时,那几行是唯一能说明原因的东西。
    """

    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "ignore")
    err = stderr.read().decode("utf-8", "ignore")
    return out, err


# =========================================================================
# 采集
# =========================================================================


def _rate(current, previous, seconds: float) -> float | None:
    """
    计数器差 → bps。和 devices/collector.py 的 `_rate()` 是同一条规矩:
    **current < previous 时返回 None**(机器重启,计数器从 0 重来),
    不按差值算负数、更不取绝对值。
    """

    if current is None or previous is None or seconds <= 0:
        return None
    if current < previous:
        return None
    return round((current - previous) * 8 / seconds, 2)


def _delta(current, previous):
    if current is None or previous is None or current < previous:
        return None
    return current - previous


def _collect_raw(server: Server) -> dict:
    """
    连上去把该读的都读回来,解析成一个扁平的 dict。

    **这是唯一按系统类型分叉的地方。**返回的 dict 两条路径完全同构,
    下游(速率 / 写样本 / 阈值 / 事件)不知道也不需要知道是哪种系统。
    """

    started = time.perf_counter()
    timeout = max(10.0, server.timeout_ms / 1000 * 2)
    module = esxi if server.os_type == ServerOS.ESXI else linux
    client = _connect(server)
    try:
        stdout, stderr = _run(client, module.build_command(server.collect_processes), timeout)
    finally:
        client.close()

    # 分段协议两边共用,所以切分只有一份实现
    sections = linux.split_sections(stdout)
    if not sections:
        # 一个标记都没解析出来:登录成功但命令没跑起来。最常见的两种原因是
        # 登录 shell 不是 POSIX shell(csh/fish),或者账号被限制成
        # 只能跑某个固定命令(ForceCommand)。把原始输出带出来,
        # 否则页面上只能看到"采集失败"三个字
        detail = (stdout or stderr or "").strip().replace("\n", " ")[:160]
        raise ServerError(f"命令没有产生可解析的输出(登录 shell 不是 sh/bash?):{detail}")

    out: dict = {"extra": {}}
    if stderr.strip():
        out["extra"]["stderr"] = stderr.strip()[:400]

    if server.os_type == ServerOS.ESXI:
        _parse_esxi(server, sections, out)
    else:
        _parse_linux(server, sections, out)

    out["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return out


def _parse_linux(server: Server, sections: dict, out: dict) -> None:
    """Linux:全部来自 /proc,只有磁盘走 df。"""

    # ---- 基本信息 ----
    if hostname := sections.get("hostname", "").strip().splitlines():
        out["hostname"] = hostname[0].strip()[:128]
    if kernel := sections.get("kernel", "").strip():
        out["kernel"] = kernel.splitlines()[0].strip()[:64]
    if os_name := linux.parse_os(sections.get("os", "")):
        out["os_name"] = os_name[:128]
    out["cpu_cores"] = linux.parse_int(sections.get("cores", ""))
    out["process_count"] = linux.parse_int(sections.get("procs", ""))
    out["tcp_established"] = linux.parse_int(sections.get("tcp", ""))
    out["uptime_s"] = linux.parse_uptime(sections.get("uptime", ""))

    load1, load5, load15 = linux.parse_loadavg(sections.get("loadavg", ""))
    out["load1"], out["load5"], out["load15"] = load1, load5, load15

    # ---- 内存 ----
    out.update(linux.parse_meminfo(sections.get("meminfo", "")))

    # ---- CPU(需要上一拍的 jiffies) ----
    out["_cpu_jiffies"] = linux.parse_cpu_jiffies(sections.get("stat", ""))

    # ---- 磁盘 ----
    mounts = linux.parse_df(sections.get("df", ""))
    if mounts:
        worst = max(mounts, key=lambda m: m["pct"] or 0)
        out["disk_pct"] = worst["pct"]
        out["extra"]["disk_worst"] = worst["mount"]
        # 挂载点明细进 extra:页面上要能回答"是哪个盘满了",
        # 只给一个最大值的话人还得自己登上去 df 一遍
        out["extra"]["mounts"] = [
            {k: m[k] for k in ("mount", "fs", "total_bytes", "used_bytes", "pct")}
            for m in sorted(mounts, key=lambda m: m["pct"] or 0, reverse=True)[:12]
        ]

    # ---- 网卡 ----
    out["_interfaces"] = linux.parse_netdev(sections.get("netdev", ""))
    out["_default_interface"] = linux.parse_default_interface(sections.get("route", ""))

    # ---- 进程 Top ----
    if server.collect_processes:
        if processes := linux.parse_ps(sections.get("ps", "")):
            out["extra"]["top_processes"] = processes


def _parse_esxi(server: Server, sections: dict, out: dict) -> None:
    """
    ESXi:全部来自 esxcli / vim-cmd。

    **一个 esxcli 段都没解析出来时要报错**,不能像 Linux 那样"某段空了就
    留空"。理由是 ESXi 上"全空"最可能的原因是**系统类型选错了**(拿 Linux
    的机器当 ESXi 采),而那是个配置错误,必须说出来 —— 静默留空的话页面上
    看到的是一台指标全空、last_error 也空的机器,和这次要修的 bug 一模一样。
    """

    summary = esxi.parse_hostsummary(sections.get("summary", ""))
    version = esxi.parse_version(sections.get("version", ""))
    platform = esxi.parse_platform(sections.get("platform", ""))

    if not summary and not version:
        detail = (sections.get("summary") or sections.get("version") or "").strip()
        raise ServerError(
            "esxcli / vim-cmd 都没有返回内容 —— 这台不是 ESXi?"
            "(系统类型选成 ESXi 但对面是 Linux 时就是这个表现)"
            + (f":{detail[:120]}" if detail else "")
        )

    # ---- 基本信息 ----
    if hostname := sections.get("hostname", "").strip().splitlines():
        out["hostname"] = hostname[0].strip()[:128]
    if kernel := sections.get("kernel", "").strip():
        out["kernel"] = kernel.splitlines()[0].strip()[:64]
    if version:
        out["os_name"] = version[:128]
    if platform:
        out["extra"]["hw_platform"] = platform[:120]
    for key in ("hw_model", "hw_vendor", "maintenance_mode", "cpu_total_mhz",
                "overall_cpu_mhz", "cpu_threads", "cpu_packages"):
        if key in summary:
            out["extra"][key] = summary[key]

    # ---- CPU / 内存。hostsummary 拿不到时退回 esxcli 的规格(只有分母,
    #      没有使用率)—— 有分母至少「几核 / 多大内存」这两栏是对的 ----
    out["cpu_pct"] = summary.get("cpu_pct")
    out["cpu_iowait_pct"] = None                  # ESXi 不提供 iowait
    out["cpu_cores"] = summary.get("cpu_cores") or esxi.parse_cpu_global(sections.get("cpu", ""))
    out["mem_total_bytes"] = summary.get("mem_total_bytes") or esxi.parse_memory(
        sections.get("memory", "")
    )
    out["mem_pct"] = summary.get("mem_pct")
    out["mem_used_bytes"] = summary.get("mem_used_bytes")
    out["mem_available_bytes"] = summary.get("mem_available_bytes")
    out["swap_pct"] = None
    out["uptime_s"] = summary.get("uptime_s")

    # **负载留空**:ESXi 不提供 loadavg。拿 CPU 使用率换算一个"等效负载"
    # 是编数字 —— 那个数会被拿去和「每核阈值」比,而它根本不是同一个东西
    out["load1"] = out["load5"] = out["load15"] = None
    out["extra"]["load_absent"] = "ESXi 不提供 loadavg,负载阈值对这台不生效"

    if out["cpu_pct"] is None and summary:
        out["extra"]["cpu_pending"] = (
            "hostsummary 里没有 overallCpuUsage 或 cpuMhz,算不出使用率 —— "
            "hostd 没起来?试 `/etc/init.d/hostd status`"
        )

    # ---- 数据存储。字段和 df 对齐,所以判定那段是共用的 ----
    mounts = esxi.parse_storage(sections.get("storage", ""))
    if mounts:
        worst = max(mounts, key=lambda m: m["pct"] or 0)
        out["disk_pct"] = worst["pct"]
        out["extra"]["disk_worst"] = worst["mount"]
        out["extra"]["mounts"] = [
            {k: m[k] for k in ("mount", "fs", "total_bytes", "used_bytes", "pct")}
            for m in sorted(mounts, key=lambda m: m["pct"] or 0, reverse=True)[:12]
        ]

    # ---- 网卡 ----
    nic_list = esxi.parse_nic_list(sections.get("nics", ""))
    rows = esxi.parse_nic_stats(sections.get("nicstats", ""), nic_list)
    out["_interfaces"] = rows
    out["_default_interface"] = esxi.pick_primary(rows)

    # ---- 虚拟机 ----
    registered = esxi.parse_int(sections.get("vmregistered", ""))
    if registered is not None:
        out["extra"]["vm_registered"] = registered
    if server.collect_processes:
        vms = esxi.parse_vm_processes(sections.get("vmlist", ""))
        out["extra"]["vm_running"] = vms["running"]
        if vms["names"]:
            out["extra"]["vm_names"] = vms["names"]


def _primary_interface_name(server: Server, rows: list[dict], detected: str) -> str:
    """
    哪块网卡算"主网卡"。

    顺序:手工指定 → 默认路由 → 第一块非虚拟口。

    **由路由决定而不是由名字决定**是关键:虚拟机宿主机的默认路由几乎都走
    `br0`,而 br0 按名字规则是"虚拟口"。按名字挑的话会挑到一块没有流量的
    物理口,流量图长期是平的 —— 而且看不出哪儿错了。
    """

    names = {r["if_name"] for r in rows}
    if server.net_interface and server.net_interface in names:
        return server.net_interface
    if server.net_interface:
        # 配了但机器上没有这块网卡 —— 这是配置错误,要说出来,
        # 不要静默退回自动选择(那样人永远不知道自己填错了)
        log.warning(
            "服务器 %s 指定的网卡 %s 不存在,现有:%s",
            server.name, server.net_interface, sorted(names),
        )
    if detected and detected in names:
        return detected
    for row in rows:
        if not row["is_virtual"]:
            return row["if_name"]
    return ""


def _save_interfaces(server: Server, rows: list[dict], primary: str, now) -> dict:
    """
    写网卡当前状态,返回主网卡的速率 {in_bps, out_bps}。

    上一次的计数器存在每块网卡自己的 meta 里(和 DeviceInterface 一样),
    不为它单独加两列 —— 这一行本来就要 save。
    """

    existing = {i.if_name: i for i in server.interfaces.all()}
    seen: set[str] = set()
    primary_rate: dict = {"in_bps": None, "out_bps": None}

    for row in rows:
        name = row["if_name"][:32]
        seen.add(name)
        iface = existing.get(name) or ServerInterface(server=server, if_name=name)

        last = (iface.meta or {}).get("last") or {}
        elapsed = 0.0
        if last.get("ts"):
            try:
                from datetime import datetime

                elapsed = (now - datetime.fromisoformat(last["ts"])).total_seconds()
            except (ValueError, TypeError):
                elapsed = 0.0

        iface.is_virtual = row["is_virtual"]
        iface.is_primary = name == primary
        iface.in_octets = row["in_octets"]
        iface.out_octets = row["out_octets"]
        iface.in_bps = _rate(row["in_octets"], last.get("in_octets"), elapsed)
        iface.out_bps = _rate(row["out_octets"], last.get("out_octets"), elapsed)
        iface.in_err_delta = _delta(row["in_errors"], last.get("in_errors"))
        iface.out_err_delta = _delta(row["out_errors"], last.get("out_errors"))

        meta = dict(iface.meta or {})
        meta["last"] = {
            "ts": now.isoformat(),
            "in_octets": row["in_octets"],
            "out_octets": row["out_octets"],
            "in_errors": row["in_errors"],
            "out_errors": row["out_errors"],
        }
        iface.meta = meta
        iface.save()

        if iface.is_primary:
            primary_rate = {"in_bps": iface.in_bps, "out_bps": iface.out_bps}

    # 机器上已经没有的网卡要删掉(拔了网卡、删了 docker 网桥)——
    # 留着的话页面上会一直显示一块速率永远是 null 的网卡
    stale = set(existing) - seen
    if stale:
        server.interfaces.filter(if_name__in=stale).delete()

    return primary_rate


# =========================================================================
# 阈值判定
# =========================================================================


def evaluate_server(server: Server, data: dict, reachable: bool, error: str) -> tuple[str, list[dict]]:
    """
    **唯一的服务器阈值判定处。**状态语义在这里定完 —— 前端颜色、事件级别、
    统计口径都以这里为准(和 probes/runner.py 的 evaluate() 同一个定位)。
    """

    if not reachable:
        return LinkState.DOWN, [{
            "kind": EventKind.SERVER_DOWN, "severity": Severity.CRITICAL,
            "value": None, "threshold": None, "unit": "",
            "message": error or "服务器失联",
        }]

    problems: list[dict] = []
    state = LinkState.UP

    def check(field: str, kind: str, warn, crit, unit: str, label: str, digits: int = 1):
        nonlocal state
        value = data.get(field)
        if value is None:
            return                                # 采不到就是采不到,不判
        if crit and value >= crit:
            problems.append({
                "kind": kind, "severity": Severity.CRITICAL, "value": float(value),
                "threshold": float(crit), "unit": unit,
                "message": f"{label} {value:.{digits}f}{unit} 达到严重线 {crit}{unit}",
            })
            state = LinkState.DEGRADED
        elif warn and value >= warn:
            problems.append({
                "kind": kind, "severity": Severity.WARNING, "value": float(value),
                "threshold": float(warn), "unit": unit,
                "message": f"{label} {value:.{digits}f}{unit} 超过警告线 {warn}{unit}",
            })
            state = LinkState.DEGRADED

    check("cpu_pct", EventKind.CPU_HIGH, server.cpu_warn_pct, server.cpu_crit_pct, "%", "CPU 使用率")
    check("mem_pct", EventKind.MEM_HIGH, server.mem_warn_pct, server.mem_crit_pct, "%", "内存使用率")

    # 磁盘的消息里要带上是**哪个挂载点** —— "磁盘 91%" 这句话没法直接行动,
    # "/var 91%" 可以。ESXi 上这个名词是「数据存储」而不是「挂载点」:
    # 告警要用收件人在自己界面上看到的那个词,否则他得先翻译一遍
    disk_pct = data.get("disk_pct")
    if disk_pct is not None:
        mount = data.get("extra", {}).get("disk_worst") or "?"
        noun = "数据存储" if server.os_type == ServerOS.ESXI else "挂载点"
        if server.disk_crit_pct and disk_pct >= server.disk_crit_pct:
            problems.append({
                "kind": EventKind.DISK_HIGH, "severity": Severity.CRITICAL,
                "value": float(disk_pct), "threshold": float(server.disk_crit_pct), "unit": "%",
                "message": f"{noun} {mount} 已用 {disk_pct:.1f}%,达到严重线 {server.disk_crit_pct}%",
            })
            state = LinkState.DEGRADED
        elif server.disk_warn_pct and disk_pct >= server.disk_warn_pct:
            problems.append({
                "kind": EventKind.DISK_HIGH, "severity": Severity.WARNING,
                "value": float(disk_pct), "threshold": float(server.disk_warn_pct), "unit": "%",
                "message": f"{noun} {mount} 已用 {disk_pct:.1f}%,超过警告线 {server.disk_warn_pct}%",
            })
            state = LinkState.DEGRADED

    # 负载按每核算。**核数拿不到时不判** —— 拿 load 的绝对值去和"每核阈值"
    # 比,等于假设这台机器只有一个核,64 核的机器会天天报警
    load1, cores = data.get("load1"), data.get("cpu_cores")
    if load1 is not None and cores:
        per_core = round(load1 / cores, 2)
        if server.load_crit and per_core >= server.load_crit:
            problems.append({
                "kind": EventKind.LOAD_HIGH, "severity": Severity.CRITICAL,
                "value": per_core, "threshold": float(server.load_crit), "unit": "",
                "message": f"负载 {load1:.2f} / {cores} 核 = 每核 {per_core},达到严重线 {server.load_crit}",
            })
            state = LinkState.DEGRADED
        elif server.load_warn and per_core >= server.load_warn:
            problems.append({
                "kind": EventKind.LOAD_HIGH, "severity": Severity.WARNING,
                "value": per_core, "threshold": float(server.load_warn), "unit": "",
                "message": f"负载 {load1:.2f} / {cores} 核 = 每核 {per_core},超过警告线 {server.load_warn}",
            })
            state = LinkState.DEGRADED

    return state, problems


# =========================================================================
# 主入口
# =========================================================================


def collect_server(server: Server) -> ServerSample:
    """采一台服务器:连 → 读 → 算 → 写样本 → 判事件。"""

    now = timezone.now()
    data: dict = {"extra": {}}
    error = ""

    try:
        data = _collect_raw(server)
    except ServerError as exc:
        error = str(exc)
        log.info("服务器 %s 采集失败: %s", server.name, error)
    except Exception as exc:  # noqa: BLE001 —— 意外也要写一行样本,不能让任务炸掉
        error = f"{type(exc).__name__}: {exc}"
        log.exception("服务器 %s 采集异常", server.name)

    reachable = not error

    # ---- CPU ----
    # Linux 要两拍 /proc/stat 的 jiffies 相减;**ESXi 不用** —— hostd 自己
    # 就在算,`overallCpuUsage` 是个当前值,`_parse_esxi()` 里已经填好了。
    # 走到这里再减一次的话 ESXi 的 cpu_pct 会被一个 None 覆盖掉
    meta = dict(server.meta or {})
    if reachable and server.os_type != ServerOS.ESXI:
        cpu_pct, iowait_pct = linux.cpu_delta(meta.get("last_cpu_jiffies"), data.get("_cpu_jiffies"))
        data["cpu_pct"] = cpu_pct
        data["cpu_iowait_pct"] = iowait_pct
        if data.get("_cpu_jiffies"):
            meta["last_cpu_jiffies"] = data["_cpu_jiffies"]
        if cpu_pct is None:
            # 第一拍必然如此,不是错误 —— 页面上要能区分"没算出来"和"很闲"
            data["extra"]["cpu_pending"] = "首次采集没有上一拍的计数器,下一拍开始出数"

    # ---- 网卡与流量 ----
    net = {"in_bps": None, "out_bps": None}
    if reachable and data.get("_interfaces"):
        primary = _primary_interface_name(
            server, data["_interfaces"], data.get("_default_interface", "")
        )
        try:
            net = _save_interfaces(server, data["_interfaces"], primary, now)
        except Exception as exc:  # noqa: BLE001 —— 网卡写失败不该让整机指标丢掉
            log.warning("服务器 %s 网卡写入失败: %s", server.name, exc)
            data["extra"]["interface_error"] = str(exc)[:200]
        data["extra"]["primary_interface"] = primary
        data["extra"]["interface_count"] = len(data["_interfaces"])

    # ---- 写样本 ----
    sample = ServerSample.objects.create(
        server=server, ts=now, reachable=reachable,
        latency_ms=data.get("latency_ms"),
        cpu_pct=data.get("cpu_pct"), cpu_iowait_pct=data.get("cpu_iowait_pct"),
        mem_pct=data.get("mem_pct"), swap_pct=data.get("swap_pct"),
        disk_pct=data.get("disk_pct"),
        load1=data.get("load1"), load5=data.get("load5"), load15=data.get("load15"),
        uptime_s=int(data["uptime_s"]) if data.get("uptime_s") is not None else None,
        process_count=data.get("process_count"),
        tcp_established=data.get("tcp_established"),
        net_in_bps=net["in_bps"], net_out_bps=net["out_bps"],
        extra=data.get("extra") or {}, error=error[:255],
    )

    # ---- 回写服务器状态 ----
    state, problems = evaluate_server(server, data, reachable, error)
    fields = ["state", "last_collected_at", "last_error",
              "consecutive_fail", "consecutive_ok", "meta"]
    server.state = state
    server.last_collected_at = now
    server.last_error = error[:255]
    if reachable:
        server.consecutive_ok += 1
        server.consecutive_fail = 0
    else:
        server.consecutive_fail += 1
        server.consecutive_ok = 0
    server.meta = meta

    # 基本信息首次采集回填。**已有值不覆盖**,除了内核和系统版本 ——
    # 那两个升级之后就该跟着变,而它们本来就是采出来的、没人手填
    for field, attr in (("hostname", "hostname"), ("cpu_cores", "cpu_cores"),
                        ("mem_total_bytes", "mem_total_bytes")):
        value = data.get(field)
        if value and not getattr(server, attr):
            setattr(server, attr, value)
            fields.append(attr)
    for field, attr, limit in (("os_name", "os_name", 128), ("kernel", "kernel", 64)):
        value = data.get(field)
        if value and str(value)[:limit] != getattr(server, attr):
            setattr(server, attr, str(value)[:limit])
            fields.append(attr)

    server.save(update_fields=list(dict.fromkeys(fields)))

    # ---- 事件 ----
    outcome = event_engine.process(event_engine.EventSource.from_server(server), problems)
    _queue_notifications(outcome)
    return sample


def _queue_notifications(outcome) -> None:
    from netcheck.tasks import send_notification

    for event in outcome.opened + outcome.escalated:
        send_notification.delay(event.pk, "alert")
    for event in outcome.resolved:
        send_notification.delay(event.pk, "recover")


def test_connection(server: Server) -> tuple[bool, str]:
    """
    配置中心的「测试」按钮。

    **不写库、不开事件** —— 这是"试一下能不能连上",不是一次正式采样。

    Linux 那条路径返回的摘要里刻意**不含 CPU 使用率**:它要两拍 jiffies
    才算得出来,这里只有一拍。硬要在测试里给个数就得在对端 sleep 1 秒,
    那会让"测试"和"采集"走两条不同的代码路径 —— 而测试的意义正是验证
    采集那条路径。**ESXi 那条有 CPU**(hostd 给的是当前值,不用相减),
    所以这句提示按系统类型给,不要写死。
    """

    started = time.perf_counter()
    try:
        data = _collect_raw(server)
    except ServerError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"

    elapsed = int((time.perf_counter() - started) * 1000)
    extra = data.get("extra") or {}
    is_esxi = server.os_type == ServerOS.ESXI
    parts = [
        data.get("hostname") or server.host,
        data.get("os_name") or "",
        extra.get("hw_platform") if is_esxi else data.get("kernel") or "",
    ]
    head = " · ".join(p for p in parts if p)

    detail = [f"{head}({elapsed}ms)"]
    if cores := data.get("cpu_cores"):
        detail.append(f"CPU {cores} 核")
    if data.get("cpu_pct") is not None:
        detail.append(f"CPU 使用率 {data['cpu_pct']:.1f}%")
    if total := data.get("mem_total_bytes"):
        detail.append(f"内存 {total / 1024 ** 3:.1f} GiB")
    if data.get("mem_pct") is not None:
        detail.append(f"已用 {data['mem_pct']:.1f}%")
    if data.get("load1") is not None:
        detail.append(f"负载 {data['load1']:.2f}")
    if data.get("disk_pct") is not None:
        worst = extra.get("disk_worst", "?")
        label = "数据存储最满" if is_esxi else "磁盘最满"
        detail.append(f"{label} {worst} {data['disk_pct']:.1f}%")

    interfaces = data.get("_interfaces") or []
    primary = _primary_interface_name(server, interfaces, data.get("_default_interface", ""))
    nic_label = "上行口 vmnic" if is_esxi else "网卡"
    detail.append(f"{nic_label} {len(interfaces)} 块,流量统计走 {primary or '未确定'}")

    if is_esxi:
        # 这两行是 ESXi 上最容易一眼看出接错了的地方:虚拟机数为 0 说明
        # 要么这台真的空着,要么 vim-cmd 没权限(非 root 账号常见)
        vm_bits = []
        if (registered := extra.get("vm_registered")) is not None:
            vm_bits.append(f"已注册 {registered}")
        if (running := extra.get("vm_running")) is not None:
            vm_bits.append(f"运行中 {running}")
        if vm_bits:
            detail.append("虚拟机 " + " / ".join(vm_bits))
        detail.append("ESXi 没有 loadavg,负载阈值对这台不生效")
    else:
        detail.append("CPU 使用率要第二拍才有(靠两次 /proc/stat 相减)")
    return True, " | ".join(detail)
