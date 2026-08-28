"""
ICMP 探测。

**走系统 ping 命令而不是 raw socket**,这是个有意的选择:raw socket 需要
CAP_NET_RAW(要么以 root 跑 worker,要么给解释器打 capability),而这个平台
是要塞进容器里长期跑的。系统 ping 自带 setuid/cap,普通用户就能用。

代价是要解析文本输出。所以这里**逐包解析 `time=` 行**,而不是去信最后那行
汇总 —— 一是能自己算 IPDV 抖动(见 base.jitter_from_rtts),二是 iputils 和
busybox 两种 ping 的汇总行格式并不一样,逐包解析反而更稳。
"""

from __future__ import annotations

import re
import shutil
import subprocess

from .base import ErrorKind, ProbeResult, jitter_from_rtts

# "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=3.21 ms"
_RE_TIME = re.compile(r"time[=<]([\d.]+)\s*ms", re.IGNORECASE)
# "5 packets transmitted, 4 received, 20% packet loss"
_RE_SUMMARY = re.compile(r"(\d+)\s+packets transmitted,\s*(\d+)\s*(?:packets\s+)?received")
_RE_UNREACH = re.compile(r"(unreachable|100% packet loss|unknown host|name or service not known)", re.I)


def _ping_binary() -> str | None:
    return shutil.which("ping")


def probe_icmp(host: str, count: int = 5, timeout_ms: int = 2000) -> ProbeResult:
    binary = _ping_binary()
    if not binary:
        return ProbeResult.failure(
            ErrorKind.UNKNOWN, "容器/主机里没有 ping 命令,装 iputils 或把该线路改成 TCP 检测"
        )

    # -W 是**单包**等待秒数,iputils 只接受整数秒,不足 1 秒的超时会被当成 0
    # (= 不等待),所以这里向上取整到 1 秒。
    per_packet_wait = max(1, round(timeout_ms / 1000))
    # -i 0.2 是包间隔。低于 0.2 秒非 root 会被拒("cannot flood"),别再调小。
    cmd = [binary, "-n", "-c", str(count), "-W", str(per_packet_wait), "-i", "0.2", host]
    # 整体超时留出余量:count 个包 × (间隔 + 单包等待) 再加 2 秒启动开销
    hard_timeout = count * (0.2 + per_packet_wait) + 2

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=hard_timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return ProbeResult.failure(ErrorKind.TIMEOUT, f"ping 整体超时({hard_timeout:.0f}s 未返回)")
    except OSError as exc:
        return ProbeResult.failure(ErrorKind.UNKNOWN, f"ping 执行失败: {exc}")

    out = (proc.stdout or "") + (proc.stderr or "")
    rtts = [float(m) for m in _RE_TIME.findall(out)]

    sent, received = count, len(rtts)
    if m := _RE_SUMMARY.search(out):
        sent, received = int(m.group(1)), int(m.group(2))
    sent = sent or count

    if received == 0:
        # 区分"解析不出来"和"通不了" —— 前者是配置问题,后者是线路问题
        if _RE_UNREACH.search(out) and re.search(r"unknown host|not known", out, re.I):
            return ProbeResult.failure(ErrorKind.DNS_FAIL, f"{host} 无法解析")
        kind = ErrorKind.UNREACHABLE if re.search(r"unreachable", out, re.I) else ErrorKind.TIMEOUT
        return ProbeResult.failure(kind, f"{sent} 个包全部丢失", sent=sent)

    loss_pct = round((sent - received) / sent * 100, 2) if sent else 0.0
    return ProbeResult(
        # 只要有回包就算"通" —— 有丢包但没断,状态判定交给 runner 按阈值定 degraded
        ok=True,
        rtt_ms=round(sum(rtts) / len(rtts), 3),
        rtt_min_ms=round(min(rtts), 3),
        rtt_max_ms=round(max(rtts), 3),
        loss_pct=loss_pct,
        jitter_ms=jitter_from_rtts(rtts),
        error_kind=ErrorKind.PARTIAL_LOSS if loss_pct else "",
        error=f"丢包 {loss_pct}%({sent - received}/{sent})" if loss_pct else "",
        extra={"sent": sent, "received": received},
    )
