"""
拨测调度的执行侧:按协议分发 → 判定状态 → 写样本 → 交给事件引擎。

**状态判定只在这里做一次**(evaluate),探测器只报事实。这样阈值语义
在一个地方定义完,前端的颜色、事件的级别、大屏的统计全都对得上。
"""

from __future__ import annotations

import logging

from django.utils import timezone

from netcheck.models import LinkState, ProbeSample, ProbeTarget, Protocol, Severity

from .base import ErrorKind, ProbeResult
from .dns import probe_dns
from .http import probe_http
from .icmp import probe_icmp
from .tcp import probe_tcp, probe_udp

log = logging.getLogger("netcheck.probe")

# 默认端口:线路没填端口时按协议兜底
DEFAULT_PORTS = {Protocol.HTTP: 80, Protocol.HTTPS: 443, Protocol.DNS: 53}

# error_kind → 事件类型。没列到的一律算 ANOMALY(异常),
# 这样新增错误分类不会让事件悄悄丢掉。
_KIND_TO_EVENT = {
    ErrorKind.TIMEOUT: "down",
    ErrorKind.UNREACHABLE: "down",
    ErrorKind.REFUSED: "down",
    ErrorKind.DNS_FAIL: "down",
}


def execute(target: ProbeTarget) -> ProbeResult:
    """按协议分发。这里不写库,方便单独测一条线路(配置中心的「测试」按钮走这条)。"""

    proto = target.protocol
    port = target.port or DEFAULT_PORTS.get(proto)

    if proto == Protocol.ICMP:
        return probe_icmp(target.host, count=target.packets, timeout_ms=target.timeout_ms)
    if proto == Protocol.TCP:
        return probe_tcp(target.host, port, count=min(target.packets, 5), timeout_ms=target.timeout_ms)
    if proto == Protocol.UDP:
        return probe_udp(target.host, port, count=min(target.packets, 5), timeout_ms=target.timeout_ms)
    if proto in (Protocol.HTTP, Protocol.HTTPS):
        return probe_http(
            target.host,
            port=port,
            scheme="https" if proto == Protocol.HTTPS else "http",
            path=target.http_path or "/",
            method=target.http_method or "GET",
            expect_code=target.http_expect_code,
            expect_keyword=target.http_expect_keyword,
            verify_tls=target.http_verify_tls,
            timeout_ms=target.timeout_ms,
        )
    if proto == Protocol.DNS:
        return probe_dns(
            target.host,
            target.dns_query,
            port=port or 53,
            expect=target.dns_expect,
            count=min(target.packets, 3),
            timeout_ms=target.timeout_ms,
        )
    return ProbeResult.failure(ErrorKind.UNKNOWN, f"未实现的协议 {proto}")


def evaluate(target: ProbeTarget, result: ProbeResult) -> tuple[str, list[dict]]:
    """
    把观测值判成状态,并列出这一拍**应该处于活动状态**的问题。

    返回 (LinkState, problems),problems 里每项形如
    {"kind": "loss", "severity": "warning", "value": 12.0, "threshold": 5.0, "unit": "%", "message": ...}

    注意返回的是"当前问题清单",不是"要开的事件" —— 开关事件要看连续次数,
    那是 events/engine.py 的职责。
    """

    problems: list[dict] = []

    if not result.ok:
        kind = _KIND_TO_EVENT.get(result.error_kind, "anomaly")
        # 完全不通才算 down;状态码/关键字/DNS 结果不对算异常,线路仍是 degraded
        state = LinkState.DOWN if kind == "down" else LinkState.DEGRADED
        problems.append(
            {
                "kind": kind,
                "severity": Severity.CRITICAL,
                "value": result.rtt_ms,
                "threshold": None,
                "unit": "ms" if result.rtt_ms is not None else "",
                "message": result.error or "探测失败",
            }
        )
        return state, problems

    state = LinkState.UP

    # ---- 丢包 ----
    if result.loss_pct > 0:
        if target.loss_crit_pct and result.loss_pct >= target.loss_crit_pct:
            problems.append({
                "kind": "loss", "severity": Severity.CRITICAL, "value": result.loss_pct,
                "threshold": target.loss_crit_pct, "unit": "%",
                "message": f"丢包率 {result.loss_pct}% 达到严重线 {target.loss_crit_pct}%",
            })
            state = LinkState.DEGRADED
        elif target.loss_warn_pct and result.loss_pct >= target.loss_warn_pct:
            problems.append({
                "kind": "loss", "severity": Severity.WARNING, "value": result.loss_pct,
                "threshold": target.loss_warn_pct, "unit": "%",
                "message": f"丢包率 {result.loss_pct}% 超过警告线 {target.loss_warn_pct}%",
            })
            state = LinkState.DEGRADED

    # ---- 延迟 ----
    if result.rtt_ms is not None:
        if target.latency_crit_ms and result.rtt_ms >= target.latency_crit_ms:
            problems.append({
                "kind": "latency", "severity": Severity.CRITICAL, "value": result.rtt_ms,
                "threshold": float(target.latency_crit_ms), "unit": "ms",
                "message": f"延迟 {result.rtt_ms}ms 达到严重线 {target.latency_crit_ms}ms",
            })
            state = LinkState.DEGRADED
        elif target.latency_warn_ms and result.rtt_ms >= target.latency_warn_ms:
            problems.append({
                "kind": "latency", "severity": Severity.WARNING, "value": result.rtt_ms,
                "threshold": float(target.latency_warn_ms), "unit": "ms",
                "message": f"延迟 {result.rtt_ms}ms 超过警告线 {target.latency_warn_ms}ms",
            })
            state = LinkState.DEGRADED

    # ---- 抖动 ----
    if result.jitter_ms is not None:
        if target.jitter_crit_ms and result.jitter_ms >= target.jitter_crit_ms:
            problems.append({
                "kind": "jitter", "severity": Severity.CRITICAL, "value": result.jitter_ms,
                "threshold": float(target.jitter_crit_ms), "unit": "ms",
                "message": f"抖动 {result.jitter_ms}ms 达到严重线 {target.jitter_crit_ms}ms",
            })
            state = LinkState.DEGRADED
        elif target.jitter_warn_ms and result.jitter_ms >= target.jitter_warn_ms:
            problems.append({
                "kind": "jitter", "severity": Severity.WARNING, "value": result.jitter_ms,
                "threshold": float(target.jitter_warn_ms), "unit": "ms",
                "message": f"抖动 {result.jitter_ms}ms 超过警告线 {target.jitter_warn_ms}ms",
            })
            state = LinkState.DEGRADED

    return state, problems
