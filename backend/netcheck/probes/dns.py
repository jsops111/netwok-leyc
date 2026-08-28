"""
DNS 探测。

关键点:查询是**发给 target.host 那台 DNS 服务器**的,不是走本机 resolver。
需求里"配置我需要检测的 IP"对 DNS 线路来说指的就是这台服务器,
所以这里必须显式指定 nameserver(见 pyproject 里为什么引入 dnspython)。
"""

from __future__ import annotations

import time

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from .base import ErrorKind, ProbeResult, jitter_from_rtts


def probe_dns(
    server: str,
    query_name: str,
    *,
    port: int = 53,
    expect: str = "",
    count: int = 2,
    timeout_ms: int = 2000,
    rdtype: str = "A",
) -> ProbeResult:
    timeout = timeout_ms / 1000
    rtts: list[float] = []
    answers: list[str] = []
    last_kind, last_err = ErrorKind.UNKNOWN, ""

    try:
        qtype = dns.rdatatype.from_text(rdtype)
    except dns.rdatatype.UnknownRdatatype:
        return ProbeResult.failure(ErrorKind.UNKNOWN, f"不认识的记录类型 {rdtype}")

    for _ in range(max(1, count)):
        query = dns.message.make_query(query_name, qtype)
        started = time.perf_counter()
        try:
            resp = dns.query.udp(query, server, timeout=timeout, port=port)
        except dns.exception.Timeout:
            last_kind, last_err = ErrorKind.TIMEOUT, f"{server} 无响应(>{timeout:.1f}s)"
            continue
        except Exception as exc:  # noqa: BLE001
            last_kind, last_err = ErrorKind.UNREACHABLE, f"查询失败: {exc}"
            continue

        elapsed = (time.perf_counter() - started) * 1000
        rcode = resp.rcode()
        if rcode != dns.rcode.NOERROR:
            # 服务器答了,但答的是错误 —— 这说明服务是活的、线路是通的,
            # 所以 rtt 有意义,记下来;结论仍是失败。
            rtts.append(elapsed)
            last_kind = ErrorKind.DNS_RCODE
            last_err = f"服务器返回 {dns.rcode.to_text(rcode)}"
            continue

        rtts.append(elapsed)
        for rrset in resp.answer:
            for item in rrset:
                answers.append(item.to_text())

    if not rtts:
        return ProbeResult.failure(last_kind, last_err or "DNS 查询无结果")

    attempts = max(1, count)
    loss_pct = round((attempts - len(rtts)) / attempts * 100, 2)
    extra = {"answers": answers[:10], "server": server, "query": query_name, "rdtype": rdtype}

    if last_kind == ErrorKind.DNS_RCODE and not answers:
        return ProbeResult(
            ok=False, rtt_ms=round(sum(rtts) / len(rtts), 3), loss_pct=100.0,
            error_kind=ErrorKind.DNS_RCODE, error=last_err, extra=extra,
        )
    if not answers:
        return ProbeResult(
            ok=False, rtt_ms=round(sum(rtts) / len(rtts), 3), loss_pct=100.0,
            error_kind=ErrorKind.DNS_EMPTY, error=f"{query_name} 解析成功但无 {rdtype} 记录",
            extra=extra,
        )
    if expect and not any(expect in a for a in answers):
        # 解析通了但结果不对 —— 典型是 DNS 被劫持或配置改错,
        # 这是"异常"不是"断线",事件类型会落到 ANOMALY
        return ProbeResult(
            ok=False, rtt_ms=round(sum(rtts) / len(rtts), 3), loss_pct=loss_pct,
            error_kind=ErrorKind.DNS_MISMATCH,
            error=f"解析结果 {answers[:3]} 不含期望值 {expect!r}", extra=extra,
        )

    return ProbeResult(
        ok=True,
        rtt_ms=round(sum(rtts) / len(rtts), 3),
        rtt_min_ms=round(min(rtts), 3),
        rtt_max_ms=round(max(rtts), 3),
        loss_pct=loss_pct,
        jitter_ms=jitter_from_rtts(rtts),
        error_kind=ErrorKind.PARTIAL_LOSS if loss_pct else "",
        error=last_err if loss_pct else "",
        extra=extra,
    )
