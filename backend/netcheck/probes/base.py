"""
拨测结果的统一形状,以及错误分类。

每个协议探测器都只做一件事:发起探测,返回一个 ProbeResult。
**判定状态、开关事件、写库都不在探测器里** —— 那些在 runner.py 和
events/engine.py。这样加一个新协议只要写一个函数。
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ErrorKind:
    """
    错误分类。分得细是为了让事件表里能一眼看出"断"的性质:
    连不上(refused)和连上了但内容不对(keyword)在运维上是两回事。
    """

    TIMEOUT = "timeout"  # 超时无响应
    DNS_FAIL = "dns_fail"  # 目标域名解析不出来
    REFUSED = "refused"  # 端口拒绝连接
    UNREACHABLE = "unreachable"  # 网络/主机不可达
    TLS = "tls"  # 证书或握手失败
    HTTP_STATUS = "http_status"  # 状态码不符合期望
    KEYWORD = "keyword"  # 响应体缺少期望关键字
    DNS_RCODE = "dns_rcode"  # DNS 服务器返回错误码
    DNS_MISMATCH = "dns_mismatch"  # 解析结果不含期望值
    DNS_EMPTY = "dns_empty"  # 解析成功但没有记录
    PARTIAL_LOSS = "partial_loss"  # 通但有丢包
    UNKNOWN = "unknown"


@dataclass
class ProbeResult:
    """
    一次探测的原始观测值 —— 只有事实,没有判断。

    rtt_ms 在完全不通时必须是 None 而不是 0:写 0 会把平均延迟拉低,
    图上看着比实际情况好。同理 loss_pct 不通时是 100.0。
    """

    ok: bool
    rtt_ms: float | None = None
    rtt_min_ms: float | None = None
    rtt_max_ms: float | None = None
    loss_pct: float = 0.0
    jitter_ms: float | None = None
    error_kind: str = ""
    error: str = ""
    extra: dict = field(default_factory=dict)

    @classmethod
    def failure(cls, kind: str, message: str, **extra) -> "ProbeResult":
        return cls(ok=False, loss_pct=100.0, error_kind=kind, error=message[:255], extra=extra)


def jitter_from_rtts(rtts: list[float]) -> float | None:
    """
    从一组 RTT 算抖动。

    用的是相邻包延迟差的平均绝对值(IPDV,RFC 3393 的思路),不是标准差 ——
    ping 输出里的 mdev 是标准差,它对"稳定但偏高"的线路给不出区分度,
    而运维真正关心的是"包与包之间跳不跳"。少于两个包时抖动没有定义,返回 None。
    """

    if len(rtts) < 2:
        return None
    diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
    return round(sum(diffs) / len(diffs), 3)


def classify_socket_error(exc: BaseException) -> tuple[str, str]:
    """socket / OSError 到 (error_kind, 可读信息) 的映射。"""

    import socket as _socket

    if isinstance(exc, _socket.timeout) or isinstance(exc, TimeoutError):
        return ErrorKind.TIMEOUT, "连接超时"
    if isinstance(exc, _socket.gaierror):
        return ErrorKind.DNS_FAIL, f"目标地址解析失败: {exc}"
    if isinstance(exc, ConnectionRefusedError):
        return ErrorKind.REFUSED, "端口拒绝连接"
    if isinstance(exc, OSError):
        # errno 101 ENETUNREACH / 113 EHOSTUNREACH / 111 ECONNREFUSED
        if exc.errno in (101, 113):
            return ErrorKind.UNREACHABLE, "网络不可达"
        if exc.errno == 111:
            return ErrorKind.REFUSED, "端口拒绝连接"
        return ErrorKind.UNKNOWN, f"{type(exc).__name__}: {exc}"
    return ErrorKind.UNKNOWN, f"{type(exc).__name__}: {exc}"
