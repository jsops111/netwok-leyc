"""
TCP / UDP 端口探测。

TCP 测的是**握手时间**,不是"端口有没有开" —— 连上就立刻关,不发任何数据,
所以对被测服务是无害的。多次连接的 RTT 差用来算抖动,和 ICMP 一致。

UDP 天生没有握手,所以只能间接判断:发一个空包,若回来 ICMP Port Unreachable
则端口是关的(这是明确的否定),什么都没回来则**当成通** —— 因为绝大多数 UDP
服务对无效载荷就是不回应。这一点在页面上有提示,别把 UDP 的"通"当成
和 TCP 同等强度的证据。
"""

from __future__ import annotations

import socket
import time

from .base import ErrorKind, ProbeResult, classify_socket_error, jitter_from_rtts


def probe_tcp(host: str, port: int, count: int = 3, timeout_ms: int = 2000) -> ProbeResult:
    timeout = timeout_ms / 1000
    rtts: list[float] = []
    last_kind, last_err = ErrorKind.UNKNOWN, ""

    for _ in range(max(1, count)):
        started = time.perf_counter()
        sock = None
        try:
            # create_connection 会自己遍历 getaddrinfo 的结果,双栈环境下
            # v6 不通会自动回落 v4 —— 手写 socket() 拿不到这个行为
            sock = socket.create_connection((host, port), timeout=timeout)
            rtts.append((time.perf_counter() - started) * 1000)
        except Exception as exc:  # noqa: BLE001 —— 分类交给 classify_socket_error
            last_kind, last_err = classify_socket_error(exc)
        finally:
            if sock is not None:
                sock.close()

    if not rtts:
        return ProbeResult.failure(last_kind, last_err or f"{host}:{port} 无法建立 TCP 连接")

    attempts = max(1, count)
    loss_pct = round((attempts - len(rtts)) / attempts * 100, 2)
    return ProbeResult(
        ok=True,
        rtt_ms=round(sum(rtts) / len(rtts), 3),
        rtt_min_ms=round(min(rtts), 3),
        rtt_max_ms=round(max(rtts), 3),
        loss_pct=loss_pct,
        jitter_ms=jitter_from_rtts(rtts),
        error_kind=ErrorKind.PARTIAL_LOSS if loss_pct else "",
        error=f"{attempts - len(rtts)}/{attempts} 次连接失败: {last_err}" if loss_pct else "",
        extra={"attempts": attempts, "succeeded": len(rtts)},
    )


def probe_udp(host: str, port: int, count: int = 3, timeout_ms: int = 2000) -> ProbeResult:
    timeout = timeout_ms / 1000
    rtts: list[float] = []
    refused = 0
    last_err = ""

    for _ in range(max(1, count)):
        started = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                sock.send(b"\x00")
                try:
                    sock.recv(1024)
                    rtts.append((time.perf_counter() - started) * 1000)
                except socket.timeout:
                    # 没回应 —— UDP 的常态,记为通,RTT 用等待时长没有意义,
                    # 所以这里记的是"发出去到超时"的时间下限,不进 rtts
                    rtts.append((time.perf_counter() - started) * 1000)
        except ConnectionRefusedError:
            # 收到了 ICMP Port Unreachable,这是端口关闭的明确证据
            refused += 1
            last_err = "端口拒绝(收到 ICMP Port Unreachable)"
        except Exception as exc:  # noqa: BLE001
            _, last_err = classify_socket_error(exc)

    attempts = max(1, count)
    if refused == attempts:
        return ProbeResult.failure(ErrorKind.REFUSED, last_err)
    if not rtts:
        return ProbeResult.failure(ErrorKind.UNKNOWN, last_err or "UDP 探测无结果")

    loss_pct = round((attempts - len(rtts)) / attempts * 100, 2)
    return ProbeResult(
        ok=True,
        rtt_ms=round(sum(rtts) / len(rtts), 3),
        rtt_min_ms=round(min(rtts), 3),
        rtt_max_ms=round(max(rtts), 3),
        loss_pct=loss_pct,
        jitter_ms=jitter_from_rtts(rtts),
        error_kind=ErrorKind.PARTIAL_LOSS if loss_pct else "",
        error=last_err if loss_pct else "",
        extra={"attempts": attempts, "refused": refused, "note": "UDP 无响应按通计"},
    )
