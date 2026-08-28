"""
HTTP / HTTPS 探测。

判定分三层,顺序不能换 —— 因为它们对应的运维含义是递进的:
    1. 连得上吗       连不上 → down
    2. 状态码对吗     不对   → 异常(anomaly),线路本身是通的
    3. 内容对吗       不对   → 异常
第 2、3 层失败时 ok=False 但 error_kind 是 http_status / keyword,
事件类型会落到 ANOMALY 而不是 DOWN。这个区分在故障定位时很值钱:
"网络通但服务返回 502" 和 "网络不通" 找的是完全不同的人。

TLS 证书剩余天数顺手采下来放 extra —— 证书过期导致的"故障"每年都会发生几起,
而它是唯一一种能提前 30 天就看到的故障。
"""

from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone

import requests
from requests.exceptions import ConnectionError as ReqConnError
from requests.exceptions import SSLError, Timeout

from .base import ErrorKind, ProbeResult

_UA = "network-check/0.1 (+monitoring probe)"


def _tls_cert_days_left(host: str, port: int, timeout: float) -> int | None:
    """
    取证书剩余天数。

    **故意不校验证书**(CERT_NONE):目的是"看到期时间",自签名或链不全的站点
    同样需要看到 —— 校验开着这些站点直接抛异常,什么信息都拿不到。
    是否因为证书问题判故障由 http_verify_tls 决定,与此无关。

    但 CERT_NONE 有个坑:**这种模式下 OpenSSL 不填充 getpeercert() 的字典**,
    返回的是空 dict。所以这里取 DER 原文(binary_form=True)自己解析 ——
    cryptography 本来就是依赖(凭据加密在用),不多引入任何东西。
    只用字典版的话,内网自签名站点的到期时间永远是空,而那恰恰是最该盯的一类:
    证书过期是唯一一种能提前 30 天看到的故障。
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                # 先试字典版(校验开启时它是填好的,省一次解析)
                cert = tls.getpeercert()
                if cert and "notAfter" in cert:
                    expires = datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    return (expires - datetime.now(timezone.utc)).days

                der = tls.getpeercert(binary_form=True)
                if not der:
                    return None
                from cryptography import x509

                parsed = x509.load_der_x509_certificate(der)
                # cryptography 42+ 用 not_valid_after_utc(带时区);
                # 旧版只有 not_valid_after(naive UTC),两个都认
                expires = getattr(parsed, "not_valid_after_utc", None)
                if expires is None:
                    expires = parsed.not_valid_after.replace(tzinfo=timezone.utc)
                return (expires - datetime.now(timezone.utc)).days
    except Exception:  # noqa: BLE001 —— 证书信息是附加项,拿不到不影响探测结论
        return None


def probe_http(
    host: str,
    *,
    port: int | None = None,
    scheme: str = "http",
    path: str = "/",
    method: str = "GET",
    expect_code: int = 200,
    expect_keyword: str = "",
    verify_tls: bool = False,
    timeout_ms: int = 5000,
) -> ProbeResult:
    timeout = timeout_ms / 1000
    netloc = host if not port or port in (80, 443) else f"{host}:{port}"
    url = f"{scheme}://{netloc}{path if path.startswith('/') else '/' + path}"
    extra: dict = {"url": url}

    started = time.perf_counter()
    try:
        resp = requests.request(
            method.upper() or "GET",
            url,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=False,  # 302 本身就是有效信息,跟过去会掩盖掉
            headers={"User-Agent": _UA},
        )
    except Timeout:
        return ProbeResult.failure(ErrorKind.TIMEOUT, f"HTTP 请求超时(>{timeout:.1f}s)", **extra)
    except SSLError as exc:
        return ProbeResult.failure(ErrorKind.TLS, f"TLS 失败: {exc}", **extra)
    except ReqConnError as exc:
        text = str(exc)
        kind = ErrorKind.DNS_FAIL if "Name or service not known" in text else ErrorKind.UNREACHABLE
        return ProbeResult.failure(kind, f"连接失败: {text[:180]}", **extra)
    except Exception as exc:  # noqa: BLE001
        return ProbeResult.failure(ErrorKind.UNKNOWN, f"{type(exc).__name__}: {exc}", **extra)

    rtt = round((time.perf_counter() - started) * 1000, 3)
    extra.update({"http_status": resp.status_code, "size": len(resp.content)})
    if scheme == "https":
        days = _tls_cert_days_left(host, port or 443, timeout)
        if days is not None:
            extra["cert_days_left"] = days

    if expect_code and resp.status_code != expect_code:
        return ProbeResult(
            ok=False,
            rtt_ms=rtt,
            loss_pct=100.0,
            error_kind=ErrorKind.HTTP_STATUS,
            error=f"状态码 {resp.status_code},期望 {expect_code}",
            extra=extra,
        )
    if expect_keyword:
        body = resp.text if resp.encoding else resp.content.decode("utf-8", "ignore")
        if expect_keyword not in body:
            return ProbeResult(
                ok=False,
                rtt_ms=rtt,
                loss_pct=100.0,
                error_kind=ErrorKind.KEYWORD,
                error=f"响应体不含关键字 {expect_keyword!r}",
                extra=extra,
            )

    return ProbeResult(ok=True, rtt_ms=rtt, rtt_min_ms=rtt, rtt_max_ms=rtt, extra=extra)
