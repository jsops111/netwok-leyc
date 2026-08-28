"""
登录失败锁定。

密码 + 可选的两步验证,挡不住"慢慢试"—— 一个 6 位验证码只有一百万种可能,
不限速的话在线爆破是可行的。这里按**用户名**和**来源 IP** 各记一份计数:

- 只按用户名记:一台机器可以横着试所有用户名,每个都不到阈值
- 只按 IP 记:出口 NAT 后面一整个办公室共用一个 IP,一个人输错会锁掉所有人

计数放在 Redis(Django cache)里,不落库 —— 它是**短时**状态,
每次登录都写一行数据库既没必要也会让登录变慢。要看历史看 LoginAudit。

**Redis 挂了时放行,不是拦截。**拦截的后果是整个平台没人能登录,
而这个模块只是一道限速,不是唯一的防线(密码和 2FA 才是)。
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.core.cache import cache

log = logging.getLogger("netcheck.auth")

_PREFIX = "login-fail"


def _keys(username: str, ip: str | None) -> list[str]:
    keys = [f"{_PREFIX}:u:{(username or '').strip().lower()[:150]}"]
    if ip:
        keys.append(f"{_PREFIX}:i:{ip}")
    return keys


def locked_seconds(username: str, ip: str | None) -> int:
    """还要锁多久(秒)。0 表示没锁。"""

    limit = settings.NETCHECK_LOGIN_MAX_FAILS
    try:
        for key in _keys(username, ip):
            if (cache.get(key) or 0) >= limit:
                ttl = cache.ttl(key) if hasattr(cache, "ttl") else None
                return int(ttl) if ttl and ttl > 0 else settings.NETCHECK_LOGIN_LOCK_SECONDS
    except Exception as exc:                     # noqa: BLE001 —— 见模块注释
        log.warning("登录锁定检查失败(放行):%s", exc)
    return 0


def record_failure(username: str, ip: str | None) -> None:
    window = settings.NETCHECK_LOGIN_LOCK_SECONDS
    try:
        for key in _keys(username, ip):
            # add + incr:第一次落 TTL,之后只加计数。**不要每次都重设 TTL** ——
            # 那样持续的慢速尝试会把锁定窗口无限续期,反而把真人挡在外面。
            if not cache.add(key, 1, timeout=window):
                try:
                    cache.incr(key)
                except ValueError:               # 刚好在两步之间过期了
                    cache.add(key, 1, timeout=window)
    except Exception as exc:                     # noqa: BLE001
        log.warning("登录失败计数写入失败:%s", exc)


def clear(username: str, ip: str | None) -> None:
    """登录成功后清零 —— 否则白天输错几次,晚上正常登录还在计数里。"""

    try:
        cache.delete_many(_keys(username, ip))
    except Exception as exc:                     # noqa: BLE001
        log.warning("登录失败计数清理失败:%s", exc)


def client_ip(request) -> str | None:
    """
    取真实来源 IP。前面有 nginx 反代,REMOTE_ADDR 恒等于容器网关地址,
    审计里全是同一个 IP 等于没记 —— 所以优先取 X-Forwarded-For 的第一段
    (nginx.conf 里配了 X-Forwarded-For)。
    """

    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first[:45]
    return (request.META.get("REMOTE_ADDR") or "").strip()[:45] or None
