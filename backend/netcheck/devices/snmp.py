"""
SNMP 采集通道(主通道)。

pysnmp 7 只有 asyncio API,而 Celery worker 是同步的 —— 所以每次采集在
`asyncio.run()` 里跑一趟完整的事件循环。**不要试图复用全局 SnmpEngine**:
它和创建它的事件循环绑定,循环关掉之后再用会挂在 socket 上不返回
(表现是任务卡死而不是报错,极难查)。每次新建的开销在 60 秒的采集周期里
可以忽略。
"""

from __future__ import annotations

import asyncio
import logging
import time

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    usm3DESEDEPrivProtocol,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

from netcheck.models import Device, SnmpSecLevel, SnmpVersion

log = logging.getLogger("netcheck.snmp")

_AUTH_PROTOCOLS = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA1": usmHMACSHAAuthProtocol,
    "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
}
_PRIV_PROTOCOLS = {
    "DES": usmDESPrivProtocol,
    "3DES": usm3DESEDEPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES128": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol,
    "AES256": usmAesCfb256Protocol,
}


class SnmpError(Exception):
    """采集失败。信息直接进 Device.last_error,所以要写得能看懂。"""


def _auth_data(device: Device):
    if device.snmp_version == SnmpVersion.V2C:
        # mpModel=1 是 v2c,0 是 v1。v1 不支持 GETBULK,48 口设备走 v1 会慢十倍
        return CommunityData(device.snmp_community, mpModel=1)

    level = device.snmp_v3_level or SnmpSecLevel.AUTH_PRIV
    auth_proto = _AUTH_PROTOCOLS.get((device.snmp_v3_auth_proto or "SHA").upper(), usmHMACSHAAuthProtocol)
    priv_proto = _PRIV_PROTOCOLS.get((device.snmp_v3_priv_proto or "AES").upper(), usmAesCfb128Protocol)

    if level == SnmpSecLevel.NO_AUTH:
        return UsmUserData(device.snmp_v3_user, authProtocol=usmNoAuthProtocol, privProtocol=usmNoPrivProtocol)
    if level == SnmpSecLevel.AUTH_ONLY:
        return UsmUserData(
            device.snmp_v3_user, authKey=device.snmp_v3_auth_key,
            authProtocol=auth_proto, privProtocol=usmNoPrivProtocol,
        )
    return UsmUserData(
        device.snmp_v3_user,
        authKey=device.snmp_v3_auth_key, privKey=device.snmp_v3_priv_key,
        authProtocol=auth_proto, privProtocol=priv_proto,
    )


def _to_python(value):
    """
    pysnmp 的值对象转 Python。

    noSuchObject / noSuchInstance / endOfMibView 都要变成 None —— 它们的
    str() 是那串字面量,直接塞进 float() 会抛异常,而"这台设备没这个 OID"
    是正常情况,不是错误。
    """
    name = value.__class__.__name__
    if name in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
        return None
    if hasattr(value, "prettyPrint"):
        text = value.prettyPrint()
        if text in ("No Such Object currently exists at this OID",
                    "No Such Instance currently exists at this OID", ""):
            return None
        return text
    return value


async def _agets(device: Device, oids: list[str]) -> dict[str, object]:
    """一次 GET 多个标量 OID。返回 {oid: 值},取不到的 OID 不出现在结果里。"""

    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create(
            (device.mgmt_ip, device.snmp_port),
            timeout=device.timeout_ms / 1000,
            retries=1,
        )
        err_ind, err_status, err_idx, var_binds = await get_cmd(
            engine, _auth_data(device), target, ContextData(),
            *[ObjectType(ObjectIdentity(o)) for o in oids],
        )
        if err_ind:
            raise SnmpError(f"SNMP 无响应: {err_ind}")
        if err_status:
            # 单个 OID 不存在会让整个 GET 报 noSuchName(v1)或返回 noSuchObject
            # (v2c)。v2c 走不到这里,这条主要是 v1 的兜底。
            raise SnmpError(f"SNMP 错误: {err_status.prettyPrint()} (第 {err_idx} 个 OID)")

        out = {}
        for oid, value in zip(oids, var_binds):
            converted = _to_python(value[1])
            if converted is not None:
                out[oid] = converted
        return out
    finally:
        engine.close_dispatcher()


async def _awalk(device: Device, oid_prefix: str, max_rows: int = 512) -> dict[str, object]:
    """
    GETBULK 遍历一列。返回 {索引后缀: 值}。

    max_rows 是护栏:采集器只会走已知的表(接口表、传感器表),但设备返回的
    表长度是它说了算的 —— 一台配置异常的设备能让 walk 跑几万行,把 worker
    占死。48 口交换机的接口表(含 VLAN、Port-channel)通常一两百行,512 够用。
    """

    engine = SnmpEngine()
    out: dict[str, object] = {}
    try:
        target = await UdpTransportTarget.create(
            (device.mgmt_ip, device.snmp_port),
            timeout=device.timeout_ms / 1000,
            retries=1,
        )
        # maxRepetitions=25:一次请求取 25 行。再大容易超过 UDP MTU 触发
        # tooBig 重传,反而更慢
        walker = bulk_walk_cmd(
            engine, _auth_data(device), target, ContextData(),
            0, 25, ObjectType(ObjectIdentity(oid_prefix)),
            lexicographicMode=False,  # 走出这一列就停,否则会一路走到 MIB 尽头
        )
        async for err_ind, err_status, _err_idx, var_binds in walker:
            if err_ind:
                raise SnmpError(f"SNMP walk 无响应: {err_ind}")
            if err_status:
                raise SnmpError(f"SNMP walk 错误: {err_status.prettyPrint()}")
            for oid, value in var_binds:
                oid_text = str(oid)
                if not oid_text.startswith(oid_prefix):
                    return out
                converted = _to_python(value)
                if converted is not None:
                    out[oid_text[len(oid_prefix) + 1:]] = converted
            if len(out) >= max_rows:
                log.warning("设备 %s 的 %s 表超过 %d 行,已截断", device.name, oid_prefix, max_rows)
                break
        return out
    finally:
        engine.close_dispatcher()


# ---------------------------------------------------------------- 同步入口

def snmp_get(device: Device, oids: list[str]) -> dict[str, object]:
    return asyncio.run(_agets(device, oids))


def snmp_walk(device: Device, oid_prefix: str, max_rows: int = 512) -> dict[str, object]:
    return asyncio.run(_awalk(device, oid_prefix, max_rows))


def snmp_walk_many(device: Device, oid_prefixes: dict[str, str], max_rows: int = 512) -> dict[str, dict]:
    """
    并发走多列。48 口设备要走十几列,串行的话一次采集要几十秒。

    并发度压在 6:交换机的 SNMP agent 是单线程的,并发太高它自己会丢包,
    表现成随机的超时(而且是间歇性的,最难查的那种)。
    """

    async def _run():
        engine_limit = asyncio.Semaphore(6)

        async def one(name: str, prefix: str):
            async with engine_limit:
                try:
                    return name, await _awalk(device, prefix, max_rows)
                except SnmpError as exc:
                    log.debug("设备 %s 列 %s 采集失败: %s", device.name, name, exc)
                    return name, {}

        results = await asyncio.gather(*[one(n, p) for n, p in oid_prefixes.items()])
        return dict(results)

    return asyncio.run(_run())


def test_connection(device: Device) -> tuple[bool, str]:
    """配置中心「测试连通性」:只取 sysDescr,不采指标。"""

    started = time.perf_counter()
    try:
        result = snmp_get(device, ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"])
    except SnmpError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"

    elapsed = int((time.perf_counter() - started) * 1000)
    descr = str(result.get("1.3.6.1.2.1.1.1.0", ""))[:160]
    name = result.get("1.3.6.1.2.1.1.5.0", "?")
    if not descr:
        return False, "SNMP 有响应但读不到 sysDescr,检查 community 的 view 是否限制了 OID 范围"
    return True, f"{name} / {descr} ({elapsed}ms)"
