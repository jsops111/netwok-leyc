"""
FortiGate REST API 采集通道(FortiOS 7.x)。

为什么 FortiGate 要单独一条通道:SNMP 的 fgSysSesCount 只给一个总数,
而防火墙上真正要看的东西 —— 每个 VDOM 的会话分布、HA 成员各自的状态、
策略命中计数、License 和特征库到期 —— SNMP 全拿不到。这些恰好是防火墙
出事时第一批要看的指标。

认证用 REST API 管理员的 token(系统 → 管理员 → 新建 REST API 管理员),
放在 Authorization: Bearer 头里。**不要用 access_token URL 参数那种写法**:
它会进 FortiGate 自己的 HTTP 访问日志,等于把 token 明文记在设备上。

多 VDOM:所有请求带 vdom= 参数。设备配的是 root 就查 root。
"""

from __future__ import annotations

import logging
import time

import requests

from netcheck.models import Device

log = logging.getLogger("netcheck.fortigate")


class FortiApiError(Exception):
    pass


def _base_url(device: Device) -> str:
    scheme = device.api_scheme or "https"
    port = device.api_port or (443 if scheme == "https" else 80)
    netloc = device.mgmt_ip if port in (80, 443) else f"{device.mgmt_ip}:{port}"
    return f"{scheme}://{netloc}/api/v2"


def _request(device: Device, path: str, params: dict | None = None) -> dict:
    url = f"{_base_url(device)}{path}"
    query = {"vdom": device.api_vdom or "root"}
    if params:
        query.update(params)

    try:
        resp = requests.get(
            url,
            params=query,
            headers={"Authorization": f"Bearer {device.api_token}", "Accept": "application/json"},
            timeout=device.timeout_ms / 1000,
            verify=device.api_verify_tls,
        )
    except requests.Timeout as exc:
        raise FortiApiError(f"API 超时(>{device.timeout_ms}ms): {path}") from exc
    except requests.RequestException as exc:
        raise FortiApiError(f"API 请求失败: {str(exc)[:160]}") from exc

    if resp.status_code == 401:
        raise FortiApiError("API Token 无效或已过期(401)")
    if resp.status_code == 403:
        # 最常见的部署问题:REST API 管理员的可信主机没放行本机 IP,
        # 或者 profile 没给 monitor 读权限。直接把方向写出来。
        raise FortiApiError("API 拒绝访问(403),检查 REST API 管理员的可信主机和权限 profile")
    if resp.status_code == 404:
        # 不同 FortiOS 版本 monitor 端点会挪位置,404 不该让整次采集失败
        raise FortiApiError(f"端点不存在(404): {path},可能是 FortiOS 版本差异")
    if resp.status_code >= 400:
        raise FortiApiError(f"HTTP {resp.status_code}: {resp.text[:160]}")

    try:
        return resp.json()
    except ValueError as exc:
        raise FortiApiError(f"响应不是 JSON: {resp.text[:120]}") from exc


def _safe(device: Device, path: str, params: dict | None = None) -> dict | None:
    """
    可选端点的包装:失败返回 None 而不抛。

    版本差异导致某个端点不存在时,**其它指标应该照采** —— 一台 7.0 的设备
    不该因为少一个 7.4 才有的端点就整台采集失败。
    """
    try:
        return _request(device, path, params)
    except FortiApiError as exc:
        log.debug("设备 %s 可选端点 %s 跳过: %s", device.name, path, exc)
        return None


def collect(device: Device) -> dict:
    """
    采一轮。返回的键对应 DeviceSample 的列名,采不到的键不出现。

    system/status 是唯一的**必需**端点:它拿不到就说明 token 或网络有问题,
    没必要继续试其它端点。其余全部走 _safe。
    """

    started = time.perf_counter()
    out: dict = {"extra": {}}

    status = _request(device, "/monitor/system/status")
    results = status.get("results", status) or {}
    version = status.get("version") or results.get("version") or ""
    serial = status.get("serial") or results.get("serial") or ""
    if version:
        out["os_version"] = version
    if serial:
        out["serial"] = serial
    if hostname := results.get("hostname"):
        out["extra"]["hostname"] = hostname

    # ---- CPU / 内存 / 会话 ----
    # resource/usage 一次可以要多个 resource,但不同小版本对多值的支持不一致,
    # 分开要更稳
    for resource, field in (("cpu", "cpu_pct"), ("memory", "mem_pct"), ("session", "session_count")):
        data = _safe(device, "/monitor/system/resource/usage", {"resource": resource, "interval": "1-min"})
        if not data:
            continue
        value = _extract_usage(data)
        if value is not None:
            out[field] = value

    if uptime := _safe(device, "/monitor/system/time"):
        # FortiOS 的 system/time 不带 uptime,uptime 在 status 的 results 里
        out["extra"]["device_time"] = (uptime.get("results") or {}).get("time")
    if isinstance(results.get("log_disk_status"), str):
        out["extra"]["log_disk"] = results["log_disk_status"]

    # ---- HA ----
    if ha := _safe(device, "/monitor/system/ha-statistics"):
        members = ha.get("results") or []
        if isinstance(members, list) and members:
            me = next((m for m in members if m.get("is_manage_master") or m.get("is_root_master")), members[0])
            role = "master" if (me.get("is_manage_master") or me.get("is_root_master")) else "slave"
            out["ha_state"] = f"{role}({len(members)} 成员)"
            out["extra"]["ha_members"] = [
                {"hostname": m.get("hostname"), "serial": m.get("serial_no"),
                 "cpu": m.get("cpu_usage"), "mem": m.get("mem_usage"), "sessions": m.get("session_count")}
                for m in members[:8]
            ]
            # HA 成员的会话数之和比全局值更准 —— 主备模式下全局值只算主
            if out.get("session_count") is None:
                total = sum(m.get("session_count") or 0 for m in members)
                if total:
                    out["session_count"] = total

    # ---- VPN ----
    if vpn := _safe(device, "/monitor/vpn/ipsec"):
        tunnels = vpn.get("results") or []
        if isinstance(tunnels, list):
            up = sum(
                1 for t in tunnels
                for proxy in (t.get("proxyid") or [{}])
                if (proxy.get("status") or t.get("status")) == "up"
            )
            out["vpn_tunnels_up"] = up
            out["extra"]["vpn_tunnels_total"] = len(tunnels)

    # ---- 温度 / 硬件传感器 ----
    if sensors := _safe(device, "/monitor/system/sensor-info"):
        temps = [
            s.get("value") for s in (sensors.get("results") or [])
            if isinstance(s, dict) and (s.get("unit") == "C" or "temp" in str(s.get("name", "")).lower())
            and isinstance(s.get("value"), (int, float))
        ]
        if temps:
            # 取最高的那个传感器 —— 平均值会把一个过热的部件藏起来
            out["temp_c"] = float(max(temps))
        alarms = [s.get("name") for s in (sensors.get("results") or [])
                  if isinstance(s, dict) and s.get("alarm")]
        if alarms:
            out["extra"]["sensor_alarms"] = alarms[:10]

    # ---- License / 特征库到期(这是 SNMP 完全拿不到的一类) ----
    if lic := _safe(device, "/monitor/license/status"):
        entries = lic.get("results") or {}
        if isinstance(entries, dict):
            expiring = {
                name: info.get("expires")
                for name, info in entries.items()
                if isinstance(info, dict) and info.get("expires")
            }
            if expiring:
                out["extra"]["license_expiry"] = expiring

    out["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return out


def _extract_usage(data: dict):
    """
    resource/usage 的响应形状在小版本间有出入:
        {"results": {"cpu": [{"current": 12}]}}      7.2/7.4
        {"results": [{"current": 12}]}               7.0
        {"results": {"current": 12}}                 某些补丁版
    三种都要认 —— 只认一种的话升级固件之后指标会静默变空。
    """
    results = data.get("results")
    candidates = []
    if isinstance(results, dict):
        for value in results.values():
            candidates.append(value)
        if "current" in results:
            candidates.append(results)
    elif isinstance(results, list):
        candidates.extend(results)

    for item in candidates:
        if isinstance(item, list) and item:
            item = item[-1]
        if isinstance(item, dict) and isinstance(item.get("current"), (int, float)):
            return float(item["current"])
        if isinstance(item, (int, float)):
            return float(item)
    return None


def collect_interfaces(device: Device) -> list[dict]:
    """
    接口清单与流量。返回的每项形如
    {"if_name","if_alias","oper_up","admin_up","speed_bps","in_octets","out_octets", ...}

    if_index 走 API 拿不到,所以用**接口名的稳定哈希**当索引 —— DeviceInterface
    的唯一键是 (device, if_index),API 通道下它只是个内部标识,不参与展示。
    这样同一台设备在 API 和 SNMP 通道之间切换时不会产生两套重复接口,
    前提是接口名一致(FortiGate 上是一致的)。
    """

    data = _safe(device, "/monitor/system/interface", {"scope": "global", "include_vlan": "true"})
    if not data:
        return []

    results = data.get("results") or {}
    items = results.values() if isinstance(results, dict) else results
    out: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("id")
        if not name:
            continue
        speed_mbps = item.get("speed")
        out.append({
            "if_index": _stable_index(str(name)),
            "if_name": str(name),
            "if_alias": str(item.get("alias") or ""),
            "if_type": str(item.get("type") or ""),
            "mac": str(item.get("mac") or ""),
            "admin_up": item.get("link") is not None,
            "oper_up": bool(item.get("link")),
            "speed_bps": int(float(speed_mbps) * 1_000_000) if isinstance(speed_mbps, (int, float)) else None,
            "in_octets": item.get("rx_bytes"),
            "out_octets": item.get("tx_bytes"),
            "in_errors": item.get("rx_errors"),
            "out_errors": item.get("tx_errors"),
            "in_discards": item.get("rx_dropped"),
            "out_discards": item.get("tx_dropped"),
        })
    return out


def _stable_index(name: str) -> int:
    """
    接口名 → 稳定的正整数。用 CRC32 而不是 hash():Python 的 hash() 对 str
    带进程级随机盐,重启之后同一个接口名会算出不同的值,于是每次重启都新增
    一套接口记录。
    """
    import zlib

    return zlib.crc32(name.encode()) & 0x7FFFFFFF


def test_connection(device: Device) -> tuple[bool, str]:
    started = time.perf_counter()
    try:
        status = _request(device, "/monitor/system/status")
    except FortiApiError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"

    results = status.get("results", {}) or {}
    version = status.get("version") or results.get("version") or "?"
    hostname = results.get("hostname") or "?"
    elapsed = int((time.perf_counter() - started) * 1000)
    return True, f"{hostname} FortiOS {version} ({elapsed}ms)"
