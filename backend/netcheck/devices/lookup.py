"""
按需查找:**「这个 MAC / 这个 IP 在哪台交换机的哪个口上」**。

这是交换机排障里问得最多的一句话:一台机器不通了,先要知道它插在哪儿;
一个 IP 冲突了,要知道两个 MAC 分别挂在哪个口。

## 为什么是「按需查」而不是「定时采集存库」

MAC 地址表是**大而易变**的:一台接入交换机几百到几千条,而且随时在老化和
重新学习。定时采集意味着:

  - 一台设备一次采几千行,几十台设备就是几十万行/次
  - 存下来的是一份**过期的**表 —— 而排障时要的恰恰是"现在在哪儿"
  - 这张表几乎从不被整体浏览,只被"查一个地址"用

所以这里是同步查询:输入一个 MAC 或 IP,现场去选中的设备上 walk 一遍。
一台设备 1~5 秒,所以接口是**显式选设备**的,不默认全网扫。

## 索引解析

    dot1dTpFdbPort        索引 = MAC 的 6 个十进制字节   → 桥端口号
    dot1qTpFdbPort        索引 = VLAN.MAC 的 6 个字节    → 桥端口号(带 VLAN)
    dot1dBasePortIfIndex  桥端口号 → ifIndex             ← **这一步不能省**
    ipNetToMediaPhysAddr  索引 = ifIndex.IPv4 四段       → MAC(ARP 表)

**桥端口号不是 ifIndex。**在多数 Cisco 平台上它们不相等,直接把桥端口号
当 ifIndex 用会指到一个完全无关的接口 —— 而那正是这个功能最不能出的错:
照着错的结果去拔线,拔的是别人的。
"""

from __future__ import annotations

import logging
import re

from netcheck.models import Device, DeviceInterface

from . import snmp

log = logging.getLogger("netcheck.lookup")

# BRIDGE-MIB / Q-BRIDGE-MIB
DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"      # dot1dTpFdbPort,索引 = MAC(6)
DOT1D_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"    # 3=learned 5=static
DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"  # dot1qTpFdbPort,索引 = VLAN.MAC(6)
DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # 桥端口号 → ifIndex
# IP-MIB 的 ARP 表(老的 at 表已废弃,这个是通用的)
IP_NET_TO_MEDIA_MAC = "1.3.6.1.2.1.4.22.1.2"   # 索引 = ifIndex.a.b.c.d

MAX_FDB_ROWS = 20000


class LookupError_(Exception):
    """查找失败(设备不可达、community 权限不够等)。"""


# =========================================================================
# 归一化
# =========================================================================

_MAC_CLEAN = re.compile(r"[^0-9a-fA-F]")
# **只有这几个字符算分隔符。**剥掉"任何非十六进制字符"是个陷阱:
# `aabbccddeeffgg` 会被剥成 12 位的 aabbccddeeff 而静默通过,
# 于是人拿着一个自己打错的 MAC 查到"不在网上",结论完全是假的
_MAC_SEPARATORS = re.compile(r"[\s:.\-]")


def normalize_mac(text: str) -> str:
    """
    各种写法的 MAC → `aabbccddeeff`(小写无分隔)。

    支持 `aa:bb:cc:dd:ee:ff` / `aa-bb-cc-dd-ee-ff` / `aabb.ccdd.eeff`
    (Cisco 风格)/ `AABBCCDDEEFF`。**认不出来抛异常**,不返回一个猜的值 ——
    拿一个猜错的 MAC 去查会得到"查不到",而人会以为那台机器不在网上。
    """

    stripped = _MAC_SEPARATORS.sub("", text or "")
    cleaned = stripped.lower()
    if len(cleaned) != 12 or _MAC_CLEAN.search(stripped):
        raise ValueError(
            f"认不出这个 MAC:{text!r} —— 支持 aa:bb:cc:dd:ee:ff、"
            "aa-bb-cc-dd-ee-ff、aabb.ccdd.eeff、aabbccddeeff"
        )
    return cleaned


def pretty_mac(mac12: str) -> str:
    return ":".join(mac12[i:i + 2] for i in range(0, 12, 2))


def mac_to_oid_suffix(mac12: str) -> str:
    """`aabbccddeeff` → `170.187.204.221.238.255`(FDB 表的索引形式)。"""

    return ".".join(str(int(mac12[i:i + 2], 16)) for i in range(0, 12, 2))


def oid_suffix_to_mac(suffix: str) -> str:
    """FDB 索引的最后 6 段 → `aabbccddeeff`。段数不对时返回空。"""

    parts = suffix.split(".")
    if len(parts) < 6:
        return ""
    try:
        return "".join(f"{int(p):02x}" for p in parts[-6:])
    except ValueError:
        return ""


def is_ipv4(text: str) -> bool:
    parts = (text or "").strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# =========================================================================
# 查询
# =========================================================================


def _bridge_port_map(device: Device) -> dict[str, int]:
    """
    桥端口号 → ifIndex。

    **这一步不能省。**桥端口号在多数 Cisco 平台上不等于 ifIndex,
    直接当 ifIndex 用会指到一个无关的接口。这张表取不到时,
    调用方要把结果标成"端口号未翻译",而不是假装它就是 ifIndex。
    """

    try:
        rows = snmp.snmp_walk(device, DOT1D_BASE_PORT_IFINDEX, max_rows=1024)
    except Exception as exc:  # noqa: BLE001
        log.info("设备 %s 取不到桥端口映射: %s", device.name, exc)
        return {}
    out: dict[str, int] = {}
    for index, value in rows.items():
        try:
            out[index.split(".")[-1]] = int(str(value).strip())
        except (ValueError, TypeError):
            continue
    return out


def _iface_names(device: Device) -> dict[int, str]:
    return {
        i.if_index: i.if_name
        for i in device.interfaces.all().only("if_index", "if_name")
    }


def find_mac_on_device(device: Device, mac12: str) -> list[dict]:
    """
    在一台设备上找一个 MAC。返回命中列表(一个 MAC 可能出现在多个 VLAN)。

    先查带 VLAN 的 Q-BRIDGE 表(信息更全),再查 dot1d 表。
    """

    suffix = mac_to_oid_suffix(mac12)
    bridge_map = _bridge_port_map(device)
    names = _iface_names(device)
    hits: list[dict] = []

    # ---- Q-BRIDGE:索引 = VLAN.MAC(6) ----
    try:
        q_rows = snmp.snmp_walk(device, DOT1Q_FDB_PORT, max_rows=MAX_FDB_ROWS)
    except Exception as exc:  # noqa: BLE001
        q_rows = {}
        log.debug("设备 %s 的 dot1q FDB 不可用: %s", device.name, exc)

    for index, value in q_rows.items():
        if not index.endswith(suffix):
            continue
        parts = index.split(".")
        vlan = parts[0] if len(parts) >= 7 else ""
        hits.append(_build_hit(device, value, bridge_map, names, vlan=vlan, source="dot1q"))

    # ---- dot1d:索引 = MAC(6),没有 VLAN ----
    if not hits:
        try:
            d_rows = snmp.snmp_walk(device, DOT1D_FDB_PORT, max_rows=MAX_FDB_ROWS)
        except Exception as exc:  # noqa: BLE001
            raise LookupError_(f"读不到 MAC 地址表:{exc}") from exc
        for index, value in d_rows.items():
            if index.endswith(suffix):
                hits.append(_build_hit(device, value, bridge_map, names, source="dot1d"))

    return hits


def _build_hit(device, port_value, bridge_map, names, vlan: str = "", source: str = "") -> dict:
    """把一条 FDB 记录翻成"在哪个口上"。"""

    bridge_port = str(port_value).strip()
    if_index = bridge_map.get(bridge_port)
    # 桥端口映射拿不到时**明确说出来**,不要把桥端口号当 ifIndex 报上去
    if_name = names.get(if_index, "") if if_index is not None else ""
    return {
        "device_id": device.pk,
        "device_name": device.name,
        "mgmt_ip": device.mgmt_ip,
        "vlan": vlan,
        "bridge_port": bridge_port,
        "if_index": if_index,
        "if_name": if_name or (f"ifIndex {if_index}" if if_index is not None else ""),
        "port_resolved": if_index is not None,
        "note": (
            "" if if_index is not None
            else "**桥端口号没能翻成 ifIndex**(dot1dBasePortIfIndex 读不到)—— "
                 f"这个 {bridge_port} 是桥端口号,不是接口号,不要照着它去拔线"
        ),
        "source": source,
    }


def find_ip_on_device(device: Device, ip: str) -> dict:
    """
    在一台设备上查一个 IP 的 ARP 记录 → 拿到 MAC。

    只有三层设备(路由器 / 防火墙 / 有 SVI 的交换机)才有这台机器的 ARP。
    拿到 MAC 之后再去二层设备上找口 —— 那是 `lookup()` 的两段式流程。
    """

    try:
        rows = snmp.snmp_walk(device, IP_NET_TO_MEDIA_MAC, max_rows=MAX_FDB_ROWS)
    except Exception as exc:  # noqa: BLE001
        raise LookupError_(f"读不到 ARP 表:{exc}") from exc

    names = _iface_names(device)
    for index, value in rows.items():
        parts = index.split(".")
        if len(parts) < 5:
            continue
        if ".".join(parts[-4:]) != ip:
            continue
        raw = value
        mac12 = ""
        if isinstance(raw, bytes):
            mac12 = raw.hex()
        else:
            text = str(raw).strip()
            # 这里剥的是 pysnmp 回来的值(可能是 `0x001122334455` 或
            # `1:2:3:4:5:6`),不是人手输的,所以宽松剥离是对的
            cleaned = _MAC_CLEAN.sub("", text)
            if len(cleaned) == 12:
                mac12 = cleaned.lower()
        if not mac12:
            continue
        try:
            if_index = int(parts[0])
        except ValueError:
            if_index = None
        return {
            "device_id": device.pk, "device_name": device.name,
            "if_index": if_index,
            "if_name": names.get(if_index, "") if if_index is not None else "",
            "mac": pretty_mac(mac12), "mac12": mac12,
        }
    return {}


def lookup(query: str, devices: list[Device]) -> dict:
    """
    统一入口。`query` 是 MAC 或 IPv4。

    IP 的流程是**两段式**:先在选中的设备里找 ARP 记录拿到 MAC
    (只有三层设备有),再拿这个 MAC 去所有选中的设备上找口。
    直接拿 IP 去交换机上找是找不到的 —— 二层表里只有 MAC。

    返回里的 `errors` 是**逐台**的失败原因,不是整体失败:一台设备
    community 配错了不该让整次查询没有结果。
    """

    query = (query or "").strip()
    result: dict = {
        "query": query, "kind": "", "mac": "", "arp": [],
        "hits": [], "errors": [], "searched": len(devices),
    }
    if not query:
        raise ValueError("要查什么?填一个 MAC 或 IP")
    if not devices:
        raise ValueError("至少选一台设备 —— 这是现场去设备上查,不是查本地缓存")

    if is_ipv4(query):
        result["kind"] = "ip"
        for device in devices:
            try:
                arp = find_ip_on_device(device, query)
            except LookupError_ as exc:
                result["errors"].append({"device": device.name, "error": str(exc)})
                continue
            except Exception as exc:  # noqa: BLE001
                result["errors"].append({"device": device.name,
                                         "error": f"{type(exc).__name__}: {exc}"})
                continue
            if arp:
                result["arp"].append(arp)
        if not result["arp"]:
            result["detail"] = (
                "选中的设备里没有这个 IP 的 ARP 记录。ARP 只在三层设备上"
                "(路由器 / 防火墙 / 有 SVI 的交换机)—— 把网关那台选上再查"
            )
            return result
        mac12 = result["arp"][0]["mac12"]
        result["mac"] = pretty_mac(mac12)
    else:
        result["kind"] = "mac"
        mac12 = normalize_mac(query)
        result["mac"] = pretty_mac(mac12)

    for device in devices:
        try:
            result["hits"].extend(find_mac_on_device(device, mac12))
        except LookupError_ as exc:
            result["errors"].append({"device": device.name, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            result["errors"].append({"device": device.name,
                                     "error": f"{type(exc).__name__}: {exc}"})

    if not result["hits"] and "detail" not in result:
        result["detail"] = (
            f"{result['mac']} 不在选中设备的 MAC 表里。可能是:这台机器已经离线"
            "(MAC 老化掉了,默认 5 分钟)、它挂在别的交换机上、"
            "或者 community 的 view 没放开 BRIDGE-MIB"
        )

    # 一个 MAC 出现在多个口上时:**上行口也会学到它**。
    # 所以"接入口"通常是那个只学到少量 MAC 的口 —— 这一点提示给使用者,
    # 不替他判断(判断要再 walk 一遍全表数每个口的 MAC 数,代价太大)
    if len({(h["device_id"], h["if_name"]) for h in result["hits"]}) > 1:
        result["multi_note"] = (
            "多个口都学到了这个 MAC —— **上行口也会学到**。"
            "真正的接入口通常是级联关系里最下游的那个,"
            "对照「设备邻居」页看哪个口是上行口"
        )
    return result
