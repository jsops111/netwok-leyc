"""
邻居发现(LLDP + CDP)—— 「这个口对面接的是谁」。

这是 `show lldp neighbors` / `show cdp neighbors` 的 SNMP 版本,也是网络
工程师排障时问的第一个问题:一个口 down 了对面是谁?一台机器失联了它挂在
哪台交换机的哪个口上?这个口能不能停?

## 两套都采,不是二选一

LLDP 是标准(802.1AB),CDP 是 Cisco 私有 —— 但纯 Cisco 环境里往往**只开了
CDP**。只采一套的结果是"有些口对面是空的",而那是最容易被当成"没接线"的
误读:实际上线接着,只是我们问错了协议。

## 索引解析是这个文件的全部难点

两套表的索引结构不一样,而**搞错索引的后果是把邻居挂到错误的口上** ——
一份错的拓扑比没有拓扑危险得多(照着它去停一个口,停错的是别人)。

    cdpCacheTable      索引 = ifIndex.cdpCacheDeviceIndex
                       → 第一段**就是** ifIndex,直接可用

    lldpRemTable       索引 = lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex
                       → 本地口是**第二段**,而且它是 lldpLocalPortNum,
                         **不保证等于 ifIndex**。标准没规定两者相等;
                         Cat9k 上通常相等,但有的平台是另一套从 1 开始的编号。
                         所以要靠 lldpLocPortId 表把它翻成口名,再和接口表对。

`lldpRemTimeMark` 是"这条邻居信息是什么时候学到的"的时间戳,它会变 ——
**不能拿整个索引当唯一键**,否则每次采集都会认为是一条新邻居。
"""

from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

from netcheck.models import Device, DeviceNeighbor

from . import snmp
from .profiles import CDP_CACHE, LLDP_LOC_PORT_DESC, LLDP_LOC_PORT_ID, LLDP_REM

log = logging.getLogger("netcheck.neighbors")

# 一台设备最多存多少条邻居。接了哑交换机的口可能学到几十个邻居,
# 而那种情况下逐条列出来没有意义(拓扑本来就不清晰)
MAX_NEIGHBORS = 400


def _text(value) -> str:
    if value is None:
        return ""
    return str(value).strip().strip("\x00")


def _hex_to_ipv4(value) -> str:
    """
    cdpCacheAddress 是字节串。IPv4 是 4 字节,pysnmp 取回来可能是
    `0x0a140001` 这种十六进制字符串,也可能是原始 bytes。

    **认不出来就返回空字符串**,不要硬转 —— 一个错的管理地址会让人
    去登录一台无关的设备。
    """

    if value is None:
        return ""
    if isinstance(value, bytes):
        data = value
    else:
        text = str(value).strip()
        if text.startswith("0x"):
            text = text[2:]
        # 形如 "10.20.0.1" 的直接用
        if text.count(".") == 3 and all(p.isdigit() for p in text.split(".")):
            return text
        try:
            data = bytes.fromhex(text)
        except ValueError:
            return ""
    if len(data) == 4:
        return ".".join(str(b) for b in data)
    return ""


def _first_line(text, limit: int = 200) -> str:
    """LLDP 的 sysDesc 是一整段版本信息,取第一行当"平台"就够展示。"""

    for line in _text(text).replace("\r", "\n").split("\n"):
        if line.strip():
            return line.strip()[:limit]
    return ""


# =========================================================================
# 采集
# =========================================================================


def _collect_cdp(device: Device) -> list[dict]:
    """CDP。索引第一段就是 ifIndex,所以不需要额外映射。"""

    tables = snmp.snmp_walk_many(device, dict(CDP_CACHE), max_rows=MAX_NEIGHBORS * 2)
    if not any(tables.values()):
        return []

    out: list[dict] = []
    for index, remote in (tables.get("cdpCacheDeviceId") or {}).items():
        if_index = index.split(".")[0]
        if not if_index.isdigit():
            continue
        out.append({
            "protocol": "cdp",
            "local_if_index": int(if_index),
            "remote_device": _text(remote)[:255],
            "remote_port": _text((tables.get("cdpCacheDevicePort") or {}).get(index))[:255],
            "remote_platform": _text((tables.get("cdpCachePlatform") or {}).get(index))[:255],
            "remote_mgmt_ip": _hex_to_ipv4((tables.get("cdpCacheAddress") or {}).get(index))[:64],
            "remote_chassis_id": "",
            "raw": {"index": index, "protocol": "cdp"},
        })
    return out


def _collect_lldp(device: Device) -> list[dict]:
    """
    LLDP。要先拿 lldpLocPortId 把 lldpLocalPortNum 翻成本地口名。

    **不假设 lldpLocalPortNum == ifIndex**(见模块开头)。翻不出名字时
    仍然把这条邻居收下,但 local_if_index 留空 —— 有邻居信息但不知道挂在
    哪个口,比整条丢掉有用,而且页面上能看出是"口名未知"。
    """

    columns = dict(LLDP_REM)
    columns["lldpLocPortId"] = LLDP_LOC_PORT_ID
    columns["lldpLocPortDesc"] = LLDP_LOC_PORT_DESC
    tables = snmp.snmp_walk_many(device, columns, max_rows=MAX_NEIGHBORS * 2)
    if not any(tables.get(k) for k in LLDP_REM):
        return []

    loc: dict[str, str] = {}
    for key in ("lldpLocPortId", "lldpLocPortDesc"):
        for index, value in (tables.get(key) or {}).items():
            port_num = index.split(".")[0]
            if port_num.isdigit() and _text(value):
                loc.setdefault(port_num, _text(value)[:128])

    out: list[dict] = []
    for index, sys_name in (tables.get("lldpRemSysName") or {}).items():
        parts = index.split(".")
        # timeMark.localPortNum.remIndex —— **本地口是第二段**
        if len(parts) < 3:
            continue
        port_num = parts[1]
        out.append({
            "protocol": "lldp",
            "local_port_num": int(port_num) if port_num.isdigit() else None,
            "local_if_name_hint": loc.get(port_num, ""),
            "remote_device": _text(sys_name)[:255],
            "remote_port": (
                _text((tables.get("lldpRemPortDesc") or {}).get(index))
                or _text((tables.get("lldpRemPortId") or {}).get(index))
            )[:255],
            "remote_platform": _first_line((tables.get("lldpRemSysDesc") or {}).get(index))[:255],
            "remote_mgmt_ip": "",
            "remote_chassis_id": _text((tables.get("lldpRemChassisId") or {}).get(index))[:128],
            "raw": {"index": index, "protocol": "lldp"},
        })
    return out


def _resolve_local(device: Device, rows: list[dict]) -> list[dict]:
    """
    把每条邻居落到一个具体的本地接口上。

    CDP 已经有 ifIndex,直接查名字。LLDP 只有 lldpLocalPortNum 和一个口名
    提示:**先按口名去接口表里找**(那是可靠的),找不到再退回"把 portNum
    当 ifIndex 试一下"—— 后者在多数平台上成立,试出来能对上就用,
    对不上就留空。

    留空而不是硬猜是有意的:**把邻居挂到错误的口上比不知道糟得多** ——
    照着一份错的拓扑去停一个口,停错的是别人。
    """

    by_index: dict[int, str] = {}
    by_name: dict[str, int] = {}
    for iface in device.interfaces.all().only("if_index", "if_name"):
        by_index[iface.if_index] = iface.if_name
        by_name[iface.if_name.strip().lower()] = iface.if_index

    resolved: list[dict] = []
    for raw_row in rows:
        row = dict(raw_row)
        if row["protocol"] == "cdp":
            row["local_if_name"] = (
                by_index.get(row["local_if_index"], "") or f"ifIndex {row['local_if_index']}"
            )
            resolved.append(row)
            continue

        hint = (row.pop("local_if_name_hint", "") or "").strip()
        port_num = row.pop("local_port_num", None)
        if hint and hint.lower() in by_name:
            row["local_if_name"] = hint[:128]
            row["local_if_index"] = by_name[hint.lower()]
        elif port_num is not None and port_num in by_index:
            row["local_if_name"] = by_index[port_num]
            row["local_if_index"] = port_num
        elif hint:
            # 有名字但接口表里没有(接口采集关掉了)—— 名字仍然可用
            row["local_if_name"] = hint[:128]
            row["local_if_index"] = None
        else:
            row["local_if_name"] = f"lldp 端口 {port_num}" if port_num is not None else "未知"
            row["local_if_index"] = None
        resolved.append(row)
    return resolved


def _match_managed(rows: list[dict], exclude_id: int) -> None:
    """
    对端如果也是这个平台在管的设备,关联过去 —— 这样能画出"受管链路"。

    匹配顺序:管理地址精确匹配 → 设备名精确匹配(不分大小写)→ 去掉域名
    后缀再匹配(交换机常把自己报成 `core-sw-01.example.com`)。
    **不做模糊匹配** —— 连错的链路比没有链路糟。
    """

    devices = list(Device.objects.exclude(pk=exclude_id).only("id", "name", "mgmt_ip"))
    by_ip = {d.mgmt_ip: d for d in devices}
    by_name = {d.name.strip().lower(): d for d in devices}

    for row in rows:
        match = None
        if row.get("remote_mgmt_ip"):
            match = by_ip.get(row["remote_mgmt_ip"])
        name = (row.get("remote_device") or "").strip().lower()
        if match is None and name:
            match = by_name.get(name) or by_name.get(name.split(".")[0])
        row["matched_device_id"] = match.pk if match else None


def collect_neighbors(device: Device) -> dict:
    """
    采一台设备的邻居并写库(全量替换 + 保留 first_seen)。

    返回里的 `changes` 是**对端变了或消失了**的那些 —— 通常意味着有人动了线,
    调用方会为它记一条瞬时事件。首次采集时 `first_run=True`,
    那时候"全是新增"不是变化。
    """

    rows: list[dict] = []
    counts = {"lldp": 0, "cdp": 0}
    for name, fn in (("lldp", _collect_lldp), ("cdp", _collect_cdp)):
        try:
            found = fn(device)
        except Exception as exc:  # noqa: BLE001 —— 一套采不到不影响另一套
            log.info("设备 %s 的 %s 邻居采集失败: %s", device.name, name.upper(), exc)
            continue
        counts[name] = len(found)
        rows.extend(found)

    if len(rows) > MAX_NEIGHBORS:
        log.warning("设备 %s 学到 %d 条邻居,超过上限 %d,已截断",
                    device.name, len(rows), MAX_NEIGHBORS)
        rows = rows[:MAX_NEIGHBORS]

    rows = _resolve_local(device, rows)
    _match_managed(rows, device.pk)

    now = timezone.now()
    added = removed = changed = 0
    changes: list[dict] = []

    with transaction.atomic():
        existing = {
            (n.protocol, n.local_if_name, n.remote_device, n.remote_port): n
            for n in DeviceNeighbor.objects.select_for_update().filter(device=device)
        }
        first_run = not existing
        seen: set = set()

        for row in rows:
            key = (row["protocol"], row["local_if_name"],
                   row["remote_device"], row["remote_port"])
            seen.add(key)
            current = existing.get(key)
            if current is None:
                # 同一个口上原来有别的邻居吗?有的话这是一次**变化**
                # (对面换人了),不只是新增
                previous = next(
                    (n for k, n in existing.items()
                     if k[0] == row["protocol"] and k[1] == row["local_if_name"]),
                    None,
                )
                DeviceNeighbor.objects.create(
                    device=device, first_seen=now, last_seen=now,
                    changed_at=now if previous is not None else None,
                    protocol=row["protocol"],
                    local_if_index=row.get("local_if_index"),
                    local_if_name=row["local_if_name"],
                    remote_device=row["remote_device"], remote_port=row["remote_port"],
                    remote_platform=row["remote_platform"],
                    remote_mgmt_ip=row["remote_mgmt_ip"],
                    remote_chassis_id=row["remote_chassis_id"],
                    matched_device_id=row.get("matched_device_id"),
                    raw=row.get("raw") or {},
                )
                added += 1
                if previous is not None and not first_run:
                    changed += 1
                    changes.append({
                        "local": row["local_if_name"],
                        "before": f"{previous.remote_device}/{previous.remote_port}",
                        "after": f"{row['remote_device']}/{row['remote_port']}",
                        "protocol": row["protocol"],
                    })
                continue

            fields = ["last_seen"]
            current.last_seen = now
            chassis_changed = False
            for attr in ("remote_platform", "remote_mgmt_ip", "remote_chassis_id"):
                if getattr(current, attr) != row[attr]:
                    if attr == "remote_chassis_id" and current.remote_chassis_id and row[attr]:
                        chassis_changed = True
                    setattr(current, attr, row[attr])
                    fields.append(attr)
            if current.matched_device_id != row.get("matched_device_id"):
                current.matched_device_id = row.get("matched_device_id")
                fields.append("matched_device")
            if current.local_if_index != row.get("local_if_index"):
                current.local_if_index = row.get("local_if_index")
                fields.append("local_if_index")
            # chassis id 变了 = **对面换了一台机器**(名字和口号可能一样,
            # 比如换上一台同型号同 hostname 的备机)—— 这是要说出来的
            if chassis_changed:
                current.changed_at = now
                fields.append("changed_at")
                changed += 1
                changes.append({
                    "local": row["local_if_name"],
                    "before": "对端 chassis id 变了(换了一台机器)",
                    "after": f"{row['remote_device']}/{row['remote_port']}",
                    "protocol": row["protocol"],
                })
            current.save(update_fields=list(dict.fromkeys(fields)))

        # 这一轮没看到的:邻居消失了(拔线、对端关机、对端关了 LLDP)。
        # **直接删**而不是留着标记"已消失":一份留着幽灵条目的拓扑会让人
        # 以为线还在。消失这件事由事件记录,不由这张表记
        stale = [n for k, n in existing.items() if k not in seen]
        if stale:
            for n in stale:
                changes.append({
                    "local": n.local_if_name,
                    "before": f"{n.remote_device}/{n.remote_port}",
                    "after": "(消失)",
                    "protocol": n.protocol,
                })
            removed = len(stale)
            DeviceNeighbor.objects.filter(pk__in=[n.pk for n in stale]).delete()

    return {
        "total": len(rows), "lldp": counts["lldp"], "cdp": counts["cdp"],
        "added": added, "removed": removed, "changed": changed,
        "first_run": first_run,
        "changes": changes[:20],
    }
