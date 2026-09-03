"""
Redfish JSON → 平台自己的部件模型。**纯函数,不碰网络也不碰库。**

## 三条贯穿全文件的规矩

1. **`unknown` 不是 `ok`。**Dell 的 Redfish 在部件刚插上、固件在升级、
   或者账号权限不够时都会给 `Status.Health = null`。把它算成正常等于替
   这台机器做一个我们没验证过的保证 —— 而带外监控存在的全部理由就是
   "在操作系统看不出问题的时候告诉你哪里要坏了"。所以 `bad` 和 `unknown`
   在计数上是**两栏**,页面上是**两种颜色**。

2. **「剩余写入寿命 0」要分清是机械盘不适用还是 SSD 写光了。**
   `PredictedMediaLifeLeftPercent` 在 HDD 上返回 0 或 null 是正常的 ——
   机械盘根本没有这个概念。不 join `MediaType` 就下结论的话,一台插满
   机械盘的机器会报出一排"SSD 寿命耗尽"。

3. **硬件事件日志(SEL)不会自动清。**一台机器上留着几年前的记录很正常,
   直接数"多少条 critical"会得到一个永远不变的大数字 —— **一条永远都在
   的红等于没有红**。所以按时间窗过滤,窗口是每台机器自己配的。

## 判据是平台自己的,不照抄 iDRAC 的 status 位

iDRAC 的温度严重阈值通常在 100 ℃ 上下(那是 CPU 的绝对上限)。所以一颗
散热出了问题、比同机另一颗高 20 ℃ 的 CPU 在它眼里仍然是"正常"。
`temp_delta()` 那条同机温差判据是这里自己算的 —— 它比绝对值更早发现问题,
而且能把"机房热"和"这一颗坏了"分开(进风温度高 = 机房热)。
"""

from __future__ import annotations

import re
from datetime import datetime, timezone as dt_timezone

# Redfish 的 Status.Health 取值 → 平台的档位。
# **`None` / 缺失 / 认不出的一律 unknown,不落到 ok。**
_HEALTH = {
    "ok": "ok",
    "warning": "warning",
    "critical": "critical",
}


def health_of(node) -> str:
    """
    从任意一个带 `Status` 的 Redfish 对象里取健康档位。

    找不到时返回 `"unknown"` —— **不是 `"ok"`**。这是这个文件里最重要的
    一行:一个"读不到状态"的部件被显示成绿色,就等于这套带外监控在它最该
    说话的时候闭嘴了。
    """

    if not isinstance(node, dict):
        return "unknown"
    status = node.get("Status")
    if not isinstance(status, dict):
        return "unknown"
    raw = status.get("Health") or status.get("HealthRollup")
    return _HEALTH.get(str(raw).strip().lower(), "unknown")


def _enabled(node) -> bool:
    """
    这个部件插着吗。Redfish 用 `Status.State`:`Absent` = 槽位是空的。

    **空槽位不算部件** —— 一台 24 槽的机器插了 8 条内存,把另外 16 个空槽
    当成"状态未知的内存条"会让"未知"这一栏永远是个大数字,而那一栏本来是
    要引起注意的。
    """

    if not isinstance(node, dict):
        return False
    state = str(((node.get("Status") or {}).get("State")) or "").strip().lower()
    return state not in ("absent", "disabled")


def _num(value):
    """数字字段。**取不到返回 None,不返回 0** —— 0 是一个有含义的读数。"""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _members(node) -> list:
    """
    Redfish 集合里的成员。`$expand` 成功时是完整对象,失败时只有
    `{"@odata.id": "..."}` 那种引用 —— **引用要丢掉**,它里面什么都没有,
    留着会变成一堆"状态未知"的幽灵部件。
    """

    if not isinstance(node, dict):
        return []
    out = []
    for item in node.get("Members") or []:
        if isinstance(item, dict) and len(item) > 1:
            out.append(item)
    return out


# ---------------------------------------------------------------- 整机


def parse_system(data: dict) -> dict:
    """`/redfish/v1/Systems/System.Embedded.1` → 型号、服务编号、整机健康。"""

    if not isinstance(data, dict):
        return {}
    memory_summary = data.get("MemorySummary") or {}
    processor_summary = data.get("ProcessorSummary") or {}
    return {
        "model_name": str(data.get("Model") or "")[:128],
        "manufacturer": str(data.get("Manufacturer") or "")[:64],
        # Dell 把服务编号放在 SKU 里;有些固件同时给 SerialNumber
        "service_tag": str(data.get("SKU") or data.get("SerialNumber") or "")[:64],
        "bios_version": str(data.get("BiosVersion") or "")[:64],
        "system_hostname": str(data.get("HostName") or "")[:128],
        "power_state": str(data.get("PowerState") or "")[:16],
        "health": health_of(data),
        "cpu_count": _num(processor_summary.get("Count")),
        "cpu_model": str(processor_summary.get("Model") or "")[:128],
        # GiB。**这是汇总值**,和逐条内存那张表是两个来源 —— $expand 不支持
        # 时逐条那张表是空的,而这个数还在
        "memory_total_gib": _num(memory_summary.get("TotalSystemMemoryGiB")),
        "memory_health": health_of(memory_summary),
    }


def parse_manager(data: dict) -> dict:
    """iDRAC 自己的固件版本。升级完固件之后某些字段会变形状,这个值是线索。"""

    if not isinstance(data, dict):
        return {}
    return {"idrac_firmware": str(data.get("FirmwareVersion") or "")[:64]}


# ---------------------------------------------------------------- 温度 / 风扇


def parse_thermal(data: dict) -> dict:
    """
    `/Chassis/.../Thermal` → 温度探头 + 风扇。

    温度探头里**要把进风温度单独挑出来**(名字里带 Inlet / Ambient):
    它是机房环境温度的最好代理。有了它才能回答"是机房热还是这台机器
    的散热坏了"—— 没有它,一排 60 ℃ 的读数说明不了任何事。

    `ReadingCelsius` 为 null 的探头**要留在列表里但值是 None**:
    iDRAC 在机器关机时给的就是 null,而"关机了所以没有温度"和
    "这个探头坏了"都是有信息量的,填成 0 会变成"0 ℃",看着像机房结冰。
    """

    if not isinstance(data, dict):
        return {"temps": [], "fans": []}

    temps = []
    for item in data.get("Temperatures") or []:
        if not isinstance(item, dict) or not _enabled(item):
            continue
        name = str(item.get("Name") or "").strip()
        temps.append({
            "name": name[:64],
            "celsius": _num(item.get("ReadingCelsius")),
            # iDRAC 自己的阈值。**带出来只为了展示**,判定用平台自己的线
            # (见模块开头)—— 这两个数在很多机型上是 100/105,拿它判等于
            # 只在已经要坏了的时候才知道
            "warn_c": _num(item.get("UpperThresholdNonCritical")),
            "crit_c": _num(item.get("UpperThresholdCritical")),
            "health": health_of(item),
            "is_inlet": bool(re.search(r"inlet|ambient|进风", name, re.I)),
            "is_exhaust": bool(re.search(r"exhaust|outlet|出风", name, re.I)),
        })

    fans = []
    for item in data.get("Fans") or []:
        if not isinstance(item, dict) or not _enabled(item):
            continue
        # 字段名在不同固件上是 Reading 或 ReadingRPM
        rpm = _num(item.get("Reading"))
        if rpm is None:
            rpm = _num(item.get("ReadingRPM"))
        units = str(item.get("ReadingUnits") or "").strip().lower()
        fans.append({
            "name": str(item.get("Name") or item.get("FanName") or "")[:64],
            "rpm": rpm,
            # 有些机型报的是百分比而不是转速。**单位要带出来** ——
            # 把 40(%)当成 40 RPM 会显示成"风扇快停了"
            "units": units or "rpm",
            "health": health_of(item),
        })

    return {"temps": temps, "fans": fans}


def temp_stats(temps: list[dict]) -> dict:
    """
    温度的三个数:最高、进风、**同机最大温差**。

    温差只在"同一类"的探头之间算才有意义,而这里只用 CPU 探头 ——
    进风和出风本来就该差十几度,把它们算进温差会让每一台机器都报警。
    CPU 探头的名字形如 `CPU1 Temp` / `CPU2 Temp`。

    **少于两个 CPU 探头时温差是 None,不是 0。**单路机器算不出温差,
    而 0 的含义是"两颗一样热",那是一个具体的、正面的结论。
    """

    readings = [t["celsius"] for t in temps if t["celsius"] is not None]
    inlet = next(
        (t["celsius"] for t in temps if t["is_inlet"] and t["celsius"] is not None), None
    )
    # ⚠ **不能写 `\bcpu\b`。**Dell 的探头叫 `CPU1 Temp` / `CPU2 Temp`,
    # "CPU" 和 "1" 之间没有单词边界(两边都是 \w),那个正则一条都匹配不到 ——
    # 于是温差永远算不出来,而"算不出来"和"两颗一样热"在页面上长得一样。
    # 实测踩出来的:加这条判据时它静默失效了
    cpu = [
        t["celsius"] for t in temps
        if t["celsius"] is not None and re.search(r"cpu|proc", t["name"], re.I)
    ]
    delta = round(max(cpu) - min(cpu), 1) if len(cpu) >= 2 else None
    return {
        "max_temp_c": max(readings) if readings else None,
        "inlet_temp_c": inlet,
        "temp_delta_c": delta,
        # 最热的那个探头点名 —— 只给一个数字的话人还得自己去表里找
        "hottest": max(
            (t for t in temps if t["celsius"] is not None),
            key=lambda t: t["celsius"], default={},
        ).get("name", ""),
    }


# ---------------------------------------------------------------- 电源


def parse_power(data: dict) -> dict:
    """`/Chassis/.../Power` → 整机功耗 + 每个电源模块。"""

    if not isinstance(data, dict):
        return {"watts": None, "psus": []}

    watts = None
    for control in data.get("PowerControl") or []:
        if isinstance(control, dict):
            watts = _num(control.get("PowerConsumedWatts"))
            if watts is not None:
                break

    psus = []
    for item in data.get("PowerSupplies") or []:
        if not isinstance(item, dict) or not _enabled(item):
            continue
        psus.append({
            "name": str(item.get("Name") or "")[:64],
            "health": health_of(item),
            "capacity_w": _num(item.get("PowerCapacityWatts")),
            # 输入电压 0 = **这个电源没接电**(线掉了 / 那一路市电断了)。
            # 冗余电源坏一个机器照样跑,操作系统里一点症状都没有 ——
            # 这正是带外监控最典型的用武之地
            "input_voltage": _num(item.get("LineInputVoltage")),
            "model": str(item.get("Model") or "")[:64],
        })
    return {"watts": watts, "psus": psus}


# ---------------------------------------------------------------- 内存


def parse_memory(data: dict) -> list[dict]:
    """
    `/Systems/.../Memory?$expand=...` → 每条内存。

    **`$expand` 不支持时这里是空的**(见 `_members()`),那时候内存只剩
    `parse_system()` 里那个汇总健康值。空列表和"这台机器没有内存"当然不是
    一回事 —— 调用方要把这个区别带到页面上。
    """

    out = []
    for item in _members(data):
        if not _enabled(item):
            continue                              # 空槽位不算部件
        out.append({
            "name": str(item.get("Name") or item.get("DeviceLocator") or "")[:64],
            "health": health_of(item),
            "size_mib": _num(item.get("CapacityMiB")),
            "speed_mhz": _num(item.get("OperatingSpeedMhz")),
            "manufacturer": str(item.get("Manufacturer") or "")[:32],
            "serial": str(item.get("SerialNumber") or "")[:32],
        })
    return out


# ---------------------------------------------------------------- 存储


def parse_storage(data: dict) -> dict:
    """
    `/Systems/.../Storage?$expand=...` → 物理盘 + RAID 卷。

    两个 Dell 特有的坑:

    1. **`PredictedMediaLifeLeftPercent` 只对 SSD 有意义。**机械盘上它返回
       0 或 null 都是正常的 —— 那不是"寿命耗尽",是"没有这个概念"。
       所以这里只在 `MediaType` 是 SSD 时才带出 `life_pct`,HDD 一律 None。
    2. **`FailurePredicted`(SMART 预警)是最有价值的一位**:它是"这块盘
       还在正常工作,但快要坏了"。等到 `Health` 变红时盘通常已经掉了。
    """

    disks, volumes = [], []
    for controller in _members(data):
        for drive in controller.get("Drives") or []:
            if not isinstance(drive, dict) or len(drive) <= 1:
                continue
            media = str(drive.get("MediaType") or "").strip().upper()
            is_ssd = "SSD" in media or "FLASH" in media
            life = _num(drive.get("PredictedMediaLifeLeftPercent"))
            disks.append({
                "name": str(drive.get("Name") or drive.get("Id") or "")[:96],
                "health": health_of(drive),
                "media": media or "UNKNOWN",
                "capacity_gb": round(_num(drive.get("CapacityBytes")) / 1e9, 1)
                                if _num(drive.get("CapacityBytes")) else None,
                "model": str(drive.get("Model") or "")[:64],
                "serial": str(drive.get("SerialNumber") or "")[:32],
                # SMART 预警:还在跑,但快坏了。**这是最该报的一位**
                "smart_alert": bool(drive.get("FailurePredicted")),
                # **HDD 一律 None** —— 见上面第 1 条
                "life_pct": life if is_ssd else None,
                "is_ssd": is_ssd,
                "slot": str(drive.get("PhysicalLocation", {}).get("PartLocation", {})
                            .get("ServiceLabel") or "")[:64],
            })

        for volume in _members(controller.get("Volumes") or {}):
            volumes.append({
                "name": str(volume.get("Name") or volume.get("Id") or "")[:96],
                "health": health_of(volume),
                "raid_type": str(volume.get("RAIDType") or volume.get("VolumeType") or "")[:32],
                "capacity_gb": round(_num(volume.get("CapacityBytes")) / 1e9, 1)
                                if _num(volume.get("CapacityBytes")) else None,
                # 0 = **再坏一块盘这个卷就没了**。这是个能直接行动的数字
                "remaining_redundancy": _num(volume.get("Oem", {}).get("Dell", {})
                                             .get("DellVirtualDisk", {})
                                             .get("RemainingRedundancy")),
            })
    return {"disks": disks, "volumes": volumes}


# ---------------------------------------------------------------- 硬件日志


_SEL_SEVERITY = {"ok": "ok", "warning": "warning", "critical": "critical"}


def parse_sel(data: dict, window_days: int, now: datetime | None = None) -> dict:
    """
    硬件事件日志(SEL)。**按时间窗过滤是这个函数存在的理由。**

    SEL 不会自动清 —— 一台跑了七年的机器上留着 2019 年的记录很正常。
    直接数"多少条 critical"会得到一个永远不变的大数字,而**一条永远都在
    的红等于没有红**:人看两次就不看了,真出事的那条就淹在里面。

    时间解析不出来的条目**保留但排在最后**,并且**不计入窗口内的计数** ——
    我们不知道它是什么时候的,不能替它决定算不算数。
    """

    now = now or datetime.now(dt_timezone.utc)
    cutoff = now.timestamp() - window_days * 86400

    entries, recent_warn, recent_crit, undated = [], 0, 0, 0
    for item in (data or {}).get("Members") or []:
        if not isinstance(item, dict):
            continue
        severity = _SEL_SEVERITY.get(
            str(item.get("Severity") or "").strip().lower(), "unknown"
        )
        created = item.get("Created")
        ts = None
        if created:
            try:
                # Redfish 用 ISO 8601,带 Z 或 +08:00。Python 3.11+ 的
                # fromisoformat 认 Z,更早的不认 —— 这里显式换掉
                ts = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=dt_timezone.utc)
            except (ValueError, TypeError):
                ts = None

        in_window = ts is not None and ts.timestamp() >= cutoff
        if ts is None:
            undated += 1
        elif in_window:
            if severity == "critical":
                recent_crit += 1
            elif severity == "warning":
                recent_warn += 1

        entries.append({
            "id": str(item.get("Id") or "")[:32],
            "severity": severity,
            "message": str(item.get("Message") or "")[:300],
            "at": ts.isoformat() if ts else None,
            "in_window": in_window,
        })

    # 有时间的排前面(新的在最上),没时间的垫底 —— 它们仍然要显示,
    # 只是我们说不出是什么时候的事
    entries.sort(key=lambda e: (e["at"] is None, e["at"] or ""), reverse=False)
    entries = sorted(entries, key=lambda e: (e["at"] is None, -(0 if e["at"] is None else 1)))
    dated = sorted([e for e in entries if e["at"]], key=lambda e: e["at"], reverse=True)
    undated_entries = [e for e in entries if not e["at"]]

    return {
        "entries": (dated + undated_entries)[:50],
        "total": len(entries),
        "window_days": window_days,
        "recent_critical": recent_crit,
        "recent_warning": recent_warn,
        # 时间解不出来的条数。**单独报** —— 它是"这个数可能不全"的说明
        "undated": undated,
    }


# ---------------------------------------------------------------- 汇总


def count_states(items: list[dict]) -> tuple[int, int, int]:
    """
    (总数, 异常数, 未知数)。

    **未知单独一栏,不并进任何一边** —— 并进 bad 会天天误报,
    并进 ok 会在真出事时闭嘴。见模块开头第 1 条。
    """

    total = len(items)
    bad = sum(1 for i in items if i.get("health") in ("warning", "critical"))
    unknown = sum(1 for i in items if i.get("health") == "unknown")
    return total, bad, unknown
