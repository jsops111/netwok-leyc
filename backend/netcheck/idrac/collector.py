"""
带外采集的入口:Redfish 拉一遍 → 判阈值 → 写样本 → 开/关事件。

和 `servers/collector.py`、`devices/collector.py` 是同一套骨架,
**没有通道降级** —— 带外只有 Redfish 一条路。

## 这里的判定和 iDRAC 自己的判定是两回事

`evaluate_idrac()` 是**唯一的带外阈值判定处**(和 `probes/runner.evaluate()`、
`servers/collector.evaluate_server()` 同一个定位)。它**不照抄 iDRAC 的
status 位**:

- iDRAC 的温度严重线通常是 100 ℃ 上下(CPU 的绝对上限),所以一颗散热
  出了问题、比同机另一颗高 20 ℃ 的 CPU 在它眼里是"正常"的。
  这里的 `temp_delta_warn_c` 就是为这种情况准备的 —— 而且它能把
  "机房热"和"这一颗坏了"分开(进风温度高 = 机房热)。
- SMART 预警(`FailurePredicted`)在 iDRAC 的整机健康里通常只是 warning,
  但"这块盘还在跑、但快坏了"恰恰是最该立刻处理的一条。

## 三条和别处一致、不能改回去的规则

1. **`unknown` 不是 `ok`。**读不到状态的部件单独计数、单独显示。
   把它算成正常等于替这台机器做一个我们没验证过的保证。
2. **算不出来的指标留 None,不填 0。**单路机器算不出同机温差、
   机械盘没有剩余寿命 —— 这两处填 0 都会造出假结论。
3. **失败也写一行样本。**`reachable=False` 的那些行是带外可用率的分母。
"""

from __future__ import annotations

import logging
import time

from django.utils import timezone

from netcheck.events import engine as event_engine
from netcheck.models import (
    EventKind,
    HwState,
    IdracHost,
    IdracSample,
    LinkState,
    Severity,
)

from . import parse, redfish

log = logging.getLogger("netcheck.idrac")


class IdracError(Exception):
    """带外采不到。只有一条通道,所以这个异常等价于"这台带外没通"。"""


# =========================================================================
# 采集
# =========================================================================


def _collect_raw(host: IdracHost) -> dict:
    """连上去拉一遍,解析成一个扁平 dict。**不写库、不开事件。**"""

    started = time.perf_counter()
    timeout = host.timeout_ms / 1000
    try:
        raw = redfish.fetch_all(
            host.host, host.port, host.username, host.password,
            host.verify_tls, timeout, with_events=host.collect_events,
        )
    except redfish.RedfishError as exc:
        raise IdracError(str(exc)) from exc

    out: dict = {"extra": {}}
    if raw.get("_errors"):
        # 哪一段没取到、为什么。**页面上"内存那栏为什么是空的"只有它答得了**
        out["extra"]["endpoint_errors"] = raw["_errors"]

    # ---- 整机 ----
    system = parse.parse_system(raw.get("system") or {})
    out.update({k: system[k] for k in (
        "model_name", "manufacturer", "service_tag", "bios_version",
        "system_hostname", "power_state",
    ) if system.get(k)})
    out["health"] = system.get("health", HwState.UNKNOWN)
    out.update(parse.parse_manager(raw.get("manager") or {}))
    for key in ("cpu_count", "cpu_model", "memory_total_gib"):
        if system.get(key) is not None:
            out["extra"][key] = system[key]

    # ---- 温度 / 风扇 ----
    thermal = parse.parse_thermal(raw.get("thermal") or {})
    stats = parse.temp_stats(thermal["temps"])
    out["max_temp_c"] = stats["max_temp_c"]
    out["inlet_temp_c"] = stats["inlet_temp_c"]
    out["temp_delta_c"] = stats["temp_delta_c"]
    out["extra"]["temps"] = thermal["temps"]
    out["extra"]["hottest"] = stats["hottest"]

    fans = thermal["fans"]
    out["extra"]["fans"] = fans
    # 只统计真的报转速的风扇 —— 有些机型报的是百分比,拿它当 RPM
    # 会显示成"风扇快停了"
    rpms = [f["rpm"] for f in fans if f["rpm"] is not None and f["units"] == "rpm"]
    out["fan_max_rpm"] = int(max(rpms)) if rpms else None
    out["fan_total"], out["fan_bad"], fan_unknown = parse.count_states(fans)

    # ---- 电源 ----
    power = parse.parse_power(raw.get("power") or {})
    out["power_watts"] = power["watts"]
    out["extra"]["psus"] = power["psus"]
    out["psu_total"], out["psu_bad"], _ = parse.count_states(power["psus"])

    # ---- 内存 ----
    memory = parse.parse_memory(raw.get("memory") or {})
    out["extra"]["memory"] = memory
    if memory:
        out["memory_total"], out["memory_bad"], _ = parse.count_states(memory)
    else:
        # $expand 不支持(iDRAC 7/8 常见)→ 逐条明细拿不到,只剩汇总健康值。
        # **不要把 memory_total 填成 0** —— 那看着像"这台机器没有内存"。
        # 汇总值仍然能判事件,页面上说明为什么没有明细
        out["extra"]["memory_summary_only"] = (
            "这个固件不支持 $expand,拿不到逐条内存明细 —— "
            "下面的内存健康是 iDRAC 给的汇总值"
        )
        out["extra"]["memory_health"] = system.get("memory_health", HwState.UNKNOWN)

    # ---- 存储 ----
    storage = parse.parse_storage(raw.get("storage") or {})
    out["extra"]["disks"] = storage["disks"]
    out["extra"]["volumes"] = storage["volumes"]
    out["disk_total"], out["disk_bad"], out["disk_unknown"] = parse.count_states(storage["disks"])
    out["vdisk_total"], out["vdisk_bad"], _ = parse.count_states(storage["volumes"])

    # ---- 硬件日志 ----
    if host.collect_events and raw.get("sel") is not None:
        out["extra"]["sel"] = parse.parse_sel(raw["sel"], host.event_window_days)

    out["extra"]["fan_unknown"] = fan_unknown
    out["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return out


# =========================================================================
# 阈值判定
# =========================================================================


def evaluate_idrac(host: IdracHost, data: dict, reachable: bool, error: str) -> tuple[str, list[dict]]:
    """
    **唯一的带外阈值判定处。**状态语义在这里定完 —— 前端颜色、事件级别、
    大屏统计都以这里为准。
    """

    if not reachable:
        return LinkState.DOWN, [{
            "kind": EventKind.IDRAC_DOWN, "severity": Severity.CRITICAL,
            "value": None, "threshold": None, "unit": "",
            "message": error or "带外管理口失联",
        }]

    problems: list[dict] = []
    state = LinkState.UP
    extra = data.get("extra") or {}

    def add(kind, severity, message, value=None, threshold=None, unit=""):
        """
        记一条问题。**同一个 kind 只能有一条** —— 这不是风格问题:
        `event_engine.process()` 里是 `{p["kind"]: p for p in problems}`,
        同 kind 的第二条会**静默覆盖**第一条。而带外这边一个 kind 下天生
        就有好几种发现(温度既有绝对值超线又有同机温差、盘既有已经坏的
        又有 SMART 预警),按追加写的话页面上只会看到最后一条 ——
        **而最后一条恰恰常常是级别较低的那条**。实测就是这样:
        89℃ 的 critical 被 20℃ 温差的 warning 顶掉了。

        所以这里合并:**级别取高的**,消息拼起来,value/threshold 跟着
        级别高的那条走(它才是触发告警的那个数)。
        """
        nonlocal state
        state = LinkState.DEGRADED
        entry = next((p for p in problems if p["kind"] == kind), None)
        if entry is None:
            problems.append({
                "kind": kind, "severity": severity, "value": value,
                "threshold": threshold, "unit": unit, "message": message,
            })
            return
        rank = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}
        if rank.get(severity, 0) > rank.get(entry["severity"], 0):
            entry.update({"severity": severity, "value": value,
                          "threshold": threshold, "unit": unit})
            # 级别更高的放前面:告警消息第一句就该是最严重的那件事
            entry["message"] = f"{message};{entry['message']}"
        else:
            entry["message"] = f"{entry['message']};{message}"

    # ---- 物理盘。SMART 预警和"已经坏了"要分开说 ----
    disks = extra.get("disks") or []
    failing = [d for d in disks if d["health"] in ("warning", "critical")]
    smart = [d for d in disks if d["smart_alert"] and d not in failing]
    if failing:
        names = "、".join(d["name"] or d["slot"] or "?" for d in failing[:4])
        add(EventKind.HW_DISK, Severity.CRITICAL,
            f"{len(failing)} 块物理盘异常:{names}"
            + ("…" if len(failing) > 4 else ""),
            value=float(len(failing)))
    if smart:
        # **SMART 预警单独报,而且是 warning 不是 info。**"这块盘还在跑但
        # 快坏了"是最该提前换的一种 —— 等到 Health 变红时盘通常已经掉了
        names = "、".join(d["name"] or d["slot"] or "?" for d in smart[:4])
        add(EventKind.HW_DISK, Severity.WARNING,
            f"{len(smart)} 块盘报了 SMART 预警(还在跑,但快坏了):{names}",
            value=float(len(smart)))

    # ---- SSD 剩余写入寿命。**机械盘不参与**(life_pct 恒为 None) ----
    if host.ssd_life_warn_pct:
        worn = [
            d for d in disks
            if d.get("life_pct") is not None and d["life_pct"] <= host.ssd_life_warn_pct
        ]
        if worn:
            worst = min(worn, key=lambda d: d["life_pct"])
            add(EventKind.SSD_WORN, Severity.WARNING,
                f"{len(worn)} 块 SSD 剩余写入寿命低于 {host.ssd_life_warn_pct}%,"
                f"最低的是 {worst['name'] or worst['slot']}({worst['life_pct']:.0f}%)",
                value=float(worst["life_pct"]), threshold=float(host.ssd_life_warn_pct), unit="%")

    # ---- RAID 卷 ----
    volumes = extra.get("volumes") or []
    bad_volumes = [v for v in volumes if v["health"] in ("warning", "critical")]
    if bad_volumes:
        names = "、".join(v["name"] for v in bad_volumes[:4])
        add(EventKind.HW_RAID, Severity.CRITICAL,
            f"{len(bad_volumes)} 个 RAID 卷降级:{names}", value=float(len(bad_volumes)))
    # 冗余度归零:**再坏一块盘这个卷就没了**。卷本身还是 OK 的,所以
    # 上面那条不会命中 —— 但这件事必须让人知道
    no_redundancy = [
        v for v in volumes
        if v.get("remaining_redundancy") == 0 and v not in bad_volumes
    ]
    if no_redundancy:
        names = "、".join(v["name"] for v in no_redundancy[:4])
        add(EventKind.HW_RAID, Severity.WARNING,
            f"{len(no_redundancy)} 个 RAID 卷已经没有冗余了(再坏一块盘就丢数据):{names}",
            value=float(len(no_redundancy)))

    # ---- 电源 ----
    psus = extra.get("psus") or []
    bad_psus = [p for p in psus if p["health"] in ("warning", "critical")]
    # 输入电压 0 = 没接电。冗余电源掉一路时机器照跑,**操作系统里一点症状
    # 都没有** —— 这正是带外监控最典型的用武之地
    unpowered = [
        p for p in psus
        if p.get("input_voltage") is not None and p["input_voltage"] < 50 and p not in bad_psus
    ]
    if bad_psus:
        add(EventKind.PSU_FAULT, Severity.CRITICAL,
            f"{len(bad_psus)} 个电源模块异常:" + "、".join(p["name"] for p in bad_psus[:4]),
            value=float(len(bad_psus)))
    if unpowered:
        add(EventKind.PSU_FAULT, Severity.WARNING,
            f"{len(unpowered)} 个电源没有输入电压(线掉了 / 那一路市电断了):"
            + "、".join(p["name"] for p in unpowered[:4]),
            value=float(len(unpowered)))

    # ---- 内存 ----
    memory = extra.get("memory") or []
    bad_memory = [m for m in memory if m["health"] in ("warning", "critical")]
    if bad_memory:
        add(EventKind.HW_MEMORY, Severity.CRITICAL,
            f"{len(bad_memory)} 条内存异常:" + "、".join(m["name"] for m in bad_memory[:4]),
            value=float(len(bad_memory)))
    elif not memory and extra.get("memory_health") in ("warning", "critical"):
        # 拿不到逐条明细但汇总值是坏的 —— **照样要报**,只是说不出是哪一条
        add(EventKind.HW_MEMORY, Severity.WARNING,
            "iDRAC 报告内存子系统异常(这个固件拿不到逐条明细,"
            "登 iDRAC 看 Memory 页面确认是哪一条)")

    # ---- 风扇 ----
    fans = extra.get("fans") or []
    bad_fans = [f for f in fans if f["health"] in ("warning", "critical")]
    if bad_fans:
        add(EventKind.HW_FAN, Severity.WARNING,
            f"{len(bad_fans)} 个风扇异常:" + "、".join(f["name"] for f in bad_fans[:4]),
            value=float(len(bad_fans)))

    # ---- 温度 ----
    max_temp = data.get("max_temp_c")
    if max_temp is not None:
        hottest = extra.get("hottest") or "?"
        if host.temp_crit_c and max_temp >= host.temp_crit_c:
            add(EventKind.TEMP_HIGH, Severity.CRITICAL,
                f"{hottest} {max_temp:.0f}℃,达到严重线 {host.temp_crit_c}℃",
                value=float(max_temp), threshold=float(host.temp_crit_c), unit="℃")
        elif host.temp_warn_c and max_temp >= host.temp_warn_c:
            add(EventKind.TEMP_HIGH, Severity.WARNING,
                f"{hottest} {max_temp:.0f}℃,超过警告线 {host.temp_warn_c}℃",
                value=float(max_temp), threshold=float(host.temp_warn_c), unit="℃")

    # 同机温差 —— **iDRAC 自己没有这条判据**,而它比绝对值更早发现
    # "某一颗 CPU 的散热坏了"。消息里带上进风温度,因为那是区分
    # "机房热"和"这一颗坏了"的关键:进风不高而两颗差很多 = 是这一颗
    delta = data.get("temp_delta_c")
    if host.temp_delta_warn_c and delta is not None and delta >= host.temp_delta_warn_c:
        inlet = data.get("inlet_temp_c")
        inlet_text = f",进风 {inlet:.0f}℃" if inlet is not None else ""
        add(EventKind.TEMP_HIGH, Severity.WARNING,
            f"同机两颗 CPU 温差 {delta:.0f}℃{inlet_text} —— "
            "机房不热而两颗差这么多,是其中一颗的散热出了问题(风道堵了 / 硅脂干了)",
            value=float(delta), threshold=float(host.temp_delta_warn_c), unit="℃")

    # ---- 整机健康。**放最后,而且只在上面都没命中时才报** ----
    # iDRAC 说"整机不正常"但我们逐个部件都查过没问题,那多半是一条
    # 陈旧的 SEL 记录把整机状态钉住了(它不会自己清)。这时报一条
    # 级别较低的、说明白原因的事件,比报一条"整机严重"有用得多
    if not problems and data.get("health") in ("warning", "critical"):
        add(EventKind.HW_HEALTH, Severity.WARNING,
            "iDRAC 报告整机健康异常,但逐个部件查下来都正常 —— "
            "多半是硬件日志(SEL)里有没清掉的旧记录把整机状态钉住了。"
            "登 iDRAC 确认后清一次 SEL")

    return state, problems


# =========================================================================
# 主入口
# =========================================================================


def collect_idrac(host: IdracHost) -> IdracSample:
    """采一台带外:连 → 拉 → 判 → 写样本 → 开/关事件。"""

    now = timezone.now()
    data: dict = {"extra": {}}
    error = ""

    try:
        data = _collect_raw(host)
    except IdracError as exc:
        error = str(exc)
        log.info("带外 %s 采集失败: %s", host.name, error)
    except Exception as exc:  # noqa: BLE001 —— 意外也要写一行样本,不能让任务炸掉
        error = f"{type(exc).__name__}: {exc}"
        log.exception("带外 %s 采集异常", host.name)

    reachable = not error

    sample = IdracSample.objects.create(
        idrac=host, ts=now, reachable=reachable,
        latency_ms=data.get("latency_ms"),
        power_watts=data.get("power_watts"),
        inlet_temp_c=data.get("inlet_temp_c"),
        max_temp_c=data.get("max_temp_c"),
        temp_delta_c=data.get("temp_delta_c"),
        fan_max_rpm=data.get("fan_max_rpm"),
        disk_total=data.get("disk_total"), disk_bad=data.get("disk_bad"),
        disk_unknown=data.get("disk_unknown"),
        psu_total=data.get("psu_total"), psu_bad=data.get("psu_bad"),
        memory_total=data.get("memory_total"), memory_bad=data.get("memory_bad"),
        fan_total=data.get("fan_total"), fan_bad=data.get("fan_bad"),
        vdisk_total=data.get("vdisk_total"), vdisk_bad=data.get("vdisk_bad"),
        health=data.get("health") or HwState.UNKNOWN,
        extra=data.get("extra") or {}, error=error[:255],
    )

    # ---- 回写状态 ----
    state, problems = evaluate_idrac(host, data, reachable, error)
    fields = ["state", "last_collected_at", "last_error",
              "consecutive_fail", "consecutive_ok"]
    host.state = state
    host.last_collected_at = now
    host.last_error = error[:255]
    if reachable:
        host.consecutive_ok += 1
        host.consecutive_fail = 0
    else:
        host.consecutive_fail += 1
        host.consecutive_ok = 0

    # 铭牌信息回填。**型号 / 服务编号已有值就不覆盖**(它们不会变,
    # 变了说明是换了台机器,那时候人应该重新加一条而不是被静默改掉);
    # 固件版本和电源状态反过来 —— 那两个本来就该跟着变
    for attr in ("model_name", "manufacturer", "service_tag", "system_hostname"):
        value = data.get(attr)
        if value and not getattr(host, attr):
            setattr(host, attr, value)
            fields.append(attr)
    for attr in ("bios_version", "idrac_firmware", "power_state"):
        value = data.get(attr)
        if value and value != getattr(host, attr):
            setattr(host, attr, value)
            fields.append(attr)

    host.save(update_fields=list(dict.fromkeys(fields)))

    outcome = event_engine.process(event_engine.EventSource.from_idrac(host), problems)
    _queue_notifications(outcome)
    return sample


def _queue_notifications(outcome) -> None:
    from netcheck.tasks import send_notification

    for event in outcome.opened + outcome.escalated:
        send_notification.delay(event.pk, "alert")
    for event in outcome.resolved:
        send_notification.delay(event.pk, "recover")


def test_connection(host: IdracHost) -> tuple[bool, str]:
    """
    配置中心的「测试」按钮。**不写库、不开事件。**

    报错要**指向性**:401 说凭据、403 说角色权限、404 说固件太老或者
    这根本不是一台 Dell、SSL 说把校验关掉 —— 见 `redfish.py` 里那一串。

    成功时把型号、服务编号、部件数一起打出来:**部件数是 0 的那一栏
    最能说明问题**(比如硬盘 0 块 = 这个账号读不到存储,或者盘挂在
    一个 Redfish 看不见的 HBA 上)。
    """

    started = time.perf_counter()
    try:
        data = _collect_raw(host)
    except IdracError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"

    elapsed = int((time.perf_counter() - started) * 1000)
    extra = data.get("extra") or {}
    head = " · ".join(p for p in (
        data.get("manufacturer", ""), data.get("model_name", ""),
        f"SN {data['service_tag']}" if data.get("service_tag") else "",
    ) if p) or host.host

    detail = [f"{head}({elapsed}ms)"]
    if data.get("system_hostname"):
        detail.append(f"主机名 {data['system_hostname']}")
    if data.get("power_state"):
        detail.append(f"电源 {data['power_state']}")
    if data.get("idrac_firmware"):
        detail.append(f"iDRAC {data['idrac_firmware']}")

    # 部件数。**0 要说出来**,它通常是权限或型号的线索
    detail.append(
        f"硬盘 {data.get('disk_total', 0)} 块 / "
        f"内存 {data.get('memory_total') if data.get('memory_total') is not None else '汇总'} / "
        f"电源 {data.get('psu_total', 0)} / 风扇 {data.get('fan_total', 0)}"
    )
    if data.get("max_temp_c") is not None:
        detail.append(f"最高温度 {data['max_temp_c']:.0f}℃({extra.get('hottest') or '?'})")
    if data.get("power_watts") is not None:
        detail.append(f"功耗 {data['power_watts']:.0f}W")

    # 哪一段没取到 —— 这才是「测试」最该回答的东西
    if errors := extra.get("endpoint_errors"):
        detail.append("取不到的段:" + "、".join(f"{k}({v})" for k, v in errors.items()))
    if extra.get("memory_summary_only"):
        detail.append("内存只有汇总值(固件不支持 $expand)")

    return True, " | ".join(detail)
