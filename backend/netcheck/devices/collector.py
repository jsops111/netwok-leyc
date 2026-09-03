"""
设备采集的统一入口。

一次采集的流水线:

    选通道(主/降级) → 采整机指标 → 采接口(可选) → 算速率 → 写库
                                                        → 判阈值 → 事件引擎

**通道降级只在"通道级失败"时触发**(连不上、认证错、超时),不在"某个指标
采不到"时触发 —— 后者是画像里的 optional 该处理的事。把两者混在一起会导致
一台温度传感器缺失的 C9200L 每分钟都去走一遍 SSH 降级。
"""

from __future__ import annotations

import logging
import time

from django.utils import timezone

from netcheck.events import engine as event_engine
from netcheck.models import (
    CollectMethod,
    Device,
    DeviceInterface,
    DeviceSample,
    EventKind,
    InterfaceSample,
    LinkState,
    Severity,
    Vendor,
)

from . import fortigate_api, sdwan, snmp, ssh_cli
from .profiles import (
    ENTITY_SERIAL,
    IF_COLUMNS,
    IF_FALLBACK_COLUMNS,
    SYS,
    Profile,
    get_profile,
)

log = logging.getLogger("netcheck.collector")

# CISCO-ENVMON 的状态码。1=normal 5=notPresent 都不算故障;
# 2=warning 3=critical 4=shutdown 6=notFunctioning 算故障。
_ENVMON_OK = {1, 5}


class CollectError(Exception):
    """通道级失败 —— 会触发降级。"""


# =========================================================================
# SNMP 通道的指标组装
# =========================================================================


def _collect_snmp(device: Device, profile: Profile) -> dict:
    started = time.perf_counter()
    out: dict = {"extra": {"channel": "snmp"}}

    # 标量 OID 合并成一次 GET —— 一台设备一次采集要走十几个标量,
    # 一个一个 GET 就是十几个 RTT
    scalar_oids: list[str] = [SYS["sysDescr"], SYS["sysName"], SYS["ifNumber"]]
    scalar_fields: dict[str, tuple[str, float]] = {}
    table_specs: dict[str, str] = {}
    table_fields: dict[str, tuple[str, str, float]] = {}
    # table_max_named 用:值列 key → 名字列 key,名字列 key → 要匹配的子串
    name_columns: dict[str, str] = {}
    name_matches: dict[str, tuple[str, ...]] = {}

    for field, spec in profile.metrics.items():
        if spec.kind == "scalar":
            for oid in spec.oids:
                scalar_oids.append(oid)
                scalar_fields.setdefault(oid, (field, spec.scale))
        else:
            for idx, oid in enumerate(spec.oids):
                key = f"{field}#{idx}"
                table_specs[key] = oid
                table_fields[key] = (field, spec.kind, spec.scale)
                if spec.kind == "table_max_named" and spec.name_oid:
                    name_key = f"{key}@name"
                    table_specs[name_key] = spec.name_oid
                    name_columns[key] = name_key
                    name_matches[name_key] = tuple(m.lower() for m in spec.name_match)

    try:
        scalars = snmp.snmp_get(device, list(dict.fromkeys(scalar_oids)))
    except snmp.SnmpError as exc:
        raise CollectError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise CollectError(f"SNMP 采集异常: {type(exc).__name__}: {exc}") from exc

    if descr := scalars.get(SYS["sysDescr"]):
        out["extra"]["sys_descr"] = str(descr)[:300]
        # 固件版本从 sysDescr 里抽 —— 比让人手填准
        if version := _version_from_descr(str(descr), device.vendor):
            out["os_version"] = version
    if name := scalars.get(SYS["sysName"]):
        out["extra"]["sys_name"] = str(name)
    if if_number := scalars.get(SYS["ifNumber"]):
        out["if_total"] = _as_int(if_number)

    # 候选 OID 按顺序:第一个有值的赢
    for oid, (field, scale) in scalar_fields.items():
        if field in out:
            continue
        value = _as_float(scalars.get(oid))
        if value is not None:
            out[field] = round(value * scale, 3)

    # 表:并发走
    tables: dict[str, dict] = {}
    if table_specs:
        try:
            tables = snmp.snmp_walk_many(device, table_specs, max_rows=256)
        except Exception as exc:  # noqa: BLE001 —— 表采不到不该让整次采集失败
            log.warning("设备 %s 表采集失败: %s", device.name, exc)
            tables = {}

    for key, rows in tables.items():
        if key in name_matches:  # 名字列是用来筛行的,它自己不是指标
            continue
        field, kind, scale = table_fields[key]
        if not rows or field in out:
            continue
        # psu_state / fan_state 是状态码,不能求 max/sum,单独判
        if field in ("psu_state", "fan_state"):
            codes = [c for c in (_as_int(v) for v in rows.values()) if c is not None]
            if codes:
                ok = all(c in _ENVMON_OK for c in codes)
                out["psu_ok" if field == "psu_state" else "fan_ok"] = ok
                if not ok:
                    out["extra"][f"{field}_codes"] = codes[:8]
            continue
        if kind == "table_max_named":
            rows = _filter_by_name(
                device, field, rows,
                tables.get(name_columns.get(key, "")) or {},
                name_matches[name_columns[key]], out,
            )
            if rows is None:
                continue
        values = [v for v in (_as_float(v) for v in rows.values()) if v is not None]
        if not values:
            continue
        aggregated = sum(values) if kind == "table_sum" else max(values)
        out[field] = round(aggregated * scale, 3)

    # 内存使用率要自己算(Cisco 只给 used/free 两个绝对值)
    used, free = out.pop("mem_used", None), out.pop("mem_free", None)
    if used is not None and free is not None and (used + free) > 0:
        out["mem_pct"] = round(used / (used + free) * 100, 2)
        out["extra"]["mem_used_bytes"] = int(used)
        out["extra"]["mem_total_bytes"] = int(used + free)

    # 序列号:entPhysicalSerialNum 表里第一个非空的
    if device.vendor == Vendor.CISCO and not device.serial:
        try:
            serials = snmp.snmp_walk(device, ENTITY_SERIAL, max_rows=64)
            for value in serials.values():
                text = str(value).strip()
                if text:
                    out["serial"] = text
                    break
        except Exception:  # noqa: BLE001 —— 序列号是附加项
            pass

    # 声明缺失的指标写进 extra,前端据此显示 "—" 而不是"采集失败"
    if profile.absent:
        out["extra"]["absent"] = sorted(profile.absent)
    missing = [f for f in profile.metrics if f not in out and f not in ("mem_used", "mem_free")]
    if missing:
        out["extra"]["not_collected"] = missing

    out["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return out


def _filter_by_name(
    device: Device, field: str, rows: dict, names: dict,
    wanted: tuple[str, ...], out: dict,
) -> dict | None:
    """
    按同表的名字列筛行(索引对索引)。返回 None 表示"这个指标这次不出数"。

    **名字列走不通时不退回全表最大值。**FortiGate 的传感器表里温度、风扇转速、
    电压混在一列,退回去取到的是 9000+ 的转速当温度报上来 —— 错的数字比没有
    数字糟得多:页面上看不出它是错的,阈值判定还会拿它去刷严重告警。
    采不到就让它留空,这类指标本来就在画像的 optional 里。
    """

    if not names:
        out["extra"].setdefault("name_column_missing", []).append(field)
        log.warning("设备 %s 的 %s 取不到名字列,跳过(不退回全表最大值)", device.name, field)
        return None
    matched = {
        idx: value for idx, value in rows.items()
        if any(w in str(names.get(idx, "")).lower() for w in wanted)
    }
    if not matched:
        out["extra"].setdefault("name_no_match", []).append(field)
        log.info(
            "设备 %s 的 %s:%d 行传感器里没有名字匹配 %s 的,示例名字 %s",
            device.name, field, len(rows), list(wanted),
            [str(v) for v in list(names.values())[:6]],
        )
        return None
    return matched


def _version_from_descr(descr: str, vendor: str) -> str:
    import re

    if vendor == Vendor.CISCO:
        if m := re.search(r"Version\s+([\d]+\.[\w.()]+)", descr):
            return m.group(1).rstrip(",")
    elif vendor == Vendor.FORTINET:
        if m := re.search(r"(v[\d.]+,build\d+)", descr):
            return m.group(1)
    return ""


def _as_float(value):
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _as_int(value):
    result = _as_float(value)
    return int(result) if result is not None else None


# =========================================================================
# 接口采集
# =========================================================================


def _collect_interfaces_snmp(device: Device) -> list[dict]:
    columns = dict(IF_COLUMNS)
    tables = snmp.snmp_walk_many(device, columns, max_rows=512)

    # ifHC*(64 位)采不到才退回 32 位。回退时在 extra 里标注 —— 千兆口用
    # 32 位计数器算出来的速率不可信,页面上要能看出来这个数据的成色。
    used_fallback = False
    if not tables.get("ifHCInOctets") and not tables.get("ifHCOutOctets"):
        fallback = snmp.snmp_walk_many(device, dict(IF_FALLBACK_COLUMNS), max_rows=512)
        tables["ifHCInOctets"] = fallback.get("ifInOctets", {})
        tables["ifHCOutOctets"] = fallback.get("ifOutOctets", {})
        used_fallback = bool(tables["ifHCInOctets"])

    indexes = set()
    for column in ("ifDescr", "ifName", "ifOperStatus"):
        indexes.update(tables.get(column, {}).keys())

    out: list[dict] = []
    for idx in sorted(indexes, key=lambda x: int(x) if x.isdigit() else 0):
        if not idx.isdigit():
            continue
        name = str(tables.get("ifName", {}).get(idx) or tables.get("ifDescr", {}).get(idx) or f"if{idx}")
        # 速率优先 ifHighSpeed(Mbps),它对万兆口才是对的;
        # ifSpeed 是 32 位,上限 4.29Gbps,万兆口读出来是 4294967295
        speed_bps = None
        if high := _as_float(tables.get("ifHighSpeed", {}).get(idx)):
            speed_bps = int(high * 1_000_000)
        elif low := _as_float(tables.get("ifSpeed", {}).get(idx)):
            speed_bps = int(low) if low < 4_294_967_295 else None

        out.append({
            "if_index": int(idx),
            "if_name": name,
            "if_alias": str(tables.get("ifAlias", {}).get(idx) or ""),
            "if_type": str(tables.get("ifType", {}).get(idx) or ""),
            "mac": str(tables.get("ifPhysAddress", {}).get(idx) or ""),
            "speed_bps": speed_bps,
            "admin_up": _as_int(tables.get("ifAdminStatus", {}).get(idx)) == 1,
            "oper_up": _as_int(tables.get("ifOperStatus", {}).get(idx)) == 1,
            "in_octets": _as_int(tables.get("ifHCInOctets", {}).get(idx)),
            "out_octets": _as_int(tables.get("ifHCOutOctets", {}).get(idx)),
            "in_errors": _as_int(tables.get("ifInErrors", {}).get(idx)),
            "out_errors": _as_int(tables.get("ifOutErrors", {}).get(idx)),
            "in_discards": _as_int(tables.get("ifInDiscards", {}).get(idx)),
            "out_discards": _as_int(tables.get("ifOutDiscards", {}).get(idx)),
            "_counter_32bit": used_fallback,
        })
    return out


def _rate(current, previous, seconds: float) -> float | None:
    """
    从计数器差算速率(bps)。

    current < previous 说明**计数器回绕或设备重启**。这时候唯一正确的做法
    是丢掉这次的速率(返回 None):按差值算会得到一个负数,取绝对值会在图上
    画出一根冲天的假尖峰,而那种尖峰会被当成真的流量突发去排查。
    """
    if current is None or previous is None or seconds <= 0:
        return None
    if current < previous:
        return None
    return round((current - previous) * 8 / seconds, 2)


def _save_interfaces(device: Device, rows: list[dict], now) -> list[dict]:
    """
    写接口当前状态 + 流量样本,并返回接口级问题清单(给事件引擎)。
    """

    existing = {i.if_index: i for i in device.interfaces.all()}
    problems_by_interface: list[dict] = []
    samples: list[InterfaceSample] = []

    for row in rows:
        iface = existing.get(row["if_index"])
        if iface is None:
            iface = DeviceInterface(device=device, if_index=row["if_index"])

        was_up = iface.oper_up
        iface.if_name = row["if_name"][:128]
        iface.if_alias = (row.get("if_alias") or "")[:255]
        iface.if_type = (row.get("if_type") or "")[:32]
        iface.mac = (row.get("mac") or "")[:32]
        iface.speed_bps = row.get("speed_bps")
        iface.admin_up = row.get("admin_up")
        iface.oper_up = row.get("oper_up")
        if was_up is not None and was_up != iface.oper_up:
            iface.last_change = now

        # 上次的计数器存在 meta 里 —— 反正这一行本来就要 save,
        # 不值得为它单独加四列
        last = (iface.meta or {}).get("last") or {}
        elapsed = 0.0
        if last.get("ts"):
            try:
                from datetime import datetime

                elapsed = (now - datetime.fromisoformat(last["ts"])).total_seconds()
            except (ValueError, TypeError):
                elapsed = 0.0

        in_bps = _rate(row.get("in_octets"), last.get("in_octets"), elapsed)
        out_bps = _rate(row.get("out_octets"), last.get("out_octets"), elapsed)
        iface.in_bps = in_bps
        iface.out_bps = out_bps
        iface.in_err_delta = _delta(row.get("in_errors"), last.get("in_errors"))
        iface.out_err_delta = _delta(row.get("out_errors"), last.get("out_errors"))

        meta = dict(iface.meta or {})
        meta["last"] = {
            "ts": now.isoformat(),
            "in_octets": row.get("in_octets"),
            "out_octets": row.get("out_octets"),
            "in_errors": row.get("in_errors"),
            "out_errors": row.get("out_errors"),
        }
        if row.get("_counter_32bit"):
            meta["counter_32bit"] = True
        iface.meta = meta
        iface.save()

        samples.append(InterfaceSample(
            interface=iface, ts=now,
            in_octets=row.get("in_octets"), out_octets=row.get("out_octets"),
            in_bps=in_bps, out_bps=out_bps,
            in_errors=row.get("in_errors"), out_errors=row.get("out_errors"),
            in_discards=row.get("in_discards"), out_discards=row.get("out_discards"),
            oper_up=row.get("oper_up"),
        ))

        if iface.monitored:
            problems_by_interface.append({"interface": iface, "problems": _evaluate_interface(device, iface)})

    if samples:
        InterfaceSample.objects.bulk_create(samples, batch_size=200)
    return problems_by_interface


def _delta(current, previous):
    if current is None or previous is None or current < previous:
        return None
    return current - previous


def _evaluate_interface(device: Device, iface: DeviceInterface) -> list[dict]:
    problems: list[dict] = []

    # 只对"管理上是启用的"接口判 down —— admin down 是人为关的,不是故障。
    # 这一条不写的话,48 口交换机上一堆空闲口会天天报警。
    if iface.admin_up and iface.oper_up is False:
        problems.append({
            "kind": EventKind.IF_DOWN, "severity": Severity.WARNING,
            "value": None, "threshold": None, "unit": "",
            "message": f"接口 {iface.if_name} 管理状态 up 但链路 down",
        })

    if iface.in_err_delta or iface.out_err_delta:
        total = (iface.in_err_delta or 0) + (iface.out_err_delta or 0)
        if total > 0:
            problems.append({
                "kind": EventKind.IF_ERROR, "severity": Severity.WARNING,
                "value": float(total), "threshold": 0.0, "unit": "个",
                "message": f"接口 {iface.if_name} 本周期新增错包 {total} 个(入 {iface.in_err_delta or 0} / 出 {iface.out_err_delta or 0})",
            })

    if device.if_util_warn_pct and iface.speed_bps:
        for direction, util in (("入向", iface.util_in_pct), ("出向", iface.util_out_pct)):
            if util is not None and util >= device.if_util_warn_pct:
                problems.append({
                    "kind": EventKind.IF_SATURATED,
                    "severity": Severity.CRITICAL if util >= 95 else Severity.WARNING,
                    "value": util, "threshold": float(device.if_util_warn_pct), "unit": "%",
                    "message": f"接口 {iface.if_name} {direction}带宽利用率 {util}%",
                })
                break

    return problems


# =========================================================================
# 整机阈值判定
# =========================================================================


def evaluate_device(device: Device, data: dict, reachable: bool, error: str) -> tuple[str, list[dict]]:
    if not reachable:
        return LinkState.DOWN, [{
            "kind": EventKind.DEVICE_DOWN, "severity": Severity.CRITICAL,
            "value": None, "threshold": None, "unit": "",
            "message": error or "设备失联",
        }]

    problems: list[dict] = []
    state = LinkState.UP

    def check(field: str, kind: str, warn, crit, unit: str, label: str):
        nonlocal state
        value = data.get(field)
        if value is None:
            return
        if crit and value >= crit:
            problems.append({
                "kind": kind, "severity": Severity.CRITICAL, "value": float(value),
                "threshold": float(crit), "unit": unit,
                "message": f"{label} {value}{unit} 达到严重线 {crit}{unit}",
            })
            state = LinkState.DEGRADED
        elif warn and value >= warn:
            problems.append({
                "kind": kind, "severity": Severity.WARNING, "value": float(value),
                "threshold": float(warn), "unit": unit,
                "message": f"{label} {value}{unit} 超过警告线 {warn}{unit}",
            })
            state = LinkState.DEGRADED

    check("cpu_pct", EventKind.CPU_HIGH, device.cpu_warn_pct, device.cpu_crit_pct, "%", "CPU 使用率")
    check("mem_pct", EventKind.MEM_HIGH, device.mem_warn_pct, device.mem_crit_pct, "%", "内存使用率")
    check("temp_c", EventKind.TEMP_HIGH, device.temp_warn_c, device.temp_crit_c, "℃", "温度")
    if device.session_warn:
        check("session_count", EventKind.SESSION_HIGH, device.session_warn, None, "", "并发会话数")

    if data.get("psu_ok") is False:
        problems.append({
            "kind": EventKind.PSU_FAULT, "severity": Severity.CRITICAL,
            "value": None, "threshold": None, "unit": "",
            "message": "电源模块状态异常" + (
                f"(ENVMON 状态码 {data.get('extra', {}).get('psu_state_codes')})"
                if data.get("extra", {}).get("psu_state_codes") else ""
            ),
        })
        state = LinkState.DEGRADED
    if data.get("fan_ok") is False:
        problems.append({
            "kind": EventKind.PSU_FAULT, "severity": Severity.WARNING,
            "value": None, "threshold": None, "unit": "", "message": "风扇状态异常",
        })
        state = LinkState.DEGRADED

    # HA 状态变化:和上次采到的比,变了就记一条(提示级,不判 degraded) ——
    # 主备切换本身不是故障,但值班的人必须知道
    ha_now = data.get("ha_state")
    ha_last = (device.meta or {}).get("last_ha_state")
    if ha_now and ha_last and ha_now != ha_last:
        problems.append({
            "kind": EventKind.HA_CHANGE, "severity": Severity.WARNING,
            "value": None, "threshold": None, "unit": "",
            "message": f"HA 状态由 {ha_last} 变为 {ha_now}",
        })

    return state, problems


# =========================================================================
# 主入口
# =========================================================================


def _run_channel(device: Device, method: str, profile: Profile) -> dict:
    if method == CollectMethod.SNMP:
        return _collect_snmp(device, profile)
    if method == CollectMethod.SSH:
        try:
            return ssh_cli.collect(device)
        except ssh_cli.SshError as exc:
            raise CollectError(str(exc)) from exc
    if method == CollectMethod.API:
        if device.vendor != Vendor.FORTINET:
            raise CollectError(f"REST API 通道未实现厂商 {device.vendor}")
        try:
            return fortigate_api.collect(device)
        except fortigate_api.FortiApiError as exc:
            raise CollectError(str(exc)) from exc
    raise CollectError(f"未知的采集方式 {method}")


def _collect_sdwan(device: Device, now) -> list[dict]:
    """
    拉一次 SD-WAN 健康检查,写链路当前值 + 一行采样,返回要开的事件。

    通道:有 API Token 走 monitor 端点(能拿到带宽、会话数、SLA 档数),
    否则退回 SSH 的 `diagnose sys sdwan health-check`(**拿不到的东西比
    拿得到的多**,见 `sdwan.py` 的说明)。

    ## 判定:**主判据是设备自己算的**

    FortiOS 允许一个健康检查配多档 SLA,选路按档走 —— **它比我们更清楚
    它按哪一档选路**,所以"达标没达标"以 `sla_met` 为准,平台不重算。
    平台自己那两个门限(`Device.sla_latency_warn_ms` / `sla_loss_warn_pct`)
    是给"设备说达标但数字已经很难看"准备的:FortiOS 的门限常常配得很松
    (比如 200ms),而一条 180ms 的专线该早点有人看一眼。
    """

    from netcheck.models import SdwanLink, SdwanSample, SdwanState

    rows: list[dict] = []
    config: dict = {}
    method = ""
    if device.api_token:
        payload = fortigate_api.fetch_sdwan_health(device)
        if payload is not None:
            rows = sdwan.parse_health_check(payload)
            method = "api"
        # **配置里才有门限。**monitor 端点只给实测值 —— 没有门限的话
        # 页面上"延迟 186ms"这个数没法判断算不算超,人得自己登防火墙翻配置
        cfg = fortigate_api.fetch_sdwan_config(device)
        if cfg is not None:
            config = sdwan.parse_sdwan_config(cfg)
    if not rows:
        raw = ssh_cli_sdwan(device)
        if raw:
            rows = sdwan.parse_diagnose_sdwan(raw)
            method = "ssh"

    if not rows:
        # **没有链路不等于没配 SD-WAN。**权限不够、命令名在这个版本上不一样、
        # 或者真的没配 —— 三种都会走到这里,所以这句话说的是"没采到"
        device.last_sdwan_error = "没有采到 SD-WAN 健康检查数据(没配?权限不够?)"[:255]
        device.save(update_fields=["last_sdwan_error"])
        return []

    problems: list[dict] = []
    seen: set[tuple[str, str]] = set()
    vdom = device.api_vdom or "root"

    for row in rows:
        key = (row["health_check"], row["member"])
        seen.add(key)
        link, created = SdwanLink.objects.get_or_create(
            device=device, vdom=vdom,
            health_check=row["health_check"], member=row["member"],
            defaults={"synced_at": now},
        )
        # 状态变了要留时间戳 —— "这条线什么时候掉的"是排障第一句话
        if not created and link.state != row["state"]:
            link.last_change = now

        for field in ("server", "protocol", "state", "latency_ms", "jitter_ms",
                      "loss_pct", "sla_met", "sla_targets_met", "sla_targets_total",
                      "tx_bps", "rx_bps", "session_count", "extra"):
            setattr(link, field, row[field])

        # ---- 把配置里的门限和探测目标接上 ----
        check_cfg = config.get(row["health_check"])
        if check_cfg:
            # monitor 端点没给 server 时用配置里的。**配了多个就都显示** ——
            # FortiOS 允许一个检查探好几个地址,只显示第一个会让人以为
            # 探的就那一个
            if not link.server and check_cfg["servers"]:
                link.server = ", ".join(check_cfg["servers"])[:255]
            if not link.protocol and check_cfg["protocol"]:
                link.protocol = check_cfg["protocol"][:16]
            strict = sdwan.strictest_sla(check_cfg["sla"])
            link.sla_latency_threshold = strict["latency"]
            link.sla_jitter_threshold = strict["jitter"]
            link.sla_loss_threshold = strict["loss"]
            extra = dict(link.extra or {})
            # 每一档的门限都留着 —— 页面上鼠标停一下能看到全部几档,
            # 而列上只显示最严那一档
            extra["sla_levels"] = check_cfg["sla"]
            extra["probe_interval"] = check_cfg["interval"]
            link.extra = extra
            if link.sla_targets_total is None and check_cfg["sla"]:
                link.sla_targets_total = len(check_cfg["sla"])

        link.synced_at = now
        link.method = method
        link.save()

        SdwanSample.objects.create(
            link=link, ts=now, state=row["state"],
            latency_ms=row["latency_ms"], jitter_ms=row["jitter_ms"],
            loss_pct=row["loss_pct"], sla_met=row["sla_met"],
            tx_bps=row["tx_bps"], rx_bps=row["rx_bps"],
        )

        label = f"{row['health_check']}/{row['member']}"

        # ---- 成员不通 ----
        if row["state"] == SdwanState.DEAD:
            problems.append({
                "kind": EventKind.SDWAN_DEAD, "severity": Severity.CRITICAL,
                "value": None, "threshold": None, "unit": "",
                "message": f"SD-WAN 成员 {label} 探测不通(丢包 100%)",
            })
            continue

        # ---- SLA 未达标(设备自己的判定) ----
        if row["sla_met"] is False:
            detail = []
            if row["latency_ms"] is not None:
                detail.append(f"延迟 {row['latency_ms']:.1f}ms")
            if row["jitter_ms"] is not None:
                detail.append(f"抖动 {row['jitter_ms']:.1f}ms")
            if row["loss_pct"] is not None:
                detail.append(f"丢包 {row['loss_pct']:.1f}%")
            targets = ""
            if row["sla_targets_total"]:
                targets = f",{row['sla_targets_total']} 档 SLA 都没过"
            problems.append({
                "kind": EventKind.SLA_VIOLATED, "severity": Severity.WARNING,
                "value": row["latency_ms"], "threshold": None, "unit": "ms",
                "message": f"{label} SLA 未达标({'、'.join(detail) or '设备判定'}){targets}",
            })
            continue

        # ---- 平台自己那条额外门限 ----
        # **只在设备说达标时才判** —— 上面那条已经报过的不再重复报一次
        extra_hits = []
        if device.sla_latency_warn_ms and row["latency_ms"] is not None \
                and row["latency_ms"] >= device.sla_latency_warn_ms:
            extra_hits.append(
                f"延迟 {row['latency_ms']:.1f}ms 超过平台警告线 {device.sla_latency_warn_ms:.0f}ms")
        if device.sla_loss_warn_pct and row["loss_pct"] is not None \
                and row["loss_pct"] >= device.sla_loss_warn_pct:
            extra_hits.append(
                f"丢包 {row['loss_pct']:.1f}% 超过平台警告线 {device.sla_loss_warn_pct:.1f}%")
        if extra_hits:
            problems.append({
                "kind": EventKind.SLA_VIOLATED, "severity": Severity.WARNING,
                "value": row["latency_ms"], "threshold": device.sla_latency_warn_ms,
                "unit": "ms",
                # **说清楚这是平台的线不是设备的** —— 否则人会去 FortiGate 上
                # 找一条对不上的 SLA 配置
                "message": (
                    f"{label} 设备判定达标,但{'、'.join(extra_hits)}"
                    "(这是平台自己的门限,不是设备的 SLA)"
                ),
            })

    # 设备上已经没有的链路要删掉(改了健康检查名、删了成员)——
    # 留着的话页面上会一直显示一条永远不更新的链路
    stale = [
        link.pk for link in SdwanLink.objects.filter(device=device, vdom=vdom)
        if (link.health_check, link.member) not in seen
    ]
    if stale:
        SdwanLink.objects.filter(pk__in=stale).delete()

    device.last_sdwan_at = now
    device.last_sdwan_error = ""
    device.save(update_fields=["last_sdwan_at", "last_sdwan_error"])
    return problems


def ssh_cli_sdwan(device: Device) -> str:
    """
    SSH 兜底:跑 `diagnose sys sdwan health-check`。

    **7.0 之前那条命令叫 `diagnose sys virtual-wan-link health-check`**,
    所以两条都试 —— 只试一条的话老固件上这一项永远是空的,而且不报错。
    """

    profile = get_profile(device.model, device.vendor)
    if not profile.sdwan_cli:
        return ""
    if not device.ssh_username or not (device.ssh_password or device.ssh_private_key):
        return ""

    client = ssh_cli._connect(device)
    try:
        for command in profile.sdwan_cli.split("|||"):
            try:
                raw = ssh_cli._run_exec(client, command.strip(), timeout=60.0)
            except ssh_cli.SshError:
                continue
            if "Health Check" in raw:
                return raw
    finally:
        client.close()
    return ""


def collect_device(device: Device) -> DeviceSample:
    """
    采一台设备:主通道 → 失败降级 → 写样本 → 判事件。

    无论成败都会写一行 DeviceSample —— 失败也是一个数据点,
    reachable=False 的那些行就是设备可用率的分母。
    """

    profile = get_profile(device.model, device.vendor)
    now = timezone.now()
    data: dict = {}
    error = ""
    method_used = ""

    channels = [device.collect_method] + ([device.fallback_method] if device.fallback_method else [])
    for method in channels:
        try:
            data = _run_channel(device, method, profile)
            method_used = method
            error = ""
            break
        except CollectError as exc:
            error = str(exc)
            log.info("设备 %s 通道 %s 失败: %s", device.name, method, error)
        except Exception as exc:  # noqa: BLE001 —— 通道里漏出来的意外也要降级
            error = f"{type(exc).__name__}: {exc}"
            log.exception("设备 %s 通道 %s 异常", device.name, method)

    reachable = bool(method_used)
    if reachable and len(channels) > 1 and method_used != device.collect_method:
        data.setdefault("extra", {})["degraded_from"] = device.collect_method

    # ---- 接口 ----
    interface_problems: list[dict] = []
    if reachable and device.collect_interfaces:
        try:
            if method_used == CollectMethod.API and device.vendor == Vendor.FORTINET:
                rows = fortigate_api.collect_interfaces(device)
            elif method_used == CollectMethod.SNMP:
                rows = _collect_interfaces_snmp(device)
            else:
                rows = []  # SSH 通道不解析接口明细,它是降级通道
            if rows:
                interface_problems = _save_interfaces(device, rows, now)
                data["if_total"] = len(rows)
                data["if_up"] = sum(1 for r in rows if r.get("oper_up"))
        except Exception as exc:  # noqa: BLE001 —— 接口采集失败不影响整机指标
            log.warning("设备 %s 接口采集失败: %s", device.name, exc)
            data.setdefault("extra", {})["interface_error"] = str(exc)[:200]

    # ---- 邻居(LLDP / CDP) ----
    # **只在 SNMP 通道下采** —— 这两张表是 SNMP MIB,API/SSH 通道拿不到。
    # 放在接口之后是有意的:邻居要靠接口表把 lldpLocalPortNum 翻成口名
    # (见 neighbors._resolve_local),接口先采完命中率才高
    neighbor_result: dict = {}
    if reachable and device.collect_neighbors and method_used == CollectMethod.SNMP:
        from . import neighbors as neighbor_mod

        try:
            neighbor_result = neighbor_mod.collect_neighbors(device)
            data.setdefault("extra", {})["neighbors"] = neighbor_result["total"]
        except Exception as exc:  # noqa: BLE001 —— 邻居采不到不影响别的
            log.warning("设备 %s 邻居采集失败: %s", device.name, exc)
            data.setdefault("extra", {})["neighbor_error"] = str(exc)[:200]

    # ---- 写样本 ----
    sample = DeviceSample.objects.create(
        device=device, ts=now, reachable=reachable, method=method_used,
        latency_ms=data.get("latency_ms"),
        cpu_pct=data.get("cpu_pct"), mem_pct=data.get("mem_pct"), temp_c=data.get("temp_c"),
        uptime_s=data.get("uptime_s"),
        session_count=data.get("session_count"), session_rate=data.get("session_rate"),
        ha_state=(data.get("ha_state") or "")[:32],
        vpn_tunnels_up=data.get("vpn_tunnels_up"),
        if_total=data.get("if_total"), if_up=data.get("if_up"),
        psu_ok=data.get("psu_ok"), fan_ok=data.get("fan_ok"),
        extra=data.get("extra") or {}, error=error[:255],
    )

    # ---- 回写设备状态 ----
    state, problems = evaluate_device(device, data, reachable, error)
    fields = ["state", "last_collected_at", "last_method_used", "last_error",
              "consecutive_fail", "consecutive_ok", "meta"]
    device.state = state
    device.last_collected_at = now
    device.last_method_used = method_used
    device.last_error = error[:255]
    if reachable:
        device.consecutive_ok += 1
        device.consecutive_fail = 0
    else:
        device.consecutive_fail += 1
        device.consecutive_ok = 0

    meta = dict(device.meta or {})
    if data.get("ha_state"):
        meta["last_ha_state"] = data["ha_state"]
    if data.get("extra", {}).get("license_expiry"):
        meta["license_expiry"] = data["extra"]["license_expiry"]
    device.meta = meta

    # 首次采集回填固件版本和序列号 —— 手填的值不覆盖
    if data.get("os_version") and not device.os_version:
        device.os_version = str(data["os_version"])[:64]
        fields.append("os_version")
    if data.get("serial") and not device.serial:
        device.serial = str(data["serial"])[:64]
        fields.append("serial")
    device.save(update_fields=fields)

    # ---- SD-WAN 性能 SLA ----
    #
    # **跟着设备采集的节拍走,不单独排一类调度** —— 它是指标(延迟/抖动/
    # 丢包),和 CPU、温度同一个性质,每台设备自己的 interval_seconds
    # 已经是对的节拍。
    #
    # 它的 problems **合进设备这一次 process()**,不另开一次:
    # process() 的语义是"这个来源这一拍观测到的全部问题",分两次调用的话
    # 后一次会把前一次开的事件当成已恢复关掉(CLAUDE.md 第 8 条)。
    if reachable and device.collect_sdwan:
        try:
            sdwan_problems = _collect_sdwan(device, now)
            problems.extend(sdwan_problems)
        except Exception as exc:  # noqa: BLE001 —— SD-WAN 拿不到不该让整台设备的采集失败
            log.warning("设备 %s SD-WAN 采集失败: %s", device.name, exc)
            device.last_sdwan_error = f"{type(exc).__name__}: {exc}"[:255]
            device.save(update_fields=["last_sdwan_error"])

    # ---- 事件 ----
    outcome = event_engine.process(event_engine.EventSource.from_device(device), problems)
    for item in interface_problems:
        iface_outcome = event_engine.process(
            event_engine.EventSource.from_interface(item["interface"], device), item["problems"]
        )
        outcome.opened += iface_outcome.opened
        outcome.resolved += iface_outcome.resolved
        outcome.escalated += iface_outcome.escalated

    _queue_notifications(outcome)

    # ---- 邻居变化 ----
    # **瞬时事件**,不走 process()(见 CLAUDE.md 第 8 条)。
    # 首次采集时"全是新增"不是变化,不报。
    if neighbor_result.get("changes") and not neighbor_result.get("first_run"):
        from netcheck.events.engine import record_point_event

        lines = "\n".join(
            f"  {c['local']}: {c['before']} → {c['after']}({c['protocol'].upper()})"
            for c in neighbor_result["changes"]
        )
        event = record_point_event(
            event_engine.EventSource.from_device(device),
            EventKind.NEIGHBOR_CHANGE, Severity.WARNING,
            title=f"{device.name} 邻居关系发生变化",
            message=(
                f"新增 {neighbor_result['added']} / 消失 {neighbor_result['removed']} / "
                f"换端 {neighbor_result['changed']}:\n{lines}\n"
                "—— 通常意味着有人动了线,或者对端设备被换掉/关机了"
            ),
            # 一次改线会在两端设备上各报一次,而且可能连着几拍才稳定 ——
            # 半小时窗口把一次操作收敛成一条
            dedupe_seconds=1800,
        )
        if event is not None:
            from netcheck.tasks import send_notification

            send_notification.delay(event.pk, "alert")

    return sample


def _queue_notifications(outcome) -> None:
    """事件推送异步发 —— 采集任务不该被一个连不上的 Telegram 拖住。"""

    from netcheck.tasks import send_notification

    for event in outcome.opened + outcome.escalated:
        send_notification.delay(event.pk, "alert")
    for event in outcome.resolved:
        send_notification.delay(event.pk, "recover")


def test_device_connection(device: Device, method: str = "") -> tuple[bool, str]:
    """配置中心「测试连通性」。method 留空则测主通道。"""

    method = method or device.collect_method
    if method == CollectMethod.SNMP:
        return snmp.test_connection(device)
    if method == CollectMethod.SSH:
        return ssh_cli.test_connection(device)
    if method == CollectMethod.API:
        if device.vendor != Vendor.FORTINET:
            return False, f"REST API 通道未实现厂商 {device.get_vendor_display()}"
        return fortigate_api.test_connection(device)
    return False, f"未知的采集方式 {method}"
