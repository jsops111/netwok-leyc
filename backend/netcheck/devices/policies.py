"""
防火墙策略同步 —— 把设备上**现有**的规则拉回来存成快照。

两条通道,拿到的东西不一样:

| 通道 | 配置 | 命中计数 / 字节 / 会话 |
|---|---|---|
| REST API(推荐) | 有 | **有** —— monitor/firewall/policy |
| SSH `show firewall policy` | 有 | 没有 |

命中计数是这个页面最有价值的一列:**"这条规则从来没命中过"是能直接拿去
删规则的结论**。所以 SSH 通道下 hit_count 一律留 None,不填 0 ——
"没命中过"和"不知道有没有命中"是两个结论,把后者当成前者会让人删掉
一条其实在用的规则。

## `show` 的输出里"没有那一行"是有含义的

FortiOS 的 `show`(相对 `show full-configuration`)**只打印偏离默认值的项**。
于是:

    没有 `set action ...`   → action 是默认值 deny
    没有 `set status ...`   → 策略是 enable 的
    没有 `set nat ...`      → NAT 关

把"没有 action 行"当成"未知"是错的,把它当成 accept 更是危险的错 ——
页面上会把一条拒绝规则显示成允许。这一条是 SSH 解析器里最容易搞错的地方。

## 同步是全量替换

设备上被删掉的策略必须在这边也消失。留着一条现实中已经不存在的规则比
没有这个页面更危险:有人会照着它判断"这个访问是被允许的"。
"""

from __future__ import annotations

import logging
import re

from django.db import transaction
from django.utils import timezone

from netcheck.models import (
    Device,
    DeviceKind,
    FirewallPolicy,
    FirewallVip,
    PolicyAction,
    Vendor,
    VipType,
)

from . import fortigate_api, ssh_cli
from .profiles import get_profile

log = logging.getLogger("netcheck.policies")

# 一台设备的策略条数上限。几千条策略的设备存在,但页面上翻不动,
# 而且一次 bulk_create 几万行会把内存和事务拖长 —— 超过就截断并告警
MAX_POLICIES = 3000


class PolicyError(Exception):
    pass


# =========================================================================
# 归一化
# =========================================================================

_ACTION_MAP = {
    "accept": PolicyAction.ACCEPT,
    "allow": PolicyAction.ACCEPT,
    "permit": PolicyAction.ACCEPT,
    "deny": PolicyAction.DENY,
    "drop": PolicyAction.DENY,
    "block": PolicyAction.DENY,
    "reject": PolicyAction.DENY,
    "ipsec": PolicyAction.IPSEC,
}


def normalize_action(raw: str) -> str:
    """
    动作归一化。认不出的落到 OTHER,**不猜成 accept** ——
    把一条不认识的规则显示成"允许"是这个页面能犯的最严重的错误。
    """

    return _ACTION_MAP.get(str(raw or "").strip().lower(), PolicyAction.OTHER)


def _epoch_to_dt(value):
    """
    FortiOS 的命中时间戳形状不一:秒级 epoch、毫秒级 epoch、0(从未命中)。

    0 要变成 None 而不是 1970-01-01 —— 页面上一排 1970 年会让人以为
    时区配错了,而真实含义是"这条规则从没命中过"。
    """

    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    if number > 1e11:                             # 毫秒级
        number /= 1000
    try:
        from datetime import datetime, timezone as dt_timezone

        return datetime.fromtimestamp(number, tz=dt_timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


# =========================================================================
# API 通道
# =========================================================================


def _from_api(device: Device) -> list[dict]:
    try:
        rows = fortigate_api.fetch_policies(device)
    except fortigate_api.FortiApiError as exc:
        raise PolicyError(str(exc)) from exc

    # 命中统计是可选的:profile 权限不够时它拿不到,但配置照样能展示。
    # 拿不到时**整列留 None**,页面上显示"未知"而不是 0
    stats = fortigate_api.fetch_policy_stats(device)
    if not stats and rows:
        log.info(
            "设备 %s 拿到了 %d 条策略但没有命中统计 —— "
            "REST API 管理员的 profile 需要 monitor 读权限",
            device.name, len(rows),
        )

    out: list[dict] = []
    for seq, item in enumerate(rows):
        if not isinstance(item, dict):
            continue
        try:
            policy_id = int(item.get("policyid", item.get("id")))
        except (TypeError, ValueError):
            continue

        stat = stats.get(policy_id) or {}
        out.append({
            "policy_id": policy_id,
            "seq": seq,
            "name": str(item.get("name") or "")[:128],
            "src_intf": fortigate_api._as_names(item.get("srcintf")),
            "dst_intf": fortigate_api._as_names(item.get("dstintf")),
            "src_addr": (
                fortigate_api._as_names(item.get("srcaddr"))
                or fortigate_api._as_names(item.get("srcaddr6"))
            ),
            "dst_addr": (
                fortigate_api._as_names(item.get("dstaddr"))
                or fortigate_api._as_names(item.get("dstaddr6"))
            ),
            "service": fortigate_api._as_names(item.get("service")),
            "schedule": str(item.get("schedule") or "")[:64],
            "action": normalize_action(item.get("action")),
            "enabled": str(item.get("status") or "enable").lower() != "disable",
            "nat": str(item.get("nat") or "disable").lower() == "enable",
            "log_traffic": str(item.get("logtraffic") or "")[:16],
            "comments": str(item.get("comments") or "")[:255],
            "uuid": str(item.get("uuid") or "")[:64],
            "hit_count": stat.get("hit_count"),
            "bytes_count": stat.get("bytes"),
            "packets": stat.get("packets"),
            "sessions": stat.get("active_sessions"),
            "first_hit_at": _epoch_to_dt(stat.get("first_hit")),
            "last_hit_at": _epoch_to_dt(stat.get("last_hit") or stat.get("last_used")),
            "raw": item,
        })
    return out


# =========================================================================
# SSH 通道
# =========================================================================

_RE_EDIT = re.compile(r"^\s*edit\s+(\d+)\s*$")
_RE_SET = re.compile(r"^\s*set\s+(\S+)\s+(.*)$")
_RE_NEXT = re.compile(r"^\s*next\s*$")
# `set srcaddr "a" "b"` / `set action accept` —— 带引号的取引号内,
# 不带引号的按空白切
_RE_QUOTED = re.compile(r'"([^"]*)"')


def _split_values(raw: str) -> list[str]:
    raw = raw.strip()
    if '"' in raw:
        return [v for v in _RE_QUOTED.findall(raw) if v]
    return [v for v in raw.split() if v]


def parse_show_firewall_policy(text: str) -> list[dict]:
    """
    解析 FortiOS `show firewall policy`。

    **默认值不会出现在输出里**(见模块开头):没有 `set action` 就是 deny,
    没有 `set status` 就是 enable,没有 `set nat` 就是关。
    """

    out: list[dict] = []
    current: dict | None = None
    seq = 0

    for line in text.replace("\r\n", "\n").split("\n"):
        if m := _RE_EDIT.match(line):
            current = {
                "policy_id": int(m.group(1)),
                "seq": seq,
                # 默认值在这里给全 —— 后面只覆盖 show 里出现的项
                "name": "", "src_intf": [], "dst_intf": [], "src_addr": [], "dst_addr": [],
                "service": [], "schedule": "", "action": PolicyAction.DENY,
                "enabled": True, "nat": False, "log_traffic": "", "comments": "", "uuid": "",
                # SSH 拿不到命中统计。**留 None,不要填 0**
                "hit_count": None, "bytes_count": None, "packets": None, "sessions": None,
                "first_hit_at": None, "last_hit_at": None,
                "raw": {"_channel": "ssh"},
            }
            seq += 1
            continue

        if _RE_NEXT.match(line) and current is not None:
            out.append(current)
            current = None
            continue

        if current is None:
            continue

        m = _RE_SET.match(line)
        if not m:
            continue
        key, raw_value = m.group(1).lower(), m.group(2).strip()
        values = _split_values(raw_value)
        one = values[0] if values else ""
        current["raw"][key] = raw_value

        if key == "name":
            current["name"] = one[:128]
        elif key == "srcintf":
            current["src_intf"] = values
        elif key == "dstintf":
            current["dst_intf"] = values
        elif key in ("srcaddr", "srcaddr6"):
            current["src_addr"] = current["src_addr"] + values
        elif key in ("dstaddr", "dstaddr6"):
            current["dst_addr"] = current["dst_addr"] + values
        elif key == "service":
            current["service"] = values
        elif key == "schedule":
            current["schedule"] = one[:64]
        elif key == "action":
            current["action"] = normalize_action(one)
        elif key == "status":
            current["enabled"] = one.lower() != "disable"
        elif key == "nat":
            current["nat"] = one.lower() == "enable"
        elif key == "logtraffic":
            current["log_traffic"] = one[:16]
        elif key == "comments":
            current["comments"] = one[:255]
        elif key == "uuid":
            current["uuid"] = one[:64]

    # 输出被截断时最后一条会缺 `next`。**不要把它当成一条完整策略收下** ——
    # 半条策略(比如缺了 dstaddr)在页面上看着像"目的地址是任意"
    if current is not None:
        log.warning("策略输出在 edit %s 处结束但没有 next,该条被丢弃(输出被截断?)",
                    current["policy_id"])
    return out


# =========================================================================
# 映射(firewall vip)
# =========================================================================
#
# 策略表回答"允不允许",映射表回答"外面的 1.2.3.4:443 到底进到哪台机器"。
# 后者完全不在策略表里 —— 策略的 dstaddr 里只有一个 VIP 的**名字**。
# 没有这张表的话页面上就是 `web-vip` 这么一个字符串,而它指向哪里
# 只有登上设备才知道。

# `edit "web-vip"` —— 策略是 `edit 3`(数字),VIP 是带引号的名字
_RE_EDIT_NAME = re.compile(r'^\s*edit\s+"?([^"\n]+?)"?\s*$')

# FortiOS 里 VIP 的 type。认不出的落到 other,**不猜成 static-nat** ——
# 把一条负载均衡 VIP 显示成"1.2.3.4:443 → 10.0.0.5:443"会让人以为
# 后面只有一台机器
_VIP_TYPES = {
    "static-nat": VipType.STATIC_NAT,
    "server-load-balance": VipType.LOAD_BALANCE,
    "dns-translation": VipType.DNS_TRANSLATION,
    "fqdn": VipType.FQDN,
}


def normalize_vip_type(raw: str) -> str:
    return _VIP_TYPES.get(str(raw or "").strip().lower(), VipType.OTHER)


def _mapped_ip_text(value) -> str:
    """
    `mappedip` 的形状在版本之间不一样,三种都要认:

        "10.0.0.5"                              老版本 / show 输出
        [{"range": "10.0.0.5"}]                 6.x 以后的 cmdb
        [{"range": "10.0.0.5-10.0.0.9"}, ...]   一条 VIP 映到一段地址

    **只认一种的话升级固件后这一列会变成空的**,而空的目标地址在页面上
    看着像"这条映射没配好"——而它其实好好地在把外网流量放进内网。
    """

    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return str(value.get("range") or value.get("name") or value.get("q_origin_key") or "").strip()
    if isinstance(value, list):
        parts = [_mapped_ip_text(v) for v in value]
        return ", ".join(p for p in parts if p)
    return str(value)


def _ext_ip_text(value) -> str:
    """`extip` 同样可能是字符串或列表(一段范围)。"""
    return _mapped_ip_text(value)


def _vips_from_api(device: Device) -> list[dict]:
    """API 通道的映射。**拿不到就是空列表**,不让它把策略同步拖失败。"""

    out: list[dict] = []
    for seq, item in enumerate(fortigate_api.fetch_vips(device)):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        port_forward = str(item.get("portforward") or "disable").lower() == "enable"
        out.append({
            "name": name[:128],
            "seq": seq,
            "vip_type": normalize_vip_type(item.get("type")),
            "ext_intf": fortigate_api._as_names(item.get("extintf")),
            "ext_ip": _ext_ip_text(item.get("extip"))[:128],
            # **端口只在 portforward 开着时才有意义。**关着时设备上这两个
            # 字段可能残留着上次的值,原样存下来会在页面上显示成一条
            # "只映射 443 的规则",而它实际上是整机映射 —— 暴露面差很多
            "ext_port": (str(item.get("extport") or "")[:64] if port_forward else ""),
            "mapped_ip": _mapped_ip_text(item.get("mappedip"))[:256],
            "mapped_port": (str(item.get("mappedport") or "")[:64] if port_forward else ""),
            "protocol": (str(item.get("protocol") or "")[:12] if port_forward else ""),
            "port_forward": port_forward,
            "comment": str(item.get("comment") or "")[:255],
            "uuid": str(item.get("uuid") or "")[:64],
            "raw": item,
        })
    return out


def parse_show_firewall_vip(text: str) -> list[dict]:
    """
    解析 FortiOS `show firewall vip`。

    和策略那个解析器同一条规矩:**默认值不会出现在输出里**。

        没有 `set portforward enable`  → 关,也就是**整机 1:1 映射**
        没有 `set protocol ...`        → tcp(但只在 portforward 开着时有意义)
        没有 `set type ...`            → static-nat

    最容易搞错的是第一条:没有 portforward 那一行时**不能**把
    `extport` / `mappedport` 当成"没解析到"而留空再显示成端口未知 ——
    它是"所有端口都进去",那是这张表里暴露面最大的一种,必须看得出来。
    """

    out: list[dict] = []
    current: dict | None = None
    seq = 0

    for line in text.replace("\r\n", "\n").split("\n"):
        if m := _RE_EDIT_NAME.match(line):
            name = m.group(1).strip()
            # `config firewall vip` 这种行也会被 edit 正则漏进来?不会 ——
            # 但空名字要挡掉,否则会造出一条名字为空、什么都指不到的映射
            if not name:
                continue
            current = {
                "name": name[:128], "seq": seq,
                # 默认值在这里给全,后面只覆盖 show 里出现的项
                "vip_type": VipType.STATIC_NAT, "ext_intf": [], "ext_ip": "",
                "ext_port": "", "mapped_ip": "", "mapped_port": "", "protocol": "",
                "port_forward": False, "comment": "", "uuid": "",
                "raw": {"_channel": "ssh"},
            }
            seq += 1
            continue

        if _RE_NEXT.match(line) and current is not None:
            # portforward 关着 = 整机映射,端口字段没有意义。设备上偶尔会
            # 残留 extport(改配置时留下的),原样存会显示成端口映射
            if not current["port_forward"]:
                current["ext_port"] = current["mapped_port"] = current["protocol"] = ""
            out.append(current)
            current = None
            continue

        if current is None:
            continue

        m = _RE_SET.match(line)
        if not m:
            continue
        key, raw_value = m.group(1).lower(), m.group(2).strip()
        values = _split_values(raw_value)
        one = values[0] if values else ""
        current["raw"][key] = raw_value

        if key == "type":
            current["vip_type"] = normalize_vip_type(one)
        elif key == "extintf":
            current["ext_intf"] = values
        elif key == "extip":
            current["ext_ip"] = raw_value.strip('"')[:128]
        elif key == "extport":
            current["ext_port"] = raw_value.strip('"')[:64]
        elif key == "mappedip":
            # `set mappedip "10.0.0.5"` 或 `set mappedip 10.0.0.5 10.0.0.6`
            current["mapped_ip"] = ", ".join(values)[:256] if values else raw_value[:256]
        elif key == "mappedport":
            current["mapped_port"] = raw_value.strip('"')[:64]
        elif key == "protocol":
            current["protocol"] = one[:12]
        elif key == "portforward":
            current["port_forward"] = one.lower() == "enable"
        elif key == "comment":
            current["comment"] = raw_value.strip('"')[:255]
        elif key == "uuid":
            current["uuid"] = one[:64]

    if current is not None:
        # 和策略那边一样:半条映射(比如缺了 mappedip)在页面上看着像
        # "映射到空",而那是个会让人下错结论的显示
        log.warning("映射输出在 edit %s 处结束但没有 next,该条被丢弃(输出被截断?)",
                    current["name"])
    return out


def _vips_from_ssh(device: Device) -> list[dict]:
    """
    SSH 通道的映射。**失败只记日志、返回空**,不抛 ——
    策略已经拿到了,不该因为映射没拿到而把整批策略一起丢掉。
    """

    profile = get_profile(device.model, device.vendor)
    if not profile.vip_cli:
        return []
    client = ssh_cli._connect(device)
    try:
        raw = ssh_cli._run_exec(client, profile.vip_cli, timeout=120.0)
    except ssh_cli.SshError as exc:
        log.info("设备 %s 映射同步失败(%s),这次只更新策略", device.name, exc)
        return []
    finally:
        client.close()
    return parse_show_firewall_vip(raw)


def _from_ssh(device: Device) -> list[dict]:
    profile = get_profile(device.model, device.vendor)
    if not profile.policy_cli:
        raise PolicyError(
            f"型号 {device.get_model_display()} 的画像没有定义策略命令 —— "
            "在 devices/profiles.py 里补 policy_cli"
        )
    if not device.ssh_username or not (device.ssh_password or device.ssh_private_key):
        raise PolicyError("SSH 通道需要 SSH 用户名 + 密码/私钥")

    client = ssh_cli._connect(device)
    try:
        raw = ssh_cli._run_exec(client, profile.policy_cli, timeout=120.0)
    except ssh_cli.SshError as exc:
        raise PolicyError(str(exc)) from exc
    finally:
        client.close()

    rows = parse_show_firewall_policy(raw)
    if not rows:
        head = raw.strip().replace("\n", " ")[:160]
        raise PolicyError(f"`{profile.policy_cli}` 没有解析出策略:{head or '(空输出)'}")
    return rows


# =========================================================================
# 主入口
# =========================================================================


def sync_policies(device: Device) -> dict:
    """
    同步一台防火墙的策略。返回统计。

    通道:有 API Token 走 API(带命中计数),失败或没有 token 退回 SSH。
    **降级会被记下来**(返回值里的 method),页面上要能看出这批数据
    有没有命中计数 —— 否则一列空白的"命中"会被当成"全都没命中过"。
    """

    if device.kind != DeviceKind.FIREWALL:
        raise PolicyError("策略同步只对防火墙有意义")
    if device.vendor != Vendor.FORTINET:
        raise PolicyError(
            f"策略同步目前只实现了 FortiGate。{device.get_vendor_display()} 的解析器"
            "要在 devices/policies.py 里补"
        )

    rows: list[dict] = []
    vips: list[dict] = []
    method = ""
    api_error = ""

    if device.api_token:
        try:
            rows = _from_api(device)
            method = "api"
            # 映射和策略走同一条通道、同一次同步 —— 两边不同步的话页面上会
            # 出现"策略引用了一个不存在的映射"或者反过来,而那看起来像
            # 设备上配错了。**映射拿不到不算失败**,策略照常写
            vips = _vips_from_api(device)
        except PolicyError as exc:
            api_error = str(exc)
            log.info("设备 %s API 策略同步失败(%s),尝试 SSH", device.name, api_error)

    if not method:
        try:
            rows = _from_ssh(device)
            method = "ssh"
            vips = _vips_from_ssh(device)
        except PolicyError as exc:
            # 两条都失败时,把 API 的错也带出来 —— 只报 SSH 的错会让人
            # 去修一条自己根本没打算用的通道
            if api_error:
                raise PolicyError(f"API:{api_error};SSH:{exc}") from exc
            raise

    truncated = False
    if len(rows) > MAX_POLICIES:
        log.warning("设备 %s 有 %d 条策略,超过上限 %d,已截断", device.name, len(rows), MAX_POLICIES)
        rows = rows[:MAX_POLICIES]
        truncated = True

    now = timezone.now()
    vdom = (device.api_vdom or "root") if method == "api" else "root"

    with transaction.atomic():
        # **全量替换。**设备上删掉的策略必须在这边消失(见模块开头)。
        # 删完重建会让主键变化,而页面是靠筛选和排序用的、不靠固定 id,
        # 所以这个代价可以接受;换成 upsert 要多一轮"哪些不见了"的比对,
        # 而漏掉一条"不见了"的后果是页面上留着一条不存在的规则
        FirewallPolicy.objects.filter(device=device, vdom=vdom).delete()
        FirewallPolicy.objects.bulk_create([
            FirewallPolicy(device=device, vdom=vdom, synced_at=now, method=method, **row)
            for row in rows
        ], batch_size=500)

        # 映射同样是全量替换,而且**和策略在同一个事务里** —— 分两个事务的话
        # 中间那一刻页面上会看到"策略引用了一个不存在的映射",看起来像
        # 设备上配错了。设备上删掉的映射也必须在这边消失,理由和策略一样:
        # 留着一条现实中不存在的映射,有人会照着它判断"这个端口是通的"
        FirewallVip.objects.filter(device=device, vdom=vdom).delete()
        if vips:
            FirewallVip.objects.bulk_create([
                FirewallVip(device=device, vdom=vdom, synced_at=now, method=method, **vip)
                for vip in vips
            ], batch_size=500)

    device.policy_count = FirewallPolicy.objects.filter(device=device).count()
    device.last_policy_sync_at = now
    device.last_policy_error = ""
    device.save(update_fields=["policy_count", "last_policy_sync_at", "last_policy_error"])

    with_hits = sum(1 for r in rows if r.get("hit_count") is not None)
    never_hit = sum(1 for r in rows if r.get("hit_count") == 0)
    return {
        "method": method,
        "total": len(rows),
        "vips": len(vips),
        # 整机映射的条数单独报 —— 它是这批数据里暴露面最大的那种,
        # 而在列表里它和一条只映射 443 的规则长得几乎一样
        "vips_whole_host": sum(1 for v in vips if not v.get("port_forward")),
        "vdom": vdom,
        "has_hit_stats": with_hits > 0,
        "never_hit": never_hit if with_hits else None,
        "disabled": sum(1 for r in rows if not r.get("enabled")),
        "truncated": truncated,
        "degraded_from_api": bool(api_error) and method == "ssh",
    }
