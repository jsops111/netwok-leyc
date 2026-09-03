"""
配置合规基线检查 —— 在**已经备份下来的配置**上跑,不需要任何新采集。

## 为什么值得单独一个模块

网络设备的配置里最容易长期躺着的东西,不是"配错了",而是**"从来没配"**:
telnet 一直开着、community 还是 `public`、口令是明文、日志没往外送、
NTP 没配所以日志时间是错的。这些东西没有任何症状 —— 设备跑得好好的,
直到出事时才发现没有可用的日志,或者审计时被一条一条挑出来。

所以这里做的是「基线」而不是「差异比对」:比对告诉你**变了什么**,
基线告诉你**缺了什么**。两个问题都要回答,而缺的那个更容易被忽略。

## 三条自律

1. **规则要能说出「怎么改」。**只报"不合规"没有用 —— 每条规则带一个
   `fix` 字段,写明该敲什么命令。一条不知道怎么修的告警等于噪声。

2. **认不出的厂商明确说"没有规则",不给一个"全部通过"。**
   通用画像的设备跑出来 0 条问题,人会以为它合规,而真相是我们没检查。
   这和「命中计数三态」是同一个道理。

3. **不猜。**只写能从配置文本可靠判断的规则。比如"ACL 是不是过宽"需要
   理解整个 ACL 的语义,没做;而"有没有 `service password-encryption`"
   是一行文本的存在与否,做得了。宁可规则少而准。

## 判定基于清洗后的文本吗?

不。**基于原始文本** —— 清洗规则(backup_volatile)去掉的是时间戳之类,
而合规检查要看的是配置本身,两者不冲突;但用原始文本能保留行号,
报出来的问题可以指到具体哪一行。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netcheck.models import Device, DeviceBackup, Severity, Vendor

# 一条规则最多报几行 —— 一个 48 口交换机上"接口没配 description"可能有 40 行,
# 全列出来会把别的问题挤出去
MAX_HITS_PER_RULE = 12


@dataclass
class Rule:
    """
    一条基线规则。

    `must_match` 有值 = 配置里**必须出现**它(缺了就是问题,这是"从来没配"
    那一类);`must_not_match` 有值 = 配置里**不允许出现**它。
    两者只能给一个。

    `fix` 是必填的:一条不知道怎么修的告警等于噪声。
    """

    key: str
    label: str
    severity: str
    fix: str
    why: str
    vendors: tuple[str, ...] = ()
    must_match: str = ""
    must_not_match: str = ""
    # 命中行里要忽略的(比如注释行)
    ignore: tuple[str, ...] = ()

    def applies_to(self, device: Device) -> bool:
        return not self.vendors or device.vendor in self.vendors


# =========================================================================
# Cisco IOS / IOS-XE
# =========================================================================

_CISCO_RULES = [
    Rule(
        key="telnet_enabled",
        label="VTY 允许 telnet 接入",
        severity=Severity.CRITICAL,
        why="telnet 是明文的 —— 管理口令会在管理网里裸奔。抓一个包就能拿到 enable 密码",
        fix="line vty 0 15 → transport input ssh(只留 ssh)",
        vendors=(Vendor.CISCO,),
        must_not_match=r"^\s*transport input\s+.*\btelnet\b",
    ),
    Rule(
        key="no_ssh_only",
        label="VTY 没有显式限制成只允许 SSH",
        severity=Severity.WARNING,
        why="没有 transport input 时各平台默认值不同,有的默认允许 telnet",
        fix="line vty 0 15 → transport input ssh",
        vendors=(Vendor.CISCO,),
        must_match=r"^\s*transport input\s+ssh\s*$",
    ),
    Rule(
        key="default_community",
        label="SNMP 用了默认/弱 community",
        severity=Severity.CRITICAL,
        why="public / private 是所有扫描器的第一个尝试。读权限就能拉走整份拓扑和接口表",
        fix="换成随机字符串,并用 ACL 限制来源:snmp-server community <随机> RO <acl>",
        vendors=(Vendor.CISCO,),
        must_not_match=r"^\s*snmp-server community\s+(public|private|cisco|admin)\b",
    ),
    Rule(
        key="snmp_no_acl",
        label="SNMP community 没有绑 ACL",
        severity=Severity.WARNING,
        why="没有 ACL 限制时,管理网里任何一台机器都能读设备信息",
        fix="snmp-server community <字符串> RO <acl 号>,再用 access-list 限定网管地址",
        vendors=(Vendor.CISCO,),
        # community 行后面只有 RO/RW 而没有 ACL 号或名字
        must_not_match=r"^\s*snmp-server community\s+\S+\s+(RO|RW)\s*$",
    ),
    Rule(
        key="plaintext_enable",
        label="用了明文的 enable password",
        severity=Severity.CRITICAL,
        why="enable password 是可逆的 type 7 或明文;enable secret 才是不可逆哈希",
        fix="enable secret <口令>,然后 no enable password",
        vendors=(Vendor.CISCO,),
        must_not_match=r"^\s*enable password\b",
    ),
    Rule(
        key="no_password_encryption",
        label="没开 service password-encryption",
        severity=Severity.WARNING,
        why="不开的话配置文件里的口令是纯明文 —— 而配置文件会被备份、会被传阅",
        fix="service password-encryption",
        vendors=(Vendor.CISCO,),
        must_match=r"^\s*service password-encryption\s*$",
    ),
    Rule(
        key="no_aaa",
        label="没有配 AAA / 本地认证",
        severity=Severity.WARNING,
        why="没有 AAA 时所有人共用一个 enable 口令,登录审计里分不出是谁操作的",
        fix="aaa new-model,再配 tacacs+/radius 或至少 local 用户",
        vendors=(Vendor.CISCO,),
        must_match=r"^\s*aaa new-model\s*$",
    ),
    Rule(
        key="http_server",
        label="ip http server 开着",
        severity=Severity.WARNING,
        why="设备的 Web 管理面是明文 HTTP,而且历史上是漏洞高发面。不用就该关",
        fix="no ip http server(要 Web 就只留 no ip http server + ip http secure-server)",
        vendors=(Vendor.CISCO,),
        must_not_match=r"^\s*ip http server\s*$",
    ),
    Rule(
        key="no_ntp",
        label="没有配 NTP 服务器",
        severity=Severity.WARNING,
        why="**时间不对的日志在排障时是废的** —— 几台设备的日志对不上时间轴就没法串事件",
        fix="ntp server <地址>(至少两个),并配 clock timezone",
        vendors=(Vendor.CISCO,),
        must_match=r"^\s*ntp server\s+\S+",
    ),
    Rule(
        key="no_syslog_host",
        label="日志没有往外送",
        severity=Severity.WARNING,
        why="设备本地日志缓冲区几百条就滚掉了。出事之后想看当时发生了什么,已经没了",
        fix="logging host <日志服务器>",
        vendors=(Vendor.CISCO,),
        must_match=r"^\s*logging (host|server)?\s*\d+\.\d+\.\d+\.\d+",
    ),
    Rule(
        key="no_exec_timeout",
        label="VTY 没有配空闲超时",
        severity=Severity.WARNING,
        why="没有超时的话一个忘了关的会话会一直挂着,而那个终端可能没锁屏",
        fix="line vty 0 15 → exec-timeout 10 0",
        vendors=(Vendor.CISCO,),
        must_match=r"^\s*exec-timeout\s+(?!0\s+0)\d+",
    ),
    Rule(
        key="exec_timeout_zero",
        label="VTY 的空闲超时被显式关掉了",
        severity=Severity.CRITICAL,
        why="exec-timeout 0 0 是「永不超时」—— 比没配更糟,因为它是有人故意关的",
        fix="改成 exec-timeout 10 0",
        vendors=(Vendor.CISCO,),
        must_not_match=r"^\s*exec-timeout\s+0\s+0\s*$",
    ),
    Rule(
        key="no_login_banner",
        label="没有配登录 banner",
        severity=Severity.INFO,
        why="很多合规要求要有「未授权访问将被追究」的告示。技术上没影响,审计上会被挑",
        fix="banner login ^C ... ^C",
        vendors=(Vendor.CISCO,),
        must_match=r"^\s*banner (login|motd)\b",
    ),
    Rule(
        key="vtp_server",
        label="VTP 工作在 server 模式",
        severity=Severity.WARNING,
        why="VTP server 上误删一个 VLAN 会传播到整个域 —— 这是经典的大面积事故起因",
        fix="vtp mode transparent(除非你确实在用 VTP 管理 VLAN)",
        vendors=(Vendor.CISCO,),
        must_not_match=r"^\s*vtp mode\s+server\b",
    ),
]

# =========================================================================
# FortiOS
# =========================================================================

_FORTIOS_RULES = [
    Rule(
        key="fg_telnet",
        label="管理接口允许 telnet",
        severity=Severity.CRITICAL,
        why="telnet 明文传管理口令",
        fix="config system interface → set allowaccess 里去掉 telnet",
        vendors=(Vendor.FORTINET,),
        must_not_match=r"^\s*set allowaccess\s+.*\btelnet\b",
    ),
    Rule(
        key="fg_http",
        label="管理接口允许明文 HTTP",
        severity=Severity.WARNING,
        why="管理面走明文 HTTP,口令和会话 cookie 都在管理网里裸奔",
        fix="set allowaccess 里去掉 http,只留 https",
        vendors=(Vendor.FORTINET,),
        must_not_match=r"^\s*set allowaccess\s+(?=[^\n]*\bhttp\b)(?![^\n]*\bhttps\b[^\n]*$)",
    ),
    Rule(
        key="fg_no_ntp",
        label="没有配 NTP",
        severity=Severity.WARNING,
        why="防火墙的日志时间不对,和交换机的日志就串不起来;而且证书校验也依赖时间",
        fix="config system ntp → set ntpsync enable",
        vendors=(Vendor.FORTINET,),
        must_match=r"^\s*set ntpsync\s+enable",
    ),
    Rule(
        key="fg_no_syslog",
        label="日志没有往外送",
        severity=Severity.WARNING,
        why="FortiGate 本地日志盘满了就滚。而防火墙日志恰恰是事后唯一能查访问来源的东西",
        fix="config log syslogd setting → set status enable + set server <地址>",
        vendors=(Vendor.FORTINET,),
        must_match=r"^\s*config log syslogd setting",
    ),
    Rule(
        key="fg_admin_timeout",
        label="没有配管理会话超时",
        severity=Severity.INFO,
        why="默认 5 分钟通常够用,显式配出来是为了让它不被人改大之后没人发现",
        fix="config system global → set admintimeout 10",
        vendors=(Vendor.FORTINET,),
        must_match=r"^\s*set admintimeout\s+\d+",
    ),
]

RULES: list[Rule] = _CISCO_RULES + _FORTIOS_RULES

# 有规则的厂商。**不在这里面的厂商要明确说"没有规则"**,
# 而不是报一个 0 条问题的"全部通过"
SUPPORTED_VENDORS = {Vendor.CISCO, Vendor.FORTINET}


# =========================================================================
# 执行
# =========================================================================


def _lines(text: str) -> list[tuple[int, str]]:
    """(行号从 1 起, 行内容)。行号要能报出去 —— 指到具体一行才好改。"""

    return list(enumerate(text.replace("\r\n", "\n").split("\n"), start=1))


def check_config(text: str, device: Device) -> list[dict]:
    """
    对一份配置文本跑所有适用的规则。返回不合规项的清单。

    **合规的规则不返回** —— 页面上要的是"待办清单",不是一份两百行的
    逐条清单。合规数量单独给一个计数。
    """

    numbered = _lines(text)
    findings: list[dict] = []

    for rule in RULES:
        if not rule.applies_to(device):
            continue
        pattern = re.compile(rule.must_not_match or rule.must_match, re.I | re.M)

        if rule.must_not_match:
            hits = [(n, ln.strip()) for n, ln in numbered if pattern.search(ln)]
            if not hits:
                continue
            findings.append({
                "key": rule.key, "label": rule.label, "severity": rule.severity,
                "why": rule.why, "fix": rule.fix, "kind": "present",
                "hit_count": len(hits),
                "hits": [{"line": n, "text": t} for n, t in hits[:MAX_HITS_PER_RULE]],
            })
        else:
            # "必须出现"的规则:整份配置里一次都没出现才算问题
            if any(pattern.search(ln) for _n, ln in numbered):
                continue
            findings.append({
                "key": rule.key, "label": rule.label, "severity": rule.severity,
                "why": rule.why, "fix": rule.fix, "kind": "missing",
                "hit_count": 0, "hits": [],
            })

    order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 3), f["label"]))
    return findings


def check_device(device: Device) -> dict:
    """
    对一台设备的**最新一个配置版本**跑基线检查。

    没有备份就没法检查 —— 那时明确返回 `supported/checked` 的原因,
    而不是一个 0 条问题的结果。**"没检查"和"没问题"必须分得开。**
    """

    latest = DeviceBackup.objects.filter(device=device).order_by("-ts").first()
    applicable = [r for r in RULES if r.applies_to(device)]

    base = {
        "device_id": device.pk,
        "device_name": device.name,
        "mgmt_ip": device.mgmt_ip,
        "vendor": device.vendor,
        "vendor_label": device.get_vendor_display(),
        "model_label": device.get_model_display(),
        "kind": device.kind,
        "rule_count": len(applicable),
        "backup_at": latest.ts if latest else None,
        "backup_hash": latest.short_hash if latest else "",
    }

    if device.vendor not in SUPPORTED_VENDORS:
        return {
            **base, "supported": False, "checked": False,
            "reason": (
                f"{device.get_vendor_display()} 还没有基线规则 —— "
                "**这不等于合规**,只是没检查。规则在 devices/compliance.py 里加"
            ),
            "findings": [], "critical": 0, "warning": 0, "info": 0, "passed": 0,
        }
    if latest is None:
        return {
            **base, "supported": True, "checked": False,
            "reason": "这台设备还没有配置备份 —— 基线检查是在备份下来的配置上跑的",
            "findings": [], "critical": 0, "warning": 0, "info": 0, "passed": 0,
        }

    findings = check_config(latest.content, device)
    return {
        **base, "supported": True, "checked": True, "reason": "",
        "findings": findings,
        "critical": sum(1 for f in findings if f["severity"] == Severity.CRITICAL),
        "warning": sum(1 for f in findings if f["severity"] == Severity.WARNING),
        "info": sum(1 for f in findings if f["severity"] == Severity.INFO),
        "passed": len(applicable) - len(findings),
    }


# =========================================================================
# 事件
# =========================================================================


def problems_for_events(result: dict) -> list[dict]:
    """
    基线检查结果 → 事件引擎要的 problems。

    **只出一条** `compliance_fail`(级别取最高的那条发现),消息里带上
    "多少条 + 前几条是什么"。理由:一台设备上不合规的项通常是一批
    (telnet 开着、community 是 public、日志没外送往往同时出现),
    每一项开一条事件会在事件表里刷出一屏,而**它们要做的是同一件事** ——
    登上去改一遍配置。

    **`checked=False` 时返回空列表,不是"没问题"** —— 没检查过的设备不该
    因为"没有发现"而把一条已经开着的事件关掉。这一条和
    「认不出的厂商明确说没有规则」是同一个道理。
    """

    if not result.get("checked"):
        return []

    findings = result.get("findings") or []
    if not findings:
        return []

    from netcheck.models import EventKind, Severity

    crit = [f for f in findings if f.get("severity") == "critical"]
    warn = [f for f in findings if f.get("severity") == "warning"]
    # info 级的发现**不开事件** —— 它们是"可以更好",不是"有问题",
    # 开成事件会让未恢复列表里常年挂着几条没人会去处理的
    if not crit and not warn:
        return []

    top = (crit or warn)[:3]
    names = "、".join(f.get("title") or f.get("id") or "?" for f in top)
    more = len(crit) + len(warn) - len(top)
    return [{
        "kind": EventKind.COMPLIANCE_FAIL,
        "severity": Severity.CRITICAL if crit else Severity.WARNING,
        "value": float(len(crit) + len(warn)),
        "threshold": None,
        "unit": "项",
        "message": (
            f"配置基线有 {len(crit)} 项严重 / {len(warn)} 项警告:{names}"
            + (f" 等 {more} 项" if more > 0 else "")
            + "。到「配置合规」页看每条该敲什么命令"
        ),
    }]
