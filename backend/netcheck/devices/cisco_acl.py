"""
Cisco 的**访问控制**解析 —— 纯函数,不碰网络也不碰库。

三样东西,和 FortiGate 那三样一一对应:

| FortiGate | Cisco IOS | Cisco ASA/FTD |
|---|---|---|
| `firewall policy` | `ip access-list` 里的 ACE | `access-list` |
| `firewall vip` | `ip nat inside source static` | `object network ... nat` |
| `firewall address` / `addrgrp` | `object-group network` | 同左 |

## ⚠ 三个会静默出错的地方

### 1. IOS 的 ACL 用**通配符掩码**,而 object-group 用**子网掩码**

    access-list  ... 10.0.0.0 0.0.0.255      ← 通配符,= /24
    object-group ... 10.0.0.0 255.255.255.0  ← 子网掩码,= /24

**同一台设备上两种掩码混着用。**把通配符 `0.0.0.255` 当成子网掩码去算,
得到的是 `/0`(全网);反过来把 `255.255.255.0` 当通配符算,得到的是
`/24` 的补集。两种错都会在页面上显示成一个**看起来完全正常的网段**,
而它和实际范围差着几个数量级。

ASA 的 access-list 用的是**子网掩码**,和 IOS 相反 —— 所以解析器要知道
自己在解哪一种。

### 2. 每个 ACL 末尾有一条**隐含的 `deny ip any any`**,它不出现在输出里

不把它补出来的话:
  - 影子规则判定会漏掉"这条规则后面其实什么都到不了"
  - 人看着一张全是 permit 的表,会以为没写到的流量是放行的

补出来的那一条**必须标成 `implicit`**,否则人会去设备上找这一行然后找不到。

### 3. ACL 只是一张表,**它作用在哪要另查**

FortiGate 的一条策略自带源/目的接口对;ACL 不带 —— 绑定关系在
`ip access-group <name> in|out` 里。不拼上去的话页面上是一堆不知道
作用在哪儿的规则,人会以为它在全局生效。

而**一个 ACL 可以一个接口都没绑** —— 那意味着它**完全不生效**。
那是个该被看见的结论,和"我们没查到绑定"是两回事。
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------- 掩码


def wildcard_to_cidr(addr: str, wildcard: str) -> str:
    """
    `10.0.0.0 0.0.0.255` → `10.0.0.0/24`。**通配符是反的**(见模块开头第 1 条)。

    通配符里的 1 表示"这一位不管",所以前缀长度 = 32 - 通配符里 1 的个数。

    **非连续通配符返回原文**(`0.0.255.0` 这种"隔一段管一段"是合法的 IOS
    写法,常见于按奇偶网段匹配)—— 硬折成一个前缀长度会把一条精巧的规则
    显示成一个平平无奇的网段。
    """

    try:
        octets = [int(x) for x in wildcard.split(".")]
    except ValueError:
        return f"{addr} {wildcard}"
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        return f"{addr} {wildcard}"

    bits = "".join(f"{o:08b}" for o in octets)
    # 通配符的合法形状是"前面全 0、后面全 1";出现 10 就是非连续
    if "10" in bits:
        return f"{addr} wildcard {wildcard}"
    return f"{addr}/{32 - bits.count('1')}"


def netmask_to_cidr(addr: str, mask: str) -> str:
    """
    `10.0.0.0 255.255.255.0` → `10.0.0.0/24`。

    **和 `wildcard_to_cidr()` 是两个函数,不要合并** —— 合并意味着要靠
    "看起来像哪种"去猜,而 `255.0.0.0` 和 `0.255.255.255` 都是合法的、
    含义相反的东西。**由调用方按上下文决定用哪个**(IOS 的 ACL 用通配符、
    object-group 用子网掩码;ASA 的 ACL 用子网掩码)。
    """

    try:
        octets = [int(x) for x in mask.split(".")]
    except ValueError:
        return f"{addr} {mask}"
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        return f"{addr} {mask}"
    bits = "".join(f"{o:08b}" for o in octets)
    if "01" in bits:
        return f"{addr} mask {mask}"
    return f"{addr}/{bits.count('1')}"


# ---------------------------------------------------------------- ACL

_RE_ACL_HEADER = re.compile(
    r"^(Standard|Extended|Reflexive)\s+(?:IP|IPv6)\s+access\s+list\s+(\S+)", re.I)
_RE_MATCHES = re.compile(r"\((\d+)\s+matches?\)")
_RE_SEQ = re.compile(r"^\s*(\d+)\s+(permit|deny)\s+(.*)$", re.I)
# ASA:`access-list NAME line 1 extended permit tcp any host 1.2.3.4 eq https (hitcnt=421)`
_RE_ASA = re.compile(
    r"^access-list\s+(\S+)\s+line\s+(\d+)\s+(?:extended\s+|standard\s+)?"
    r"(permit|deny)\s+(.*?)(?:\s+\(hitcnt=(\d+)\))?(?:\s+0x\w+)?\s*$", re.I)

_PORT_OPS = ("eq", "neq", "lt", "gt", "range")


def _take_endpoint(tokens: list[str], i: int, netmask: bool) -> tuple[str, int]:
    """
    从 token 流里取一个"地址"。返回 (人话的地址, 下一个下标)。

    IOS 的地址有四种写法:
        any                      → 任意
        host 10.0.0.1            → /32
        10.0.0.0 0.0.0.255       → 通配符(IOS ACL)
        10.0.0.0 255.255.255.0   → 子网掩码(ASA ACL / object-group)
        object-group NAME        → 引用一个组

    `netmask` 决定第三种按哪个解 —— **这个开关必须由调用方给**,
    猜不得(见 `netmask_to_cidr` 的说明)。
    """

    if i >= len(tokens):
        return "any", i
    token = tokens[i].lower()

    if token == "any" or token.startswith("any"):
        return "any", i + 1
    if token == "host" and i + 1 < len(tokens):
        return f"{tokens[i + 1]}/32", i + 2
    if token in ("object-group", "object") and i + 1 < len(tokens):
        # **组名原样带出来** —— 展开是 addresses.resolve() 的事,
        # 在这儿展开的话同一个组会在每条规则里重复一遍
        return tokens[i + 1], i + 2
    if token == "interface" and i + 1 < len(tokens):
        return f"interface {tokens[i + 1]}", i + 2

    # 地址 + 掩码
    if i + 1 < len(tokens) and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[i + 1] or ""):
        convert = netmask_to_cidr if netmask else wildcard_to_cidr
        return convert(tokens[i], tokens[i + 1]), i + 2
    return tokens[i], i + 1


def _take_port(tokens: list[str], i: int) -> tuple[str, int]:
    """端口条件。`eq 443` / `range 8080 8090` / `gt 1023`。没有就返回空。"""

    if i >= len(tokens):
        return "", i
    op = tokens[i].lower()
    if op not in _PORT_OPS:
        return "", i
    if op == "range" and i + 2 < len(tokens):
        return f"{tokens[i + 1]}-{tokens[i + 2]}", i + 3
    if i + 1 < len(tokens):
        # eq 可以跟多个端口:`eq 80 443 8080`
        ports = []
        j = i + 1
        while j < len(tokens) and not tokens[j].lower() in (
            "log", "log-input", "established", "fragments", "precedence", "dscp",
        ):
            ports.append(tokens[j])
            j += 1
            if op != "eq":
                break
        prefix = "" if op == "eq" else f"{op} "
        return prefix + ",".join(ports), j
    return op, i + 1


def _parse_ace_body(body: str, netmask: bool) -> dict:
    """
    一条 ACE 的主体(动作后面那一串)→ 协议 / 源 / 目的 / 服务。

    形状:`<协议> <源> [源端口] <目的> [目的端口] [log] [established] …`
    标准 ACL 只有源:`permit 192.168.1.0, wildcard bits 0.0.0.255`
    """

    clean = body.replace(",", " ").replace("wildcard bits", "")
    tokens = [t for t in clean.split() if t]
    out = {"protocol": "", "src": "any", "dst": "any",
           "src_port": "", "dst_port": "", "log": False}
    if not tokens:
        return out

    # 标准 ACL:第一个 token 就是地址(没有协议)
    first = tokens[0].lower()
    known_proto = first in (
        "ip", "tcp", "udp", "icmp", "gre", "esp", "ahp", "eigrp", "ospf",
        "pim", "sctp", "igmp", "ipinip", "nos", "object-group",
    ) or first.isdigit()

    i = 0
    if known_proto and first != "object-group":
        out["protocol"] = tokens[0].upper()
        i = 1
    elif not known_proto:
        # 标准 ACL:只有源地址,**目的是 any** —— 不要留空,
        # 空的地址栏在页面上看着像"没限制",而这里它确实是 any,
        # 但那是因为标准 ACL 根本不看目的,不是因为没解析出来
        out["protocol"] = "IP"
        src, _ = _take_endpoint(tokens, 0, netmask)
        out["src"] = src
        out["log"] = "log" in [t.lower() for t in tokens]
        return out

    out["src"], i = _take_endpoint(tokens, i, netmask)
    out["src_port"], i = _take_port(tokens, i)
    out["dst"], i = _take_endpoint(tokens, i, netmask)
    out["dst_port"], i = _take_port(tokens, i)
    out["log"] = any(t.lower().startswith("log") for t in tokens[i:])
    return out


def _service_text(parsed: dict) -> str:
    """协议 + 目的端口 → 服务列那一格。`TCP/443` / `IP`(所有)。"""

    proto = parsed["protocol"] or "IP"
    if parsed["dst_port"]:
        return f"{proto}/{parsed['dst_port']}"
    return proto


def parse_ios_acl(text: str) -> list[dict]:
    """
    解析 `show ip access-lists`(IOS / IOS-XE)。

    **每个 ACL 末尾补一条隐含的 `deny ip any any`**(标 `implicit=True`)——
    见模块开头第 2 条。

    **IOS 的 ACL 用通配符掩码**,所以这里 `netmask=False`。
    """

    out: list[dict] = []
    acl = ""
    seq_fallback = 0

    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if not line.strip():
            continue

        if m := _RE_ACL_HEADER.match(line.strip()):
            if acl:
                out.append(_implicit_deny(acl, seq_fallback))
            acl = m.group(2)
            seq_fallback = 0
            continue
        if not acl:
            continue

        hits = int(mh.group(1)) if (mh := _RE_MATCHES.search(line)) else None
        body = _RE_MATCHES.sub("", line).strip()

        m = _RE_SEQ.match(body)
        if m:
            seq, action, rest = int(m.group(1)), m.group(2).lower(), m.group(3)
        else:
            m2 = re.match(r"^\s*(permit|deny)\s+(.*)$", body, re.I)
            if not m2:
                continue
            # 没有行号的老格式:自己编,**从 10 起、步长 10**,和 IOS 自动
            # 编号的习惯一致 —— 编成 1,2,3 的话和设备上看到的对不上
            seq_fallback += 10
            seq, action, rest = seq_fallback, m2.group(1).lower(), m2.group(2)
        seq_fallback = max(seq_fallback, seq)

        parsed = _parse_ace_body(rest, netmask=False)
        out.append(_ace_row(acl, seq, action, parsed, hits))

    if acl:
        out.append(_implicit_deny(acl, seq_fallback))
    return out


def parse_asa_acl(text: str) -> list[dict]:
    """
    解析 ASA / FTD 的 `show access-list`。

    **ASA 用子网掩码,不是通配符** —— 和 IOS 相反(模块开头第 1 条),
    所以这里 `netmask=True`。

    ASA 会把引用 object-group 的一行**展开成多行**(每行一个组合),
    展开出来的行带同一个 `line N`。这里**按 line 去重**,只留第一条 ——
    展开的几十行在页面上是噪声,而人要看的是配置里那一行。
    """

    out: list[dict] = []
    seen: set[tuple[str, int]] = set()
    acls: set[str] = set()

    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if not line or line.startswith("access-list") is False:
            continue
        m = _RE_ASA.match(line)
        if not m:
            continue
        acl, seq, action, body, hits = (
            m.group(1), int(m.group(2)), m.group(3).lower(), m.group(4), m.group(5))
        key = (acl, seq)
        if key in seen:
            continue
        seen.add(key)
        acls.add(acl)
        parsed = _parse_ace_body(body, netmask=True)
        out.append(_ace_row(acl, seq, action, parsed, int(hits) if hits else None))

    # **ASA 也有隐含 deny**,而且它同样不出现在 show 里
    for acl in sorted(acls):
        last = max((r["policy_id"] for r in out if r["acl_name"] == acl), default=0)
        out.append(_implicit_deny(acl, last))
    return out


def _ace_row(acl: str, seq: int, action: str, parsed: dict, hits: int | None) -> dict:
    return {
        "acl_name": acl[:128],
        "policy_id": seq,
        "name": "",
        "src_addr": [parsed["src"]],
        "dst_addr": [parsed["dst"]],
        "service": [_service_text(parsed)],
        "action": "accept" if action == "permit" else "deny",
        "enabled": True,
        "nat": False,
        # **只有写了 log 的才算记日志。**IOS 的 ACE 默认不记 ——
        # 和 FortiOS 的 logtraffic 语义一致,所以审计那条规则能直接复用
        "log_traffic": "all" if parsed["log"] else "",
        "comments": "",
        "implicit": False,
        # ⚠ **IOS 的 matches 是自设备启动以来的累计**,而且 `clear ip
        # access-list counters` 会归零 —— 和 FortiGate 的 hit_count 语义
        # 接近但不完全一样。取不到时留 None(不是 0)
        "hit_count": hits,
        "raw": {"_channel": "ssh", "_vendor": "cisco",
                "protocol": parsed["protocol"], "src_port": parsed["src_port"]},
    }


def _implicit_deny(acl: str, last_seq: int) -> dict:
    """
    补出来的那条隐含 `deny ip any any`。

    **`policy_id` 排在最后一条真规则之后**,这样页面上和审计里的顺序
    和设备上的匹配顺序一致 —— 影子规则判定完全依赖这个顺序。
    """

    row = _ace_row(acl, last_seq + 1, "deny",
                   {"protocol": "IP", "src": "any", "dst": "any",
                    "src_port": "", "dst_port": "", "log": False}, None)
    row["implicit"] = True
    row["comments"] = "隐含规则:每个 ACL 末尾都有,不出现在 show 的输出里"
    return row


# ---------------------------------------------------------------- 接口绑定

_RE_IOS_BIND = re.compile(r"^\s*ip\s+access-group\s+(\S+)\s+(in|out)\b", re.I)
_RE_IOS_IF = re.compile(r"^\s*interface\s+(\S+)", re.I)
_RE_ASA_BIND = re.compile(
    r"^\s*access-group\s+(\S+)\s+(in|out|global)\s*(?:interface\s+(\S+))?", re.I)


def parse_access_groups(text: str) -> dict[str, list[dict]]:
    """
    `show running-config`(或它的 `| include` 片段)→ {ACL 名: [绑定]}。

    IOS 是**按接口块**写的:

        interface GigabitEthernet1/0/1
         ip access-group ACL-DMZ-IN in

    所以要记住"当前在哪个 interface 块里" —— 只 grep `access-group` 那一行
    的话拿不到接口名,而**没有接口名的绑定等于没有绑定**。

    ASA 是一行写完:`access-group OUTSIDE-IN in interface outside`。
    """

    out: dict[str, list[dict]] = {}
    current_if = ""
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if m := _RE_IOS_IF.match(line):
            current_if = m.group(1)
            continue
        # 顶格的非 interface 行 = 出了接口块
        if line and not line.startswith((" ", "\t")) and not _RE_ASA_BIND.match(line):
            if not _RE_IOS_IF.match(line):
                current_if = ""

        if m := _RE_ASA_BIND.match(line):
            acl, direction, iface = m.group(1), m.group(2).lower(), m.group(3)
            out.setdefault(acl, []).append(
                {"interface": iface or "global", "direction": direction})
            continue
        if m := _RE_IOS_BIND.match(line):
            acl, direction = m.group(1), m.group(2).lower()
            # **接口名拿不到时也要记一条**,但标明未知 —— 丢掉的话
            # 页面上这个 ACL 会显示成"没绑在任何接口上"(= 不生效),
            # 那是个完全相反的结论
            out.setdefault(acl, []).append(
                {"interface": current_if or "未知接口", "direction": direction})
    return out


# ---------------------------------------------------------------- 对象组

_RE_OG = re.compile(
    r"^\s*object-group\s+(network|service|protocol)\s+(\S+)(?:\s+(\S+))?", re.I)
_RE_OBJ_NET = re.compile(r"^\s*object\s+network\s+(\S+)", re.I)


def parse_object_groups(text: str) -> list[dict]:
    """
    `show running-config | section object-group` → 地址组 / 服务组。

    字段和 `FirewallAddress` / `FirewallService` 对齐,这样上层和
    `devices/addresses.resolve()` 一行都不用改 —— 递归展开、环检测、
    "查不到 ≠ 不存在" 那一整套直接复用。

    ⚠ **object-group 里用的是子网掩码,不是通配符**(模块开头第 1 条)——
    同一台设备上 ACL 用通配符、object-group 用子网掩码,这是 Cisco 的
    历史包袱,不是笔误。

        object-group network DMZ-SERVERS
         host 10.0.1.11
         10.0.2.0 255.255.255.0        ← 子网掩码
         group-object OTHER-GROUP      ← 组套组
         description 对外服务器

    ASA 的 `object network NAME` 是**单个对象**(不是组),它下面跟
    `host` / `subnet` / `range` / `fqdn`。
    """

    addresses: list[dict] = []
    services: list[dict] = []
    current: dict | None = None
    kind = ""

    def flush():
        nonlocal current, kind
        if current is None:
            return
        (services if kind == "service" else addresses).append(current)
        current, kind = None, ""

    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if not line.strip():
            continue

        if m := _RE_OG.match(line):
            flush()
            kind = m.group(1).lower()
            name = m.group(2)
            # `object-group service WEB-PORTS tcp` —— 第三个 token 是协议
            proto = (m.group(3) or "").upper()
            current = {
                "name": name[:128], "is_group": True, "members": [],
                "value": "", "comment": "",
                **({"protocol": proto} if kind == "service" else {"addr_type": "group"}),
            }
            continue

        if m := _RE_OBJ_NET.match(line):
            # ASA 的单个对象。**不是组** —— is_group=False
            flush()
            kind = "network"
            current = {
                "name": m.group(1)[:128], "is_group": False, "members": [],
                "value": "", "comment": "", "addr_type": "ipmask",
            }
            continue

        if current is None:
            continue
        # 顶格 = 出了这个块
        if not line.startswith((" ", "\t")):
            flush()
            continue

        body = line.strip()
        low = body.lower()

        if low.startswith("description "):
            current["comment"] = body[12:].strip()[:255]
        elif low.startswith("group-object "):
            # 组套组 —— 成员名原样带出来,展开是 resolve() 的事
            current["members"].append(body.split(None, 1)[1].strip())
        elif low.startswith("network-object object "):
            current["members"].append(body.split()[-1])
        elif low.startswith("network-object ") or low.startswith("host "):
            tokens = body.split()
            if tokens[0].lower() == "network-object":
                tokens = tokens[1:]
            # **子网掩码,不是通配符**
            addr, _ = _take_endpoint(tokens, 0, netmask=True)
            current["members"].append(addr)
        elif low.startswith("subnet "):
            tokens = body.split()[1:]
            current["value"] = netmask_to_cidr(tokens[0], tokens[1]) if len(tokens) > 1 else tokens[0]
        elif low.startswith("range "):
            tokens = body.split()[1:]
            current["value"] = "-".join(tokens[:2])
            current["addr_type"] = "iprange"
        elif low.startswith("fqdn "):
            current["value"] = body.split(None, 1)[1].strip().replace("v4 ", "")
            current["addr_type"] = "fqdn"
        elif low.startswith("port-object ") or low.startswith("service-object "):
            tokens = body.split()[1:]
            proto = current.get("protocol") or ""
            if tokens and tokens[0].lower() in ("tcp", "udp", "tcp-udp", "icmp", "ip"):
                proto = tokens[0].upper()
                tokens = tokens[1:]
            port, _ = _take_port(tokens, 0) if tokens else ("", 0)
            current["members"].append(f"{proto}/{port}" if port else proto or body)
        elif re.match(r"^\d+\.\d+\.\d+\.\d+", body):
            addr, _ = _take_endpoint(body.split(), 0, netmask=True)
            current["members"].append(addr)

    flush()

    # `object network` 那种单个对象:成员为空、value 有值
    for a in addresses:
        if not a["is_group"] and not a["value"] and a["members"]:
            a["value"] = a["members"][0]
            a["members"] = []
        # 组的 value 留空(展开由 resolve 做),单个对象的 members 留空
        if a["is_group"]:
            a["value"] = ""
    for s in services:
        s["value"] = "" if s["is_group"] else ", ".join(s["members"])
    return [*({**a, "_kind": "address"} for a in addresses),
            *({**s, "_kind": "service"} for s in services)]


# ---------------------------------------------------------------- NAT(映射)

# IOS:`ip nat inside source static tcp 10.0.1.11 443 203.0.113.10 443 extendable`
#      `ip nat inside source static 10.0.1.20 203.0.113.11`
_RE_IOS_NAT = re.compile(
    r"^\s*ip\s+nat\s+inside\s+source\s+static\s+"
    r"(?:(tcp|udp)\s+)?"
    r"(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?\s+"
    r"(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?", re.I)
# ASA:`nat (inside,outside) static 203.0.113.10 service tcp 443 8443`
_RE_ASA_NAT = re.compile(
    r"^\s*nat\s+\(([^,]+),([^)]+)\)\s+static\s+(\S+)"
    r"(?:\s+service\s+(tcp|udp)\s+(\S+)\s+(\S+))?", re.I)


def parse_nat(text: str) -> list[dict]:
    """
    静态 NAT(映射)→ 字段和 `FirewallVip` 对齐。

    两种写法:

        IOS:  ip nat inside source static tcp 10.0.1.11 443 203.0.113.10 443
              ↑ **内网在前、外网在后**

        ASA:  object network WEB-SERVER
               host 10.0.1.11
               nat (inside,outside) static 203.0.113.10 service tcp 443 8443
              ↑ 内网地址在上面那个 object 里,这一行只有外网地址

    ⚠ **IOS 那条命令的顺序是"内 → 外",而 FortiGate 的 VIP 是"外 → 内"。**
    照着位置抄反的话,页面上会把内网地址显示成外网入口 —— 那条映射看起来
    像是把公网地址映射进了内网,方向完全相反。

    ⚠ **没写端口 = 整机映射**(所有端口),和 FortiOS 的 `portforward` 关着
    是同一件事 —— 显示成空白或 0 都是错的(见 models.FirewallVip)。
    """

    out: list[dict] = []
    seq = 0
    current_obj = ""
    obj_host = ""

    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if not line.strip():
            continue

        if m := _RE_OBJ_NET.match(line):
            current_obj, obj_host = m.group(1), ""
            continue
        if current_obj and re.match(r"^\s+host\s+\d", line):
            obj_host = line.split()[-1]
            continue

        if m := _RE_IOS_NAT.match(line):
            proto, inside_ip, inside_port, outside_ip, outside_port = m.groups()
            port_forward = bool(proto and inside_port)
            out.append({
                "name": f"{outside_ip}:{outside_port or 'any'}"[:128],
                "seq": seq, "vip_type": "static-nat",
                "ext_intf": [], 
                # **外网在前** —— IOS 命令里它排在后面,别抄反了
                "ext_ip": outside_ip[:128],
                "ext_port": (outside_port or "") if port_forward else "",
                "mapped_ip": inside_ip[:256],
                "mapped_port": (inside_port or "") if port_forward else "",
                "protocol": (proto or "").lower() if port_forward else "",
                "port_forward": port_forward,
                "comment": "IOS 静态 NAT", "uuid": "",
                "raw": {"_channel": "ssh", "_vendor": "cisco", "_line": line.strip()},
            })
            seq += 1
            continue

        if m := _RE_ASA_NAT.match(line):
            inside_if, outside_if, mapped, proto, real_port, mapped_port = m.groups()
            port_forward = bool(proto and mapped_port)
            out.append({
                "name": (current_obj or mapped)[:128], "seq": seq,
                "vip_type": "static-nat",
                "ext_intf": [outside_if.strip()],
                "ext_ip": mapped[:128],
                "ext_port": (mapped_port or "") if port_forward else "",
                # ASA 的内网地址在上面那个 object 的 host 行里 ——
                # **拿不到时留空并说明**,不要拿映射地址凑
                "mapped_ip": (obj_host or "")[:256],
                "mapped_port": (real_port or "") if port_forward else "",
                "protocol": (proto or "").lower() if port_forward else "",
                "port_forward": port_forward,
                "comment": f"ASA 静态 NAT({inside_if.strip()} → {outside_if.strip()})"
                           + ("" if obj_host else";内网地址没解析到"),
                "uuid": "",
                "raw": {"_channel": "ssh", "_vendor": "cisco", "_line": line.strip()},
            })
            seq += 1
    return out
