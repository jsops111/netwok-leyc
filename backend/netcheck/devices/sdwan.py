"""
SD-WAN 性能 SLA 的解析 —— **纯函数,不碰网络也不碰库**。

## 它和线路拨测测的不是同一段

`ProbeTarget` 的 latency / loss / jitter 是**这个平台自己**从部署点探出来的;
这里的三个数是**防火墙自己**从它的出口探出来的(FortiOS 的 health-check,
默认 500ms 一拍)。

同一条运营商线路,两边测出来的数**不一样是正常的** —— 路径不同。而两边
都有才分得清:防火墙侧正常而平台侧不通 = 我们到防火墙这一段的问题;
两边都不通 = 那条线路真的断了。**这一页不是拨测的替代,是另一个视角。**

## 主判据是设备自己算的 `sla_targets_met`

FortiOS 允许一个健康检查配**多档 SLA**(sla 1 要求 100ms、sla 2 要求 200ms),
选路按档走。**它比我们更清楚它按哪一档选路**,所以"达标没达标"以它为准,
平台不重算一遍。平台自己那条额外判据(`Device.sla_latency_warn_ms`)是给
"设备说达标但数字已经很难看"那种情况准备的 —— FortiOS 的门限常常配得很松。

## 不通的那一拍,延迟/抖动留 None

和拨测那条规矩完全一样:**写 0 会把平均延迟拉低,图上看着比实际情况好**。
丢包率例外,不通时是 100。
"""

from __future__ import annotations

import re


def _num(value):
    """数字字段。**取不到返回 None,不返回 0** —— 0 是一个有含义的读数。"""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().replace("%", "").replace("ms", "")
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def _int(value):
    v = _num(value)
    return int(v) if v is not None else None


def parse_health_check(payload) -> list[dict]:
    """
    `GET /api/v2/monitor/virtual-wan/health-check` → 每条链路一行。

    响应形状在小版本间有出入,**三种都要认**(和 `_extract_usage()` 同一条
    规矩 —— 只认一种的话升级固件后这一页会静默变空):

        {"results": {"检查名": {"wan1": {...}, "wan2": {...}}}}
        {"results": [{"name": "检查名", "members": [{"interface": "wan1", ...}]}]}
        {"results": [{"name": ..., "interface": "wan1", ...}]}   # 已经拍平的

    每一行返回:
        health_check / member / server / protocol / state /
        latency_ms / jitter_ms / loss_pct /
        sla_met / sla_targets_met / sla_targets_total /
        tx_bps / rx_bps / session_count
    """

    results = payload.get("results") if isinstance(payload, dict) else payload
    rows: list[dict] = []

    if isinstance(results, dict):
        # 形状一:{检查名: {成员名: {...}}}
        for check_name, members in results.items():
            if not isinstance(members, dict):
                continue
            for member_name, data in members.items():
                if isinstance(data, dict):
                    rows.append(_one(check_name, member_name, data))
    elif isinstance(results, list):
        for item in results:
            if not isinstance(item, dict):
                continue
            check_name = str(item.get("name") or item.get("health_check") or "")
            members = item.get("members") or item.get("member")
            if isinstance(members, list):
                # 形状二:成员在 members 数组里
                for data in members:
                    if isinstance(data, dict):
                        rows.append(_one(
                            check_name,
                            str(data.get("interface") or data.get("name") or ""),
                            data,
                        ))
            elif isinstance(members, dict):
                for member_name, data in members.items():
                    if isinstance(data, dict):
                        rows.append(_one(check_name, member_name, data))
            else:
                # 形状三:已经拍平了
                member_name = str(item.get("interface") or item.get("member") or "")
                if member_name:
                    rows.append(_one(check_name, member_name, item))

    # 成员名或检查名为空的丢掉 —— 它们是唯一键的一半,空的存不进去,
    # 而且在页面上是一行没法定位的数据
    return [r for r in rows if r["health_check"] and r["member"]]


def _one(check_name: str, member_name: str, data: dict) -> dict:
    """一条链路。字段名在版本间有别名,逐个兜。"""

    def pick(*names):
        for n in names:
            if n in data and data[n] not in (None, ""):
                return data[n]
        return None

    alive = pick("status", "state", "alive")
    if isinstance(alive, bool):
        state = "alive" if alive else "dead"
    else:
        text = str(alive or "").strip().lower()
        # **认不出就是 unknown,不是 alive** —— 「这一拍没读到」和
        # 「它是通的」是两个结论
        state = {"alive": "alive", "up": "alive", "1": "alive",
                 "dead": "dead", "down": "dead", "0": "dead"}.get(text, "unknown")

    latency = _num(pick("latency", "latency_ms"))
    jitter = _num(pick("jitter", "jitter_ms"))
    loss = _num(pick("packet_loss", "packetloss", "loss", "packet_loss_pct"))

    if state == "dead":
        # **不通的那一拍延迟/抖动留 None,丢包给 100** —— 和拨测同一条规矩。
        # 设备在 dead 时往往还回着上一次的延迟值,原样存下来会让
        # 一条已经断了的线在图上显示成"延迟很正常"
        latency = jitter = None
        loss = 100.0

    targets_met = _int(pick("sla_targets_met", "sla_map", "sla"))
    targets_total = _int(pick("sla_targets", "sla_targets_total", "num_sla"))

    # 达标判定**以设备为准**。它没报就是 None —— 显示成"达标"等于替它
    # 做一个它没做的判断
    sla_met = None
    explicit = pick("sla_met", "in_sla")
    if isinstance(explicit, bool):
        sla_met = explicit
    elif targets_met is not None:
        sla_met = targets_met > 0
    elif state == "dead":
        # 不通当然不达标 —— 这一条不需要设备告诉我们
        sla_met = False

    return {
        "health_check": str(check_name).strip()[:64],
        "member": str(member_name).strip()[:64],
        "server": str(pick("server", "target", "dst") or "")[:255],
        "protocol": str(pick("protocol", "probe_protocol") or "")[:16],
        "state": state,
        "latency_ms": round(latency, 3) if latency is not None else None,
        "jitter_ms": round(jitter, 3) if jitter is not None else None,
        "loss_pct": round(loss, 2) if loss is not None else None,
        "sla_met": sla_met,
        "sla_targets_met": targets_met,
        "sla_targets_total": targets_total,
        "tx_bps": _num(pick("tx_bandwidth", "bandwidth_up", "tx_bw")),
        "rx_bps": _num(pick("rx_bandwidth", "bandwidth_down", "rx_bw")),
        "session_count": _int(pick("session", "session_count", "sessions")),
        "extra": {k: v for k, v in data.items() if isinstance(v, (int, float, str, bool))},
    }


# ---------------------------------------------------------------- SSH 兜底

# `diagnose sys sdwan health-check` 的输出(7.x):
#   Health Check(ISP1):
#     Seq(1 wan1): state(alive), packet-loss(0.000%) latency(8.286), jitter(0.ז)
#                  sla_map=0x1
_RE_CHECK = re.compile(r"^Health Check\(([^)]+)\)")
_RE_SEQ = re.compile(
    r"Seq\((\d+)\s+([^)]+)\):\s*state\((\w+)\)"
)
_RE_LOSS = re.compile(r"packet-loss\(([\d.]+)%?\)")
_RE_LAT = re.compile(r"latency\(([\d.]+)\)")
_RE_JIT = re.compile(r"jitter\(([\d.]+)\)")
_RE_SLA_MAP = re.compile(r"sla_map=(?:0x)?([0-9a-fA-F]+)")


def parse_diagnose_sdwan(text: str) -> list[dict]:
    """
    解析 `diagnose sys sdwan health-check`(SSH 兜底)。

    ⚠ **这条通道拿不到的东西比拿得到的多**:没有带宽、没有会话数、
    没有 SLA 档数总数(只有一个 `sla_map` 位图,能看出达标了哪几档,
    但看不出一共配了几档)。而且**这条命令的输出格式在大版本间有出入**
    (7.0 是 `diagnose sys virtual-wan-link health-check`)。

    所以 SD-WAN 这一项**强烈建议配 API Token**。这里只是兜底,让一台
    没有 API 的设备也能看到延迟/抖动/丢包,而不是完全看不到。
    """

    rows: list[dict] = []
    current_check = ""
    for line in text.replace("\r\n", "\n").split("\n"):
        if m := _RE_CHECK.search(line):
            current_check = m.group(1).strip()
            continue
        if not current_check:
            continue
        m = _RE_SEQ.search(line)
        if not m:
            continue
        member = m.group(2).strip()
        state = m.group(3).strip().lower()
        state = state if state in ("alive", "dead") else "unknown"

        loss = float(m2.group(1)) if (m2 := _RE_LOSS.search(line)) else None
        latency = float(m3.group(1)) if (m3 := _RE_LAT.search(line)) else None
        jitter = float(m4.group(1)) if (m4 := _RE_JIT.search(line)) else None

        sla_met = None
        if m5 := _RE_SLA_MAP.search(line):
            try:
                # sla_map 是位图:每一位是一档 SLA。**非零 = 至少过了一档**
                bits = int(m5.group(1), 16)
                sla_met = bits > 0
            except ValueError:
                sla_met = None

        if state == "dead":
            latency = jitter = None
            loss = 100.0
            sla_met = False

        rows.append({
            "health_check": current_check[:64], "member": member[:64],
            "server": "", "protocol": "",
            "state": state,
            "latency_ms": latency, "jitter_ms": jitter, "loss_pct": loss,
            "sla_met": sla_met,
            # **SSH 拿不到档数** —— 留 None,不要填 0(0 会被读成"配了 0 档")
            "sla_targets_met": None, "sla_targets_total": None,
            "tx_bps": None, "rx_bps": None, "session_count": None,
            "extra": {"_channel": "ssh"},
        })
    return rows
