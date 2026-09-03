"""
地址对象/地址组、服务对象/服务组的**展开** —— 纯函数,不碰网络也不碰库。

`resolve()` 两边共用:它只要 `name / is_group / value / members` 四个键,
而地址和服务在这四个键上是同构的。**不同的只有内置名那一套**
(`BUILTIN` vs `SERVICE_BUILTIN`)—— `ALL` 在服务里是"所有协议所有端口",
在地址里是 `0.0.0.0/0`,共用一套字典会让其中一边的说明是错的。

策略里写的是名字(`内网服务器组`),而人要问的是「它到底是哪几个网段」。
组可以套组,所以展开是递归的。

## 三件必须做对的事

1. **必须有环检测。**FortiOS 不拦"组 A 包含组 B、组 B 包含组 A"这种配置
   (跨 VDOM 导入、配置合并之后见得到)。没有环检测的话这个接口会把
   worker 转到超时 —— 而它是一个同步接口,人点一下页面就挂在那里。
2. **查不到一个名字 ≠ 这个名字不存在。**FortiOS 的 `show` 只打印偏离默认值
   的项,**出厂自带的对象根本不出现**(`all` / `none` / `FABRIC_DEVICE`)。
   所以解析不出来的名字要标成 `unknown` 单独列出来,页面上说
   「没同步到这个对象」——**不能说「这个对象不存在」**。
   前者是状态,后者是结论。
3. **`all` 是"任意",不是"查不到"。**它是 FortiOS 的内置名,含义是
   0.0.0.0/0。把它显示成"没同步到"会让人以为数据缺了一块,而实际上
   那条策略是**对所有地址开放的** —— 那恰恰是最该看见的一件事。
"""

from __future__ import annotations

#: FortiOS 内置的几个名字。**它们不会出现在 `show` 的输出里**,
#: 但含义是确定的,所以在这里认掉 —— 而不是让它们落到"没同步到"里
BUILTIN = {
    "all": ("任意地址(0.0.0.0/0)", "builtin_any"),
    "none": ("空(不匹配任何地址)", "builtin_none"),
    "fabric_device": ("Fabric 设备(内置动态对象)", "builtin_dynamic"),
}

#: 展开的深度上限。真实环境里套三层已经很少见,给 12 层是宽裕的兜底 ——
#: 环检测已经挡住了死循环,这一条挡的是"链特别长"那种病态配置
MAX_DEPTH = 12


#: 服务那边的内置名。和地址的 BUILTIN 是**两套** —— `ALL` 在服务里是
#: "所有协议所有端口",在地址里是 "0.0.0.0/0",含义不一样,共用一套字典
#: 会让其中一边的说明是错的。
#:
#: ⚠ FortiOS 还自带**几百个预定义服务**(HTTP / HTTPS / SSH / DNS …),
#: 它们不在这里 —— 那些是真实的对象,API 通道拿得到。这里只放"含义确定
#: 但不是一个对象"的那几个。
SERVICE_BUILTIN = {
    "all": ("所有协议、所有端口", "builtin_any"),
    "all_tcp": ("所有 TCP 端口", "builtin_any"),
    "all_udp": ("所有 UDP 端口", "builtin_any"),
    "all_icmp": ("所有 ICMP", "builtin_any"),
    "all_icmp6": ("所有 ICMPv6", "builtin_any"),
    "none": ("空(不匹配任何服务)", "builtin_none"),
}


def resolve(name: str, index: dict, _seen: set | None = None, _depth: int = 0,
            builtin: dict | None = None) -> dict:
    """
    把一个名字展开成「它到底是什么」。

    `index` 是 {名字小写: 那一行的 dict},dict 至少要有
    `name` / `is_group` / `addr_type` / `value` / `members` / `comment`。

    返回:
        {
          "name": 原样的名字,
          "kind": "address" | "group" | "builtin" | "unknown",
          "value": 人话的值(单个对象),
          "members": [ 递归展开的结果 ],   # 只有组有
          "leaves": [ {name, value, addr_type} ],  # **拍平后的叶子**
          "cycle": bool,   # 这一支是被环检测掐掉的
          "truncated": bool,
        }

    `leaves` 是这个接口存在的理由:人问"这个别名是哪些地址",要的就是
    那张拍平的表,而不是一棵要自己在脑子里展开的树。
    """

    builtin = BUILTIN if builtin is None else builtin
    seen = set(_seen or ())
    key = (name or "").strip().lower()
    row = index.get(key)

    if key in builtin and row is None:
        label, kind = builtin[key]
        return {
            "name": name, "kind": "builtin", "value": label,
            "members": [], "leaves": [{"name": name, "value": label, "addr_type": kind}],
            "cycle": False, "truncated": False,
        }

    if row is None:
        # **"没同步到" ≠ "不存在"** —— 见模块开头第 2 条
        return {
            "name": name, "kind": "unknown", "value": "",
            "members": [], "leaves": [], "cycle": False, "truncated": False,
        }

    if not row.get("is_group"):
        leaf = {
            "name": row["name"], "value": row.get("value") or "",
            "addr_type": row.get("addr_type") or "",
        }
        return {
            "name": row["name"], "kind": "address", "value": leaf["value"],
            "members": [], "leaves": [leaf], "cycle": False, "truncated": False,
        }

    # ---- 组 ----
    if key in seen:
        # 环。**掐掉这一支但不抛错** —— 一台设备上有一个环,不该让
        # 整次查询失败;页面上把这一支标出来,那正是要人去修的地方
        return {
            "name": row["name"], "kind": "group", "value": "",
            "members": [], "leaves": [], "cycle": True, "truncated": False,
        }
    if _depth >= MAX_DEPTH:
        return {
            "name": row["name"], "kind": "group", "value": "",
            "members": [], "leaves": [], "cycle": False, "truncated": True,
        }

    seen.add(key)
    members, leaves, truncated = [], [], False
    for member_name in row.get("members") or []:
        child = resolve(str(member_name), index, seen, _depth + 1, builtin)
        members.append(child)
        leaves.extend(child["leaves"])
        truncated = truncated or child["truncated"]

    # 叶子去重:两个子组包含同一个对象时,拍平的表里不该出现两遍
    deduped, seen_leaf = [], set()
    for leaf in leaves:
        marker = (leaf["name"], leaf["value"])
        if marker in seen_leaf:
            continue
        seen_leaf.add(marker)
        deduped.append(leaf)

    return {
        "name": row["name"], "kind": "group", "value": "",
        "members": members, "leaves": deduped,
        "cycle": any(m["cycle"] for m in members),
        "truncated": truncated,
    }


def build_index(rows) -> dict:
    """
    [FirewallAddress 或 dict] → {名字小写: dict}。

    **按小写建索引**:FortiOS 的对象名大小写敏感,但人在查询框里输的
    大小写不一定对得上 —— 查不到一个明明存在的别名比大小写严格更糟。
    """

    index = {}
    for row in rows:
        data = row if isinstance(row, dict) else {
            "name": row.name, "is_group": row.is_group,
            "addr_type": row.addr_type, "value": row.value,
            "members": row.members, "comment": row.comment,
        }
        index[str(data["name"]).strip().lower()] = data
    return index


def used_by_policies(name: str, policies, kind: str = "address") -> list[dict]:
    """
    哪些策略引用了这个别名(源或目的)。

    **名字精确比较**(忽略大小写),不做子串匹配 —— `web-svr` 和
    `web-svr-old` 是两个不同的对象,模糊匹配会把一条已经停用的旧策略
    算到在用的对象上。
    """

    key = (name or "").strip().lower()
    out = []
    for p in policies:
        where = []
        if kind == "service":
            if any(str(v).strip().lower() == key for v in (p.service or [])):
                where.append("服务")
        else:
            if any(str(v).strip().lower() == key for v in (p.src_addr or [])):
                where.append("源")
            if any(str(v).strip().lower() == key for v in (p.dst_addr or [])):
                where.append("目的")
        if where:
            out.append({
                "id": p.pk, "policy_id": p.policy_id, "seq": p.seq,
                "name": p.name, "enabled": p.enabled, "action": p.action,
                "where": " / ".join(where),
            })
    return out
