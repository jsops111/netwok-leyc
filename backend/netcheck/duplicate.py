"""
「复制一条配置」—— **在后端做,不在前端做。**

## 为什么必须在后端

凭据字段(SNMP community、SSH 密码/私钥、API Token、Redfish 密码、
Telegram Bot Token)在序列化器上是 `write_only`,**列表接口根本不回传**。
所以前端手上那份行数据里没有密码 —— 前端拼出来的"副本"必然是一台没有
凭据的机器,存下去要么被校验挡住,要么(对那些凭据非必填的类型)悄悄建出
一条采不了的。

后端这边拿得到解密后的值(`EncryptedTextField` 读出来就是明文),
所以复制在这里做,点一下就是一条能用的副本。

## 复制什么、不复制什么

复制的是**配置**,不复制**这台机器的现状**。三类不带:

1. **主键和时间戳。**不用解释。
2. **运行时状态**(state / last_* / consecutive_* / total_*)——
   带过去的话新那条一开始就顶着源那条的状态和最后错误,看着像它已经采过了。
3. **首次采集回填的铭牌**(型号 / 序列号 / 内核 / 服务编号 / 核数……)——
   这些是从**源那台机器**上采回来的。带过去的后果很安静:新那条在第一次
   采集之前,页面上显示的是**另一台机器的硬件信息**,而人会照着它判断
   "这台是 C9300 还是 C9200L"。

## 唯一约束挡住的那三类

`ProbeGroup` / `Device` / `Notifier` 只有 `name` 唯一,改个名就能直接建出来
—— 那是真正的"点一下就好"。

而 `ProbeTarget`(监控类+地址+协议+端口)、`Server`(地址+端口)、
`IdracHost`(地址+端口)有端点唯一约束,**原样复制建不出来**。这不是缺陷:
那条约束存在的理由就是"同一台机器加两遍会被采两遍"。所以这里的做法是
把**必须改的那几个字段**回给前端(`needs` 字段),前端只弹那几个框,
填完再调一次 —— 而不是让人对着一个四十项的完整表单从头改一遍。
"""

from __future__ import annotations

import re

from django.db import models, transaction

#: 所有类型都不带的字段。名字在各模型上不完全一样,取交集写全没关系 ——
#: 模型上没有的字段这里会被忽略
_SKIP_COMMON = {
    "id", "created_at", "updated_at",
    "state", "last_checked_at", "last_collected_at", "last_error",
    "consecutive_fail", "consecutive_ok", "total_checks", "total_fail",
    "last_rtt_ms", "last_loss_pct", "last_jitter_ms",
    "last_sent_at", "total_sent", "total_failed",
    "meta",
}

#: 首次采集回填的铭牌 —— 它们属于**源那台机器**,不属于这份配置
_SKIP_INVENTORY = {
    "os_version", "serial", "hostname", "os_name", "kernel",
    "cpu_cores", "mem_total_bytes",
    "model_name", "manufacturer", "service_tag", "bios_version",
    "idrac_firmware", "system_hostname", "power_state",
    "last_backup_at", "last_backup_status", "last_backup_error",
    "config_unsaved", "config_unsaved_lines", "config_checked_at",
    "last_policy_sync_at", "last_policy_error", "policy_count",
}

SKIP = _SKIP_COMMON | _SKIP_INVENTORY

#: 已经是副本的名字,再复制时从**原名**接着编号,而不是
#: 「xxx 复制1 复制1」这样越滚越长
_RE_SUFFIX = re.compile(r"^(.*?)\s*复制\d*$")


def next_name(model, base: str, field: str = "name", limit: int = 500) -> str:
    """
    `原名 复制1`,占了就 `复制2`……

    从**去掉后缀的原名**开始编号:对 `sw-01 复制3` 再点一次复制,
    得到的是 `sw-01 复制4`,不是 `sw-01 复制3 复制1`。

    `limit` 是个兜底 —— 真有人点了 500 次的话,最后退回带一段随机后缀的
    名字,**不抛错**:复制失败没什么好处,而一个奇怪的名字改一下就行。
    """

    if m := _RE_SUFFIX.match(base or ""):
        base = m.group(1)
    base = (base or "副本").strip()

    field_length = model._meta.get_field(field).max_length or 255
    for n in range(1, limit + 1):
        suffix = f" 复制{n}"
        # 名字有长度上限,拼完超了要从**前面**截 —— 截后缀的话
        # 「复制12」会变成「复制1」,和另一条撞名
        candidate = base[: field_length - len(suffix)] + suffix
        if not model.objects.filter(**{field: candidate}).exists():
            return candidate

    import uuid
    suffix = f" 复制{uuid.uuid4().hex[:6]}"
    return base[: field_length - len(suffix)] + suffix


def copyable_fields(instance) -> dict:
    """
    这条记录里**可以复制的字段** → 值。

    只取具体列(含外键的 `_id`),跳过 SKIP、跳过自增主键和自动时间戳。
    多对多单独处理(见 `duplicate()`)—— 它在对象存下去之前设不了。
    """

    out: dict = {}
    for field in instance._meta.concrete_fields:
        name = field.name
        if name in SKIP or field.primary_key or getattr(field, "auto_now", False) \
                or getattr(field, "auto_now_add", False):
            continue
        if isinstance(field, models.ForeignKey):
            out[f"{name}_id"] = getattr(instance, f"{name}_id")
        else:
            out[name] = getattr(instance, name)
    return out


def m2m_values(instance) -> dict:
    """多对多的当前值。存完之后再 set 回去。"""
    return {
        f.name: list(getattr(instance, f.name).values_list("pk", flat=True))
        for f in instance._meta.many_to_many
    }


@transaction.atomic
def duplicate(instance, overrides: dict | None = None, name_field: str = "name"):
    """
    复制一条记录并**直接存下来**。返回新对象。

    `overrides` 是前端补上的那几个必须改的字段(通常是地址)。
    唯一约束仍然由数据库和模型的 `clean()` 兜底 —— 这里不重复实现,
    调用方(视图)负责把 IntegrityError / ValidationError 翻成人话。
    """

    model = type(instance)
    data = copyable_fields(instance)
    links = m2m_values(instance)

    for key, value in (overrides or {}).items():
        # 只认模型上真有的字段 —— 前端多传的东西直接忽略,
        # 而不是拿去 setattr 出一个假属性
        if key in data or any(f.name == key for f in model._meta.concrete_fields):
            data[key] = value

    data[name_field] = next_name(model, getattr(instance, name_field), name_field)

    copy = model(**data)
    copy.full_clean(exclude=[f.name for f in model._meta.many_to_many])
    copy.save()

    for name, pks in links.items():
        getattr(copy, name).set(pks)
    return copy
