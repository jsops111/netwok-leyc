"""
交换机 / 路由器 / 防火墙的**配置定时备份**。

## 一行一个版本,不是一行一次备份

见 models.DeviceBackup 的类说明。这里只强调实现上的后果:
`backup_device()` 每次都会去设备上取一遍配置,但**只有内容变了才新增一行**。
没变就把最新那行的 `last_seen_at` 往后推。所以这张表的行数 = 真实变更次数,
而"最后一次成功备份是什么时候"记在 Device.last_backup_at 上。

## 比对前要清洗

Cisco 的 `! Last configuration change at ...`、`Current configuration : N bytes`、
`ntp clock-period`,FortiOS 的 `#conf_file_ver=` —— 这些行每次导出都不一样,
和配置内容无关。不去掉的话**每一次备份都会被判成"配置变更过"**,变更历史
退化成一天一条噪声,而真正有人改配置的那一天就藏在里面看不出来。

清洗只用于**哈希和 diff**;库里存的是原始文本,因为下载下来的东西要能
直接回灌到设备上。

## 通道选择和采集通道无关

采指标可以走 SNMP,但 SNMP 拿不到配置文本。所以备份的通道是:

    FortiGate + 有 API Token  → REST API 的 config/backup(拿到的是能直接
                                回灌的备份文件,CLI 的 `show` 输出不是)
    其它                      → SSH,命令来自型号画像的 backup_cli

画像里 backup_cli 为空 = 这款型号不支持备份。**不要拿别的命令凑** ——
一份内容不是配置的"备份"比没有备份糟得多:页面上看着有版本记录,
真要回滚时才发现里面是 show version 的输出。
"""

from __future__ import annotations

import difflib
import hashlib
import logging
import re

from django.db import transaction
from django.utils import timezone

from netcheck.models import (
    BackupStatus,
    Device,
    DeviceBackup,
    EventKind,
    Severity,
    Vendor,
)

from . import fortigate_api, ssh_cli
from .profiles import Profile, get_profile

log = logging.getLogger("netcheck.backup")

# 单份配置的上限。FortiGate 的 `show full-configuration` 能到几十 MB,
# 而这张表是要被列表查询的 —— 超过就截断并在文本里写明,
# **不要静默截断**:一份看不出被截断过的备份是假备份
MAX_CONFIG_BYTES = 8 * 1024 * 1024

# 提示符残留行:`switch#`、`FGT-01 (root) #`、`Router>`。
# 交互式会话取回来的文本末尾一定有一行提示符,留着会让每次比对都不一样
# (提示符里可能带配置模式、带 VDOM 名)
_RE_PROMPT_ONLY = re.compile(r"^[\w.\-]+(\s*\([\w.\-]+\))?\s*[#>]\s*$")


class BackupError(Exception):
    """备份失败。会写进 Device.last_backup_error,并记一条瞬时事件。"""


# =========================================================================
# 取配置
# =========================================================================


def _strip_cli_noise(text: str, command: str) -> str:
    """
    去掉命令回显、提示符残留和分页残渣。

    只从**首尾**下手,不在正文里做全局删除:配置里完全可能有一行注释长得
    像提示符(`description core#`),从中间删行会把真实配置删掉。
    """

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")

    # 头部:命令回显之前的东西(banner、MOTD、上一条命令的尾巴)全丢掉
    for idx, line in enumerate(lines):
        if command.strip() and command.strip() in line:
            lines = lines[idx + 1:]
            break

    # 尾部:提示符行和空行
    while lines and (not lines[-1].strip() or _RE_PROMPT_ONLY.match(lines[-1].strip())):
        lines.pop()
    # 头部残留的空行
    while lines and not lines[0].strip():
        lines.pop(0)

    cleaned = [ln for ln in lines if "--More--" not in ln and "---(more)---" not in ln.lower()]
    return "\n".join(cleaned)


def _fetch_ssh(device: Device, profile: Profile) -> str:
    if not profile.backup_cli:
        raise BackupError(
            f"型号 {device.get_model_display()} 的画像没有定义备份命令 —— "
            "在 devices/profiles.py 里给它补一条 backup_cli"
        )
    if not device.ssh_username or not (device.ssh_password or device.ssh_private_key):
        raise BackupError("配置备份需要 SSH 用户名 + 密码/私钥")

    command = profile.backup_cli
    # 配置可能几千行,超时给得比采集宽得多。**这里最容易踩的坑是截断**:
    # 上限给小了会拿到半份配置,而那半份看起来是完整的
    hard_limit = 180.0
    client = ssh_cli._connect(device)
    try:
        if device.vendor == Vendor.CISCO:
            # `terminal length 0` 必须和 backup 命令在**同一个会话**里,
            # 而且 running-config 要 enable —— 所以走交互式 shell
            outputs = ssh_cli._run_shell(
                client, ["terminal length 0", command], timeout=hard_limit + 30,
                enable_password=device.ssh_enable_password if profile.cli_needs_enable else "",
                hard_limit=hard_limit,
            )
            raw = outputs.get(command, "")
        else:
            # FortiOS 的 `show` 在非交互会话里不分页,exec_command 更稳
            raw = ssh_cli._run_exec(client, command, timeout=hard_limit)
    except ssh_cli.SshError as exc:
        raise BackupError(str(exc)) from exc
    finally:
        client.close()

    text = _strip_cli_noise(raw, command)
    if not text.strip():
        raise BackupError(
            f"`{command}` 没有输出。Cisco 的 running-config 需要 enable 权限,"
            "检查账号权限和 enable 密码"
        )
    # 权限不足时设备回的是一行错误,而不是报错退出 —— 这种"成功拿到一行
    # 错误信息"的情况必须挡住,否则会被存成一个版本
    lowered = text.lower()
    if len(text) < 400 and any(
        marker in lowered
        for marker in ("invalid input", "permission denied", "% authorization failed",
                       "command fail", "unknown action", "not allowed")
    ):
        raise BackupError(f"设备拒绝了备份命令:{text.strip()[:160]}")
    return text


def check_unsaved(device: Device, running_text: str, profile: Profile) -> dict:
    """
    比对 running-config 和 startup-config,判断有没有**改了但没保存**的配置。

    这是备份功能天然该回答的一问:一份备份下来的 running-config 看着好好的,
    而它可能一次断电就不存在了 —— `write memory` 是个人容易忘的动作,
    而忘了的后果要到设备重启才暴露。

    ## 比对同样走 sanitize,但仍然可能有假阳性

    running 和 startup 之间**天生就有一些无害差异**(两边的头部注释不一样、
    某些平台会在 startup 里多写几行),画像的 `backup_volatile` 盖住了
    已知的那些。真机上如果这一项长期报"未保存"而实际已经保存过,
    **去看 diff**(页面上有),把那几行的正则加到 `backup_volatile` 里 ——
    而不是把这个开关关掉。

    所以返回的是**差异行数 + diff 本身**,不只是一个布尔:让工程师自己看一眼
    比让他信一个不透明的判断更靠得住。

    返回 {"unsaved": bool|None, "lines": int|None, "diff": [str], "error": str}。
    `unsaved=None` 表示**没能检查**(不支持 / 取不到)—— 那和"已保存"是
    两件事,不能混。
    """

    if not profile.startup_cli:
        return {"unsaved": None, "lines": None, "diff": [],
                "error": "这款型号没有「启动配置」的概念(FortiOS 改完即存)"}
    if not (device.ssh_username and (device.ssh_password or device.ssh_private_key)):
        return {"unsaved": None, "lines": None, "diff": [], "error": "需要 SSH 凭据"}

    command = profile.startup_cli
    hard_limit = 180.0
    try:
        client = ssh_cli._connect(device)
    except ssh_cli.SshError as exc:
        return {"unsaved": None, "lines": None, "diff": [], "error": str(exc)}
    try:
        if device.vendor == Vendor.CISCO:
            outputs = ssh_cli._run_shell(
                client, ["terminal length 0", command], timeout=hard_limit + 30,
                enable_password=device.ssh_enable_password if profile.cli_needs_enable else "",
                hard_limit=hard_limit,
            )
            raw = outputs.get(command, "")
        else:
            raw = ssh_cli._run_exec(client, command, timeout=hard_limit)
    except ssh_cli.SshError as exc:
        return {"unsaved": None, "lines": None, "diff": [], "error": str(exc)}
    finally:
        client.close()

    startup = _strip_cli_noise(raw, command)
    if not startup.strip():
        return {"unsaved": None, "lines": None, "diff": [],
                "error": f"`{command}` 没有输出(需要 enable 权限?)"}
    lowered = startup.lower()
    if len(startup) < 400 and any(
        m in lowered for m in ("invalid input", "permission denied", "startup-config is not present")
    ):
        return {"unsaved": None, "lines": None, "diff": [],
                "error": f"设备拒绝了命令:{startup.strip()[:120]}"}

    run_clean = sanitize(running_text, profile).split("\n")
    start_clean = sanitize(startup, profile).split("\n")
    diff = list(difflib.unified_diff(
        start_clean, run_clean,
        fromfile="startup-config(已保存)", tofile="running-config(当前生效)",
        n=2, lineterm="",
    ))
    changed = sum(1 for line in diff
                  if (line.startswith(("+", "-")) and not line.startswith(("+++", "---"))))
    return {
        "unsaved": changed > 0,
        "lines": changed,
        # 只留前 200 行 —— 整机重配的 diff 有上万行,而那种情况看前 200 行
        # 就够判断了,全存进 meta 会让设备表变得很重
        "diff": diff[:200] + ([f"... 还有 {len(diff) - 200} 行差异"] if len(diff) > 200 else []),
        "error": "",
    }


def _fetch_api(device: Device) -> str:
    try:
        return fortigate_api.fetch_config(device)
    except fortigate_api.FortiApiError as exc:
        raise BackupError(str(exc)) from exc


def fetch_config(device: Device) -> tuple[str, str]:
    """
    取一份配置。返回 (文本, 通道)。

    FortiGate 有 API Token 就走 API:那个端点给的是**能直接回灌的备份文件**,
    带校验头;CLI 的 `show` 输出只是配置片段,回灌要人工处理。
    API 失败时退回 SSH —— 有一份 CLI 备份也比没有好,通道记在版本行上,
    页面上能看出这个版本是哪条路取的。
    """

    profile = get_profile(device.model, device.vendor)

    if device.vendor == Vendor.FORTINET and device.api_token:
        try:
            return _fetch_api(device), "api"
        except BackupError as exc:
            if not profile.backup_cli:
                raise
            log.info("设备 %s API 备份失败(%s),退回 SSH", device.name, exc)

    return _fetch_ssh(device, profile), "ssh"


# =========================================================================
# 清洗与比对
# =========================================================================


def sanitize(text: str, profile: Profile) -> str:
    """
    去掉"每次导出都变但没有意义"的行,用于**哈希和 diff**。

    另外统一行尾(\\r\\n → \\n)并去掉行尾空白:有些设备在 CLI 输出里
    补齐空格到固定宽度,而那个宽度取决于终端 width —— 换个采集节点就
    "整份配置都变了"。
    """

    patterns = [re.compile(p, re.I) for p in profile.backup_volatile]
    out: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if any(p.match(line) for p in patterns):
            continue
        out.append(line.rstrip())
    # **头尾的空行都要去掉。**只去尾部的话,`show running-config` 开头那个
    # "Building configuration..." 被 backup_volatile 滤掉之后会留下一个空行,
    # 而 `show startup-config` 没有那一行 —— 于是 running / startup 比对
    # 凭空多出一行差异,页面上报"未保存 1 行"而配置其实是一致的
    while out and not out[-1]:
        out.pop()
    while out and not out[0]:
        out.pop(0)
    return "\n".join(out)


def content_hash(sanitized: str) -> str:
    return hashlib.sha256(sanitized.encode("utf-8", "replace")).hexdigest()


def diff_counts(old_sanitized: str, new_sanitized: str) -> tuple[int, int]:
    """(新增行数, 删除行数)。列表页显示 "+3 −1" 用这两个数字。"""

    old_lines = old_sanitized.split("\n")
    new_lines = new_sanitized.split("\n")
    added = removed = 0
    for line in difflib.unified_diff(old_lines, new_lines, n=0, lineterm=""):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return added, removed


def unified_diff(
    old: DeviceBackup, new: DeviceBackup, context: int = 3, max_lines: int = 4000
) -> list[str]:
    """
    两个版本之间的 unified diff,**比对清洗后的文本**。

    比对原始文本的话每次 diff 的第一行都是 `! Last configuration change`,
    人要在噪声里找真正的改动。

    截断在 max_lines:一次把整台设备重配了的 diff 有上万行,而浏览器渲染
    上万行 diff 会卡住 —— 截断处会明确写出来还有多少行。
    """

    profile = get_profile(new.device.model, new.device.vendor)
    old_text = sanitize(old.content, profile).split("\n")
    new_text = sanitize(new.content, profile).split("\n")

    lines = list(difflib.unified_diff(
        old_text, new_text,
        fromfile=f"{old.ts:%Y-%m-%d %H:%M} ({old.short_hash})",
        tofile=f"{new.ts:%Y-%m-%d %H:%M} ({new.short_hash})",
        n=context, lineterm="",
    ))
    if len(lines) > max_lines:
        remaining = len(lines) - max_lines
        lines = lines[:max_lines] + [f"... 还有 {remaining} 行差异未显示(下载两个版本本地比对)"]
    return lines


# =========================================================================
# 主入口
# =========================================================================


def backup_device(device: Device) -> dict:
    """
    备份一台设备。返回 {"changed", "version_id", "hash", "method", ...}。

    失败时抛 BackupError —— 由调用方(tasks.backup_device_task)负责回写
    Device.last_backup_* 并记事件。这里只管"取到并存好"。

    要顺带检查"配置有没有未保存"用 `backup_and_check()`。
    """

    profile = get_profile(device.model, device.vendor)
    text, method = fetch_config(device)
    return _store(device, text, method, profile)


def _store(device: Device, text: str, method: str, profile: Profile) -> dict:
    """把取回来的配置文本存成版本(变了才新增行)。"""

    truncated = False
    encoded = text.encode("utf-8", "replace")
    if len(encoded) > MAX_CONFIG_BYTES:
        text = encoded[:MAX_CONFIG_BYTES].decode("utf-8", "ignore")
        text += (
            f"\n\n# ===== netcheck: 配置超过 {MAX_CONFIG_BYTES // 1024 // 1024}MiB,"
            "已截断。这份备份不完整,不能用于回滚 =====\n"
        )
        truncated = True
        log.warning("设备 %s 的配置超过上限,已截断", device.name)

    cleaned = sanitize(text, profile)
    digest = content_hash(cleaned)
    now = timezone.now()

    with transaction.atomic():
        # select_for_update 防两个 worker 同时备份同一台设备时各建一个版本
        latest = (
            DeviceBackup.objects.select_for_update()
            .filter(device=device).order_by("-ts").first()
        )

        if latest is not None and latest.content_hash == digest:
            latest.last_seen_at = now
            latest.seen_count += 1
            latest.save(update_fields=["last_seen_at", "seen_count"])
            return {
                "changed": False, "version_id": latest.pk, "hash": digest,
                "method": method, "size_bytes": latest.size_bytes,
                "seen_count": latest.seen_count, "truncated": truncated,
            }

        added = removed = None
        if latest is not None:
            added, removed = diff_counts(sanitize(latest.content, profile), cleaned)

        version = DeviceBackup.objects.create(
            device=device, ts=now, last_seen_at=now, seen_count=1,
            method=method, content=text,
            size_bytes=len(text.encode("utf-8", "replace")),
            line_count=text.count("\n") + 1,
            content_hash=digest,
            lines_added=added, lines_removed=removed,
            is_first=latest is None,
        )
        _prune(device)

    return {
        "changed": True, "version_id": version.pk, "hash": digest, "method": method,
        "size_bytes": version.size_bytes, "lines_added": added, "lines_removed": removed,
        "is_first": version.is_first, "truncated": truncated,
    }


def backup_and_check(device: Device) -> dict:
    """
    备份 + 顺带检查未保存的配置。

    检查**只在 SSH 通道下做**:走 API 拿到的是备份文件,和 startup-config
    不是同一种文本,拿它们比对会得到一堆假差异。
    """

    profile = get_profile(device.model, device.vendor)
    text, method = fetch_config(device)
    result = _store(device, text, method, profile)

    result["unsaved"] = None
    result["unsaved_lines"] = None
    result["unsaved_diff"] = []
    result["unsaved_error"] = ""
    if device.backup_check_unsaved and method == "ssh" and profile.startup_cli:
        try:
            check = check_unsaved(device, text, profile)
        except Exception as exc:  # noqa: BLE001 —— 检查失败不能让备份也失败
            log.warning("设备 %s 未保存检查异常: %s", device.name, exc)
            check = {"unsaved": None, "lines": None, "diff": [],
                     "error": f"{type(exc).__name__}: {exc}"}
        result["unsaved"] = check["unsaved"]
        result["unsaved_lines"] = check["lines"]
        result["unsaved_diff"] = check["diff"]
        result["unsaved_error"] = check["error"]
    return result


def _prune(device: Device) -> int:
    """
    只留最近 backup_keep 个版本。

    删的是**最老的版本**。代价是留得最久的那份基线会消失 —— 这是有意的:
    配置备份的价值随时间递减(三年前的配置回滚不回去),而这张表存的是
    全文,不删会一直涨。要长期归档的话把版本下载下来放到别的地方。
    """

    keep = max(1, device.backup_keep)
    stale_ids = list(
        DeviceBackup.objects.filter(device=device)
        .order_by("-ts")
        .values_list("pk", flat=True)[keep:]
    )
    if not stale_ids:
        return 0
    deleted, _ = DeviceBackup.objects.filter(pk__in=stale_ids).delete()
    log.info("设备 %s 清理了 %d 个超出保留数的旧版本", device.name, deleted)
    return deleted


def test_backup(device: Device) -> tuple[bool, str]:
    """
    配置中心的「测备份通道」。**取一份配置但不写库** ——
    这是"验证这条路能走通",不是留一个版本。

    存起来的话每点一次测试就多一个版本,而版本数是有上限的:
    连点五次就把真实的变更历史挤掉五个。
    """

    try:
        text, method = fetch_config(device)
    except BackupError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"

    profile = get_profile(device.model, device.vendor)
    cleaned = sanitize(text, profile)
    lines = cleaned.count("\n") + 1
    size_kib = len(text.encode("utf-8", "replace")) / 1024
    first = next((ln.strip() for ln in cleaned.split("\n") if ln.strip()), "")

    latest = DeviceBackup.objects.filter(device=device).order_by("-ts").first()
    same = latest is not None and latest.content_hash == content_hash(cleaned)
    change_note = (
        "和当前最新版本一致(这次测试不会新增版本)" if same
        else "和当前最新版本不同" if latest is not None
        else "这台设备还没有任何版本"
    )
    return True, (
        f"通道 {method.upper()} · {lines} 行 · {size_kib:.1f} KiB · "
        f"首行「{first[:60]}」· {change_note}"
    )
