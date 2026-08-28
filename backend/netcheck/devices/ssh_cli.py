"""
SSH CLI 采集通道。

这是三条通道里最脆的一条 —— 它解析的是给人看的文本。所以定位是**降级通道**:
SNMP 被关掉、community 配错、或者要拿只有 CLI 才给的东西时才用它。

两个必须处理的现实问题:

1. **分页。**Cisco 默认 `--More--` 分页,不关掉就会卡在等空格。所以每次
   会话开头先发 `terminal length 0`(FortiOS 是 `config system console` /
   `set output standard`)。
2. **提示符识别。**exec_command 每条命令一个新 channel,不保留 enable 状态,
   所以需要 enable 的设备必须用 invoke_shell 走交互式。这里两种都实现了:
   不需要 enable 的走 exec_command(更快更稳),需要的走 shell。
"""

from __future__ import annotations

import logging
import re
import socket
import time

import paramiko

from netcheck.models import Device, Vendor

from .profiles import get_profile

log = logging.getLogger("netcheck.ssh")


class SshError(Exception):
    pass


def _connect(device: Device) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {
        "hostname": device.mgmt_ip,
        "port": device.ssh_port,
        "username": device.ssh_username,
        "timeout": device.timeout_ms / 1000,
        "banner_timeout": max(15, device.timeout_ms / 1000),
        "auth_timeout": max(15, device.timeout_ms / 1000),
        "look_for_keys": False,
        "allow_agent": False,
    }
    if device.ssh_private_key:
        import io

        key_text = device.ssh_private_key
        pkey = None
        # 不知道是哪种密钥,依次试。Ed25519 放前面 —— 新设备上更常见
        for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try:
                pkey = key_cls.from_private_key(io.StringIO(key_text))
                break
            except Exception:  # noqa: BLE001 —— 试下一种
                continue
        if pkey is None:
            raise SshError("私钥解析失败(试过 Ed25519 / RSA / ECDSA)")
        kwargs["pkey"] = pkey
    else:
        kwargs["password"] = device.ssh_password

    # 网络设备的 SSH 实现普遍很老,常见的是只支持 diffie-hellman-group1-sha1
    # 和 ssh-rsa。paramiko 5 默认禁用了它们,连老 IOS 会直接报
    # "no matching key exchange method found" —— 这里显式放宽。
    # 这是有意的安全折让:管理网内的老交换机没有别的连法。
    try:
        client.connect(**kwargs)
    except paramiko.SSHException as exc:
        if "no matching" in str(exc).lower():
            transport_kwargs = dict(kwargs)
            client.connect(
                **transport_kwargs,
                disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
            )
        else:
            raise SshError(f"SSH 连接失败: {exc}") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise SshError(f"SSH 连接超时(>{device.timeout_ms}ms)") from exc
    except paramiko.AuthenticationException as exc:
        raise SshError("SSH 认证失败,检查用户名/密码或私钥") from exc
    except OSError as exc:
        raise SshError(f"SSH 网络错误: {exc}") from exc
    return client


def _run_exec(client: paramiko.SSHClient, command: str, timeout: float) -> str:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "ignore")
    err = stderr.read().decode("utf-8", "ignore")
    return out + err


def _run_shell(client: paramiko.SSHClient, commands: list[str], timeout: float,
               enable_password: str = "") -> dict[str, str]:
    """
    交互式会话跑一批命令。返回 {命令: 输出}。

    读取靠"输出静默"判断结束,而不是等提示符正则 —— 网络设备的提示符会因为
    主机名、配置模式、告警插入而变化,靠正则匹配提示符是 bug 的温床。
    静默 0.4 秒没有新数据就认为这条命令输出完了。
    """

    shell = client.invoke_shell(width=200, height=1000)
    shell.settimeout(timeout)
    outputs: dict[str, str] = {}

    def read_until_idle(idle: float = 0.4, hard_limit: float = 20.0) -> str:
        buf, last_data = "", time.time()
        deadline = time.time() + hard_limit
        while time.time() < deadline:
            if shell.recv_ready():
                chunk = shell.recv(65535).decode("utf-8", "ignore")
                buf += chunk
                last_data = time.time()
                # 分页提示还是可能漏出来(比如 terminal length 没生效),
                # 见到就喂个空格继续,别卡死
                if "--More--" in chunk or "---(more)---" in chunk.lower():
                    shell.send(" ")
            elif time.time() - last_data > idle:
                break
            else:
                time.sleep(0.05)
        return buf

    read_until_idle(0.8)  # 吞掉登录 banner

    if enable_password:
        shell.send("enable\n")
        prompt = read_until_idle()
        if "assword" in prompt:
            shell.send(enable_password + "\n")
            read_until_idle()

    for command in commands:
        shell.send(command + "\n")
        raw = read_until_idle()
        # 去掉回显的命令本身和末行提示符,只留输出
        lines = [ln for ln in raw.splitlines() if ln.strip() != command.strip()]
        outputs[command] = "\n".join(lines)

    shell.close()
    return outputs


# ---------------------------------------------------------------- 解析器

# "CPU utilization for five seconds: 5%/0%; one minute: 6%; five minutes: 7%"
_RE_IOS_CPU = re.compile(
    r"five seconds:\s*(\d+)%.*?one minute:\s*(\d+)%.*?five minutes:\s*(\d+)%", re.I | re.S
)
# "Processor Pool Total: 2100000000 Used: 900000000 Free: 1200000000"
_RE_IOS_MEM = re.compile(r"Total:\s*(\d+)\s+Used:\s*(\d+)\s+Free:\s*(\d+)", re.I)
_RE_IOS_VERSION = re.compile(r"Cisco IOS XE Software, Version\s+([\w.()]+)", re.I)
_RE_IOS_VERSION2 = re.compile(r"Version\s+([\d]+\.[\w.()]+)", re.I)
_RE_IOS_MODEL = re.compile(r"Model Number\s*:\s*(\S+)", re.I)
_RE_IOS_SERIAL = re.compile(r"System Serial Number\s*:\s*(\S+)", re.I)
_RE_IOS_UPTIME = re.compile(
    r"uptime is\s+(?:(\d+)\s+years?,\s*)?(?:(\d+)\s+weeks?,\s*)?(?:(\d+)\s+days?,\s*)?"
    r"(?:(\d+)\s+hours?,\s*)?(?:(\d+)\s+minutes?)?", re.I
)
# "SW  Temperature Value: 44 Degree Celsius" / "Inlet Temperature Value: 28"
_RE_IOS_TEMP = re.compile(r"Temperature Value:\s*(\d+)", re.I)


def parse_cisco(outputs: dict[str, str], profile) -> dict:
    """把 Cisco IOS-XE 的 CLI 输出解析成 DeviceSample 的字段。"""

    out: dict = {"extra": {"channel": "ssh"}}
    joined = "\n".join(outputs.values())

    if m := _RE_IOS_CPU.search(joined):
        # 用 five minutes 那档 —— five seconds 抖得厉害,一次 show 命令
        # 自己就能把它顶上去
        out["cpu_pct"] = float(m.group(3))
        out["extra"]["cpu_5s"] = float(m.group(1))
        out["extra"]["cpu_1m"] = float(m.group(2))

    if m := _RE_IOS_MEM.search(joined):
        total, used = float(m.group(1)), float(m.group(2))
        if total > 0:
            out["mem_pct"] = round(used / total * 100, 2)

    if m := _RE_IOS_VERSION.search(joined) or _RE_IOS_VERSION2.search(joined):
        out["os_version"] = m.group(1)
    if m := _RE_IOS_SERIAL.search(joined):
        out["serial"] = m.group(1)
    if m := _RE_IOS_MODEL.search(joined):
        out["extra"]["model_reported"] = m.group(1)

    temps = [float(t) for t in _RE_IOS_TEMP.findall(joined)]
    if temps:
        out["temp_c"] = max(temps)
    elif "temp_c" not in profile.optional:
        out["extra"]["temp_missing"] = "CLI 输出里没有温度读数"

    if m := _RE_IOS_UPTIME.search(joined):
        years, weeks, days, hours, minutes = (int(g or 0) for g in m.groups())
        out["uptime_s"] = (
            years * 31536000 + weeks * 604800 + days * 86400 + hours * 3600 + minutes * 60
        )

    # 电源:show env power 里出现 "Bad" / "Faulty" 就是有问题
    power_text = "\n".join(v for k, v in outputs.items() if "power" in k)
    if power_text.strip():
        out["psu_ok"] = not re.search(r"\b(bad|fault|faulty|fail)\b", power_text, re.I)

    # 接口 up 数:show ip interface brief 的 "up up" 行
    brief = "\n".join(v for k, v in outputs.items() if "interface brief" in k)
    if brief.strip():
        lines = [ln for ln in brief.splitlines() if re.search(r"\s(up|down|administratively down)\s", ln, re.I)]
        out["if_total"] = len(lines)
        out["if_up"] = sum(1 for ln in lines if re.search(r"\bup\s+up\b", ln, re.I))

    return out


# FortiOS "get system performance status":
#   CPU states: 1% user 2% system 0% nice 97% idle
#   Memory: 8123456k total, 3123456k used (38.4%), ...
#   Memory states: 38% used
#   Total sessions: 12345
_RE_FG_CPU_IDLE = re.compile(r"CPU states?:.*?(\d+)%\s+idle", re.I)
_RE_FG_MEM = re.compile(r"Memory states?:\s*(\d+)%\s*used", re.I)
_RE_FG_MEM_ALT = re.compile(r"Memory:.*?\((\d+(?:\.\d+)?)%\)", re.I)
_RE_FG_SESSIONS = re.compile(r"Total sessions?:\s*(\d+)", re.I)
_RE_FG_VERSION = re.compile(r"Version:\s*\S+\s+(v[\d.]+[\w,.\- ]*)", re.I)
_RE_FG_SERIAL = re.compile(r"Serial-Number:\s*(\S+)", re.I)
_RE_FG_UPTIME = re.compile(r"Uptime:\s*(\d+)\s*days?,\s*(\d+)\s*hours?,\s*(\d+)\s*minutes?", re.I)
_RE_FG_HA = re.compile(r"Mode:\s*(\S+)", re.I)


def parse_fortigate(outputs: dict[str, str], profile) -> dict:
    out: dict = {"extra": {"channel": "ssh"}}
    joined = "\n".join(outputs.values())

    if m := _RE_FG_CPU_IDLE.search(joined):
        # FortiOS 报的是 idle,使用率要自己减 —— 直接把 idle 当使用率填进去
        # 是这条通道最容易犯的错(结果是空闲设备显示 97% CPU)
        out["cpu_pct"] = float(100 - int(m.group(1)))
    if m := _RE_FG_MEM.search(joined) or _RE_FG_MEM_ALT.search(joined):
        out["mem_pct"] = float(m.group(1))
    if m := _RE_FG_SESSIONS.search(joined):
        out["session_count"] = int(m.group(1))
    if m := _RE_FG_VERSION.search(joined):
        out["os_version"] = m.group(1).strip().rstrip(",")
    if m := _RE_FG_SERIAL.search(joined):
        out["serial"] = m.group(1)
    if m := _RE_FG_UPTIME.search(joined):
        days, hours, minutes = (int(g) for g in m.groups())
        out["uptime_s"] = days * 86400 + hours * 3600 + minutes * 60

    ha_text = "\n".join(v for k, v in outputs.items() if "ha" in k.lower())
    if ha_text.strip():
        if m := _RE_FG_HA.search(ha_text):
            out["ha_state"] = m.group(1)
        elif "standalone" in ha_text.lower():
            out["ha_state"] = "standalone"

    return out


def collect(device: Device) -> dict:
    """SSH 采一轮。返回的键对应 DeviceSample 的列名。"""

    profile = get_profile(device.model, device.vendor)
    if not profile.cli:
        raise SshError(f"型号 {device.model} 的画像没有定义 CLI 命令,该型号请用 SNMP 通道")

    started = time.perf_counter()
    timeout = max(10.0, device.timeout_ms / 1000 * 3)  # CLI 比单次 SNMP 慢得多
    client = _connect(device)
    try:
        commands = list(profile.cli.values())
        if device.vendor == Vendor.CISCO:
            # terminal length 0 必须在同一个会话里生效,所以走 shell
            outputs = _run_shell(
                client, ["terminal length 0"] + commands, timeout,
                enable_password=device.ssh_enable_password if profile.cli_needs_enable else "",
            )
            data = parse_cisco(outputs, profile)
        elif device.vendor == Vendor.FORTINET:
            # FortiOS 的 get/diagnose 不分页,exec_command 够用且更快
            outputs = {cmd: _run_exec(client, cmd, timeout) for cmd in commands}
            data = parse_fortigate(outputs, profile)
        else:
            outputs = {cmd: _run_exec(client, cmd, timeout) for cmd in commands}
            data = {"extra": {"channel": "ssh", "raw_keys": list(outputs)}}
    finally:
        client.close()

    data["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return data


def test_connection(device: Device) -> tuple[bool, str]:
    started = time.perf_counter()
    try:
        client = _connect(device)
    except SshError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    try:
        profile = get_profile(device.model, device.vendor)
        probe_cmd = profile.cli.get("version", "show version")
        output = _run_exec(client, probe_cmd, max(10.0, device.timeout_ms / 1000 * 2))
    finally:
        client.close()

    elapsed = int((time.perf_counter() - started) * 1000)
    first = next((ln.strip() for ln in output.splitlines() if ln.strip()), "")
    if not first:
        return False, f"SSH 登录成功但 `{probe_cmd}` 没有输出,可能需要 enable 或账号权限不足"
    return True, f"{first[:140]} ({elapsed}ms)"
