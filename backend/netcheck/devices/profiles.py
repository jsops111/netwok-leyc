"""
设备型号画像 —— 「支持多种型号 / 多种版本」就落在这个文件里。

一台设备该采哪些 OID、走哪条 CLI 命令、哪些指标它**根本没有**,都由画像声明。
加一款新型号或新固件通常只改这里,不动模型和采集器。

三条设计约定:

1. **每个指标可以给多个候选 OID,按顺序试,第一个有值的赢。**
   Cisco 的 CPU 和内存在不同平台/固件上分布在不同 MIB 里
   (CISCO-PROCESS-MIB 新、OLD-CISCO-CPU-MIB 老;Cat9k 用
   CISCO-ENHANCED-MEMPOOL-MIB 而不是 CISCO-MEMORY-POOL-MIB),
   与其按版本号写 if/else,不如全都试一遍 —— 版本号本身还经常是错的
   (设备被升级了但 CMDB 没更新)。

2. **`optional` 里的指标采不到不算失败。**C9200L 现场普遍反馈
   ciscoEnvMonTemperature 表是空的(它的入风口传感器不一定注册到
   ENVMON MIB 里),那不是故障。这类字段在页面上显示 "—",
   区别于"采集失败"的红色 —— 混在一起会让人去查一个不存在的问题。

3. **计数器一律优先 64 位(ifHC*)。**48 口千兆交换机的 32 位 ifInOctets
   在满速下约 34 秒回绕一次,采集间隔 60 秒的话算出来的速率纯粹是噪声。
   64 位计数器才是唯一可用的选择,ifHC* 采不到再退回 32 位并在
   extra 里标注。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcheck.models import DeviceModel, Vendor

# ---------------------------------------------------------------- 通用 OID

SYS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "ifNumber": "1.3.6.1.2.1.2.1.0",
}

# IF-MIB / ifXTable。列名 → OID 前缀(walk 用)
IF_COLUMNS = {
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifType": "1.3.6.1.2.1.2.2.1.3",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5",  # 32 位,上限 4.29Gbps —— 万兆口读出来是错的
    "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifInDiscards": "1.3.6.1.2.1.2.2.1.13",
    "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
    "ifOutDiscards": "1.3.6.1.2.1.2.2.1.19",
    "ifOutErrors": "1.3.6.1.2.1.2.2.1.20",
    # ifXTable —— 64 位计数器和真实速率都在这里
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6",
    "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",  # 单位 Mbps,万兆口靠它
    "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
}

# 32 位回退列,ifHC* 取不到时用
IF_FALLBACK_COLUMNS = {
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
}

ENTITY_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.11"  # entPhysicalSerialNum

# ---------------------------------------------------------------- Cisco

# CISCO-PROCESS-MIB:cpmCPUTotal5minRev(表,按 CPU 索引)。
# Cat9k 是多核,取所有实例的最大值 —— 平均值会把一个跑满的核稀释掉。
CISCO_CPU_5MIN = "1.3.6.1.4.1.9.9.109.1.1.1.1.8"
CISCO_CPU_1MIN = "1.3.6.1.4.1.9.9.109.1.1.1.1.7"
CISCO_CPU_5SEC = "1.3.6.1.4.1.9.9.109.1.1.1.1.6"
CISCO_CPU_OLD_5MIN = "1.3.6.1.4.1.9.2.1.58.0"  # OLD-CISCO-CPU-MIB avgBusy5

# CISCO-ENHANCED-MEMPOOL-MIB(Cat9k / IOS-XE 用这套)
CISCO_MEM_ENH_USED = "1.3.6.1.4.1.9.9.221.1.1.1.1.7"
CISCO_MEM_ENH_FREE = "1.3.6.1.4.1.9.9.221.1.1.1.1.8"
# CISCO-MEMORY-POOL-MIB(老 IOS)
CISCO_MEM_POOL_USED = "1.3.6.1.4.1.9.9.48.1.1.1.5"
CISCO_MEM_POOL_FREE = "1.3.6.1.4.1.9.9.48.1.1.1.6"

# CISCO-ENVMON-MIB
CISCO_TEMP_VALUE = "1.3.6.1.4.1.9.9.13.1.3.1.3"
CISCO_TEMP_STATE = "1.3.6.1.4.1.9.9.13.1.3.1.6"  # 1=normal 2=warning 3=critical …
CISCO_PSU_STATE = "1.3.6.1.4.1.9.9.13.1.5.1.3"
CISCO_FAN_STATE = "1.3.6.1.4.1.9.9.13.1.4.1.3"

# ---------------------------------------------------------------- Fortinet

# FORTINET-FORTIGATE-MIB(enterprise 12356)
FG_CPU = "1.3.6.1.4.1.12356.101.4.1.3.0"
FG_MEM = "1.3.6.1.4.1.12356.101.4.1.4.0"
FG_DISK = "1.3.6.1.4.1.12356.101.4.1.6.0"
FG_SESSION = "1.3.6.1.4.1.12356.101.4.1.8.0"
FG_SESSION_RATE = "1.3.6.1.4.1.12356.101.4.1.10.0"  # fgSysSesRate1(每秒新建)
FG_VERSION = "1.3.6.1.4.1.12356.101.4.1.1.0"
FG_SERIAL = "1.3.6.1.4.1.12356.100.1.1.1.0"  # fnSysSerial
FG_HA_MODE = "1.3.6.1.4.1.12356.101.13.1.1.0"  # fgHaSystemMode
FG_VPN_TUNNEL_UP = "1.3.6.1.4.1.12356.101.12.1.2.0"
# fgHwSensorEntValue **不是温度表,是"所有硬件传感器"表**:温度(~40)、
# 风扇转速(~9000)、电压(~12)混在同一列里,量纲全不一样。
# 唯一能把它们分开的是同表的名字列 fgHwSensorEntName("CPU Temp" / "FAN1" /
# "+VCC3V3"),所以温度必须用 kind="table_max_named" 按名字筛完再取最大值。
FG_SENSOR_VALUE = "1.3.6.1.4.1.12356.101.4.3.2.1.3"  # fgHwSensorEntValue(表)
FG_SENSOR_NAME = "1.3.6.1.4.1.12356.101.4.3.2.1.2"  # fgHwSensorEntName(表)
FG_SENSOR_ALARM = "1.3.6.1.4.1.12356.101.4.3.2.1.4"


@dataclass
class MetricSpec:
    """
    一个整机指标怎么采。

    oids       候选 OID,按顺序试,第一个取到值的赢
    kind       scalar(单值) | table_max(表,取最大值) | table_sum(表,求和)
               | table_max_named(表,先按名字列筛掉别的行再取最大值)
    scale      取到的原始值乘这个系数(如 sysUpTime 的 timeticks → 秒)
    name_oid   同一张表的名字列,只有 table_max_named 用
    name_match 名字里出现其中任一子串(不分大小写)的行才算数

    ⚠ **一张表里混着不同量纲时必须用 table_max_named。**FortiGate 的
    fgHwSensorEntValue 把温度、风扇转速、电压放在同一列,直接 table_max
    赢的永远是风扇转速 —— 页面上是一排 9100、9300 的"温度",而且每一拍都
    撞穿 68℃ 的严重线刷告警。**实测踩出来的。**
    """

    oids: list[str]
    kind: str = "scalar"
    scale: float = 1.0
    name_oid: str = ""
    name_match: tuple[str, ...] = ()


@dataclass
class Profile:
    """一款型号的采集画像。"""

    key: str
    label: str
    vendor: str
    # 整机指标:字段名(对应 DeviceSample 的列)→ 怎么采
    metrics: dict[str, MetricSpec] = field(default_factory=dict)
    # 声明"这款设备没有这些指标",页面显示 "—" 而不是当成采集失败
    absent: set[str] = field(default_factory=set)
    # 采不到不算失败的字段
    optional: set[str] = field(default_factory=set)
    # SSH 通道用的命令表,阶段名 → 命令
    cli: dict[str, str] = field(default_factory=dict)
    # 进 CLI 后是否需要 enable
    cli_needs_enable: bool = False
    # 配置备份用的命令。**留空 = 这款型号不支持备份**,不要拿 cli["version"]
    # 之类的凑 —— 备份出一份不是配置的文本比没有备份糟得多:页面上看着有
    # 版本记录,真要回滚时才发现里面是 show version 的输出
    backup_cli: str = ""
    # 备份文本里**每次导出都会变但没有意义**的行。不去掉的话每次备份都被判成
    # "配置变更过",变更历史就退化成一天一条噪声(见 devices/backup.py 的
    # sanitize())。正则,按行匹配
    backup_volatile: tuple[str, ...] = ()
    # 防火墙策略的 SSH 命令。同样留空 = 不支持
    policy_cli: str = ""
    notes: str = ""


# ---------------------------------------------------------------- 画像定义

_CISCO_CAT9K_METRICS = {
    "cpu_pct": MetricSpec([CISCO_CPU_5MIN, CISCO_CPU_1MIN, CISCO_CPU_OLD_5MIN], kind="table_max"),
    # 内存使用率不是一个 OID,要 used/(used+free) 自己算 —— 采集器认这两个特殊键
    "mem_used": MetricSpec([CISCO_MEM_ENH_USED, CISCO_MEM_POOL_USED], kind="table_sum"),
    "mem_free": MetricSpec([CISCO_MEM_ENH_FREE, CISCO_MEM_POOL_FREE], kind="table_sum"),
    "temp_c": MetricSpec([CISCO_TEMP_VALUE], kind="table_max"),
    "uptime_s": MetricSpec([SYS["sysUpTime"]], scale=0.01),  # timeticks = 1/100 秒
    "psu_state": MetricSpec([CISCO_PSU_STATE], kind="table_max"),
    "fan_state": MetricSpec([CISCO_FAN_STATE], kind="table_max"),
}

_CISCO_CAT9K_CLI = {
    # IOS-XE 17.x。`| include` 而不是抓全量输出 —— show tech 级别的输出
    # 走 SSH 逐行读会拖到几十秒,采集间隔根本追不上
    "version": "show version | include Cisco IOS XE Software|Model Number|System Serial",
    "cpu": "show processes cpu sorted | include CPU utilization",
    "memory": "show processes memory | include Processor Pool|Total:",
    "temp": "show env temperature status",
    "power": "show env power",
    "interfaces": "show interfaces counters",
    "if_status": "show ip interface brief",
}

# Cisco 的 running-config。**需要 enable**(特权模式),普通 exec 模式下
# 这条命令直接报 "Invalid input detected"。
_CISCO_BACKUP_CLI = "show running-config"

# 每次导出都不一样的行:
#   ! Last configuration change at 12:00:01 CST Mon Sep 1 2025 by admin
#   ! NVRAM config last updated at ...
#   Current configuration : 24817 bytes
#   ntp clock-period 17179869      ← 这个每几分钟自己就变一次
# 不去掉的话每天备份都是"变更过",而真正被人改了配置的那一天混在里面看不出来
_CISCO_VOLATILE = (
    r"^\s*!\s*Last configuration change",
    r"^\s*!\s*NVRAM config last updated",
    r"^\s*Current configuration\s*:\s*\d+\s*bytes",
    r"^\s*Building configuration",
    r"^\s*ntp clock-period\s+\d+",
    r"^\s*!\s*Time:",
)

PROFILES: dict[str, Profile] = {
    # ---- 需求点名必须支持的四款 ----
    DeviceModel.C9300_48T: Profile(
        key=DeviceModel.C9300_48T,
        label="Cisco Catalyst C9300-48T",
        vendor=Vendor.CISCO,
        metrics=dict(_CISCO_CAT9K_METRICS),
        cli=dict(_CISCO_CAT9K_CLI),
        cli_needs_enable=True,
        backup_cli=_CISCO_BACKUP_CLI,
        backup_volatile=_CISCO_VOLATILE,
        absent={"session_count", "session_rate", "ha_state", "vpn_tunnels_up"},
        notes=(
            "48 个千兆电口。**必须用 ifHC* 64 位计数器**:48 口满速时 32 位的 "
            "ifInOctets 约 34 秒回绕一次,60 秒采集间隔算出的速率是噪声。"
            "开了 StackWise 时 CPU 表会有多个实例,取最大值。"
        ),
    ),
    DeviceModel.C9300_24T: Profile(
        key=DeviceModel.C9300_24T,
        label="Cisco Catalyst C9300-24T",
        vendor=Vendor.CISCO,
        metrics=dict(_CISCO_CAT9K_METRICS),
        cli=dict(_CISCO_CAT9K_CLI),
        cli_needs_enable=True,
        backup_cli=_CISCO_BACKUP_CLI,
        backup_volatile=_CISCO_VOLATILE,
        absent={"session_count", "session_rate", "ha_state", "vpn_tunnels_up"},
        notes="和 C9300-48T 同一套采集,区别只是口数。",
    ),
    DeviceModel.C9200L_24T_4G: Profile(
        key=DeviceModel.C9200L_24T_4G,
        label="Cisco Catalyst C9200L-24T-4G",
        vendor=Vendor.CISCO,
        metrics=dict(_CISCO_CAT9K_METRICS),
        cli=dict(_CISCO_CAT9K_CLI),
        cli_needs_enable=True,
        backup_cli=_CISCO_BACKUP_CLI,
        backup_volatile=_CISCO_VOLATILE,
        absent={"session_count", "session_rate", "ha_state", "vpn_tunnels_up"},
        # 温度和电源在 C9200L 上经常采不到:它是固定配置的入门款,
        # 入风口传感器和内置电源不一定注册进 ENVMON MIB。
        # 放进 optional 而不是 absent —— 有的固件版本是有的,能采就采。
        optional={"temp_c", "psu_state", "fan_state"},
        notes=(
            "24 个千兆电口 + 4 个千兆 SFP 上行。ENVMON 的温度/电源表在这款上"
            "经常是空的(取决于固件),所以它们是 optional:采不到显示 —,"
            "不判成故障。上行 SFP 口的 ifHighSpeed 是 1000。"
        ),
    ),
    DeviceModel.FORTIGATE_401F: Profile(
        key=DeviceModel.FORTIGATE_401F,
        label="FortiGate-401F",
        vendor=Vendor.FORTINET,
        metrics={
            "cpu_pct": MetricSpec([FG_CPU]),
            "mem_pct": MetricSpec([FG_MEM]),
            "session_count": MetricSpec([FG_SESSION]),
            "session_rate": MetricSpec([FG_SESSION_RATE]),
            "vpn_tunnels_up": MetricSpec([FG_VPN_TUNNEL_UP]),
            # 按名字筛出温度传感器再取最大值。401F 上典型是
            # "CPU Temp" / "SYS Temp" / "PS1 Temp";同一张表里还有
            # "FAN1"(转速)和 "+VCC3V3"(电压),不筛掉就会把转速当温度。
            # 遇到名字不带 temp 的温度传感器,往 name_match 里加一项。
            "temp_c": MetricSpec(
                [FG_SENSOR_VALUE], kind="table_max_named",
                name_oid=FG_SENSOR_NAME, name_match=("temp",),
            ),
            "uptime_s": MetricSpec([SYS["sysUpTime"]], scale=0.01),
        },
        cli={
            # FortiOS 的 get/diagnose,不是 show
            "version": "get system status",
            "performance": "get system performance status",
            "session": "diagnose sys session stat",
            "ha": "get system ha status",
            "interfaces": "diagnose netlink brief",
        },
        # **用 `show` 而不是 `show full-configuration`。**后者把所有默认值也
        # 打出来,401F 上是几 MB、十几万行 —— 走 SSH 读完要好几分钟,而且
        # diff 里全是默认值的噪声。`show` 只输出偏离默认的部分,那才是
        # "这台设备被配成了什么样"。
        # 配了 API Token 时备份会**优先走 API**(见 devices/backup.py):
        # config/backup 端点给的是能直接回灌的备份文件,CLI 输出不是。
        backup_cli="show",
        # #conf_file_ver 每次导出都变(它带时间戳性质的序号)。
        # buildno / vdom 那几行**要留着** —— 固件升级本身就是该被记录的变更
        backup_volatile=(r"^\s*#conf_file_ver=",),
        policy_cli="show firewall policy",
        optional={"temp_c", "vpn_tunnels_up"},
        notes=(
            "FortiOS 7.x。**推荐 collect_method=api、fallback=snmp**:"
            "会话数、策略命中、HA 成员状态、License 到期只有 REST API 能拿全,"
            "SNMP 的 fgSysSesCount 只有总数。fgHwSensorEntValue 表里温度、"
            "风扇转速、电压混在一起,温度靠 fgHwSensorEntName 筛出来再取最大值,"
            "**不能对整张表取最大值**(拿到的会是风扇的 9000+ RPM)。"
            "多 VDOM 环境下 SNMP 拿到的是全局值,按 VDOM 拆分必须走 API。"
        ),
    ),
    # ---- 兜底画像:同厂同系但不在册的型号 ----
    DeviceModel.GENERIC_CISCO: Profile(
        key=DeviceModel.GENERIC_CISCO,
        label="Cisco 通用",
        vendor=Vendor.CISCO,
        metrics=dict(_CISCO_CAT9K_METRICS),
        cli=dict(_CISCO_CAT9K_CLI),
        cli_needs_enable=True,
        backup_cli=_CISCO_BACKUP_CLI,
        backup_volatile=_CISCO_VOLATILE,
        optional={"temp_c", "psu_state", "fan_state"},
        notes="没在册的 Cisco 设备。能采到的照采,采不到的留空,不因为型号不认识就整台不采。",
    ),
    DeviceModel.GENERIC_FORTIGATE: Profile(
        key=DeviceModel.GENERIC_FORTIGATE,
        label="FortiGate 通用",
        vendor=Vendor.FORTINET,
        metrics={
            "cpu_pct": MetricSpec([FG_CPU]),
            "mem_pct": MetricSpec([FG_MEM]),
            "session_count": MetricSpec([FG_SESSION]),
            "session_rate": MetricSpec([FG_SESSION_RATE]),
            "uptime_s": MetricSpec([SYS["sysUpTime"]], scale=0.01),
        },
        cli={
            "version": "get system status",
            "performance": "get system performance status",
            "ha": "get system ha status",
        },
        backup_cli="show",
        backup_volatile=(r"^\s*#conf_file_ver=",),
        policy_cli="show firewall policy",
        optional={"temp_c", "vpn_tunnels_up", "session_rate"},
        notes="没在册的 FortiGate 型号。",
    ),
    DeviceModel.GENERIC_SNMP: Profile(
        key=DeviceModel.GENERIC_SNMP,
        label="通用 SNMP 设备",
        vendor=Vendor.GENERIC,
        metrics={"uptime_s": MetricSpec([SYS["sysUpTime"]], scale=0.01)},
        optional={"cpu_pct", "mem_pct", "temp_c"},
        absent={"session_count", "session_rate", "ha_state", "vpn_tunnels_up"},
        # backup_cli 故意留空:不知道是什么设备就不知道该敲什么命令,
        # 而随便敲一条命令把输出当配置存起来是在制造一份假备份
        notes=(
            "只采 RFC1213 + IF-MIB 通用部分:通断、接口流量、运行时长。"
            "CPU/内存是厂商私有 MIB,通用画像拿不到。**不支持配置备份和策略同步** ——"
            "备份命令因厂商而异,认不出型号时随便敲一条命令存下来的是假备份。"
            "华为/H3C 之类要用备份功能的话,在这个文件里加一款画像("
            "display current-configuration / display current-configuration)。"
        ),
    ),
}


def get_profile(model: str, vendor: str = "") -> Profile:
    """
    取画像。型号不在册时按厂商回落到通用画像 —— 不认识的型号也要能采,
    这是「支持多种版本」的下半句:在册的采全,不在册的采通用部分。
    """

    if model in PROFILES:
        return PROFILES[model]
    if vendor == Vendor.CISCO:
        return PROFILES[DeviceModel.GENERIC_CISCO]
    if vendor == Vendor.FORTINET:
        return PROFILES[DeviceModel.GENERIC_FORTIGATE]
    return PROFILES[DeviceModel.GENERIC_SNMP]
