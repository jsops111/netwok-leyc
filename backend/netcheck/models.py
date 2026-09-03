"""
network-check 数据模型。

分六组:

    线路拨测   ProbeGroup → ProbeTarget → ProbeSample(原始秒级) → ProbeRollup(降采样)
    设备采集   Device → DeviceSample / DeviceInterface → InterfaceSample
    服务器采集 Server → ServerSample / ServerInterface(只走 SSH,不装 agent)
    配置备份   Device → DeviceBackup(**一行一个配置版本**,不是一行一次备份)
    防火墙策略 Device → FirewallPolicy(只读快照,全量替换式同步)
    事件       Event —— 拨测/设备/服务器共用一张事件表,靠 source_type 区分
    通知       Notifier → NotifyLog

时序数据的取舍(见 CLAUDE.md「时序存储」):原始秒级点只保留
settings.NETCHECK_RAW_RETENTION_HOURS 小时供大图细看,长期趋势查 ProbeRollup。
**不要为了"省事"直接查 ProbeSample 画长时间跨度的图** —— 一条 1 秒频率的线路
一天就是 86400 行,十条线路一周的原始点扫一遍就够让接口超时。
"""

from __future__ import annotations

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models import Value
from django.db.models.functions import Coalesce

from core.crypto import EncryptedTextField
from core.models import BaseModel


# =========================================================================
# 枚举 —— 全部只定义在后端,前端通过 /api/meta/choices/ 取
# =========================================================================


class Protocol(models.TextChoices):
    ICMP = "icmp", "ICMP Ping"
    TCP = "tcp", "TCP 端口"
    UDP = "udp", "UDP 端口"
    HTTP = "http", "HTTP"
    HTTPS = "https", "HTTPS"
    DNS = "dns", "DNS 解析"


class LinkState(models.TextChoices):
    """线路/设备的当前状态。degraded 是"通但不达标"(丢包、延迟或抖动超阈值)。"""

    UNKNOWN = "unknown", "未知"
    UP = "up", "正常"
    DEGRADED = "degraded", "劣化"
    DOWN = "down", "中断"


class Severity(models.TextChoices):
    INFO = "info", "提示"
    WARNING = "warning", "警告"
    CRITICAL = "critical", "严重"


class EventKind(models.TextChoices):
    """
    事件类型。前五项对应大屏顶部那排计数(断线/丢包/延迟/抖动/异常),
    **改动这五个的 value 会让顶部统计对不上**,要一起改前端 KIND_TILES。
    """

    DOWN = "down", "断线"
    LOSS = "loss", "丢包"
    LATENCY = "latency", "延迟"
    JITTER = "jitter", "抖动"
    ANOMALY = "anomaly", "异常"
    # 设备侧
    DEVICE_DOWN = "device_down", "设备失联"
    CPU_HIGH = "cpu_high", "CPU 过高"
    MEM_HIGH = "mem_high", "内存过高"
    TEMP_HIGH = "temp_high", "温度过高"
    IF_DOWN = "if_down", "接口 Down"
    IF_ERROR = "if_error", "接口错包"
    IF_SATURATED = "if_saturated", "接口带宽饱和"
    HA_CHANGE = "ha_change", "HA 状态切换"
    SESSION_HIGH = "session_high", "会话数过高"
    PSU_FAULT = "psu_fault", "电源异常"
    # 服务器侧(SSH 采集)
    SERVER_DOWN = "server_down", "服务器失联"
    DISK_HIGH = "disk_high", "磁盘空间不足"
    LOAD_HIGH = "load_high", "负载过高"
    # 配置备份 —— 这两个是**瞬时事件**,不走连续次数的开/关流程,
    # 见 events/engine.py 的 record_point_event()
    BACKUP_FAILED = "backup_failed", "配置备份失败"
    CONFIG_CHANGED = "config_changed", "配置发生变更"
    CONFIG_UNSAVED = "config_unsaved", "配置未保存"
    NEIGHBOR_CHANGE = "neighbor_change", "邻居变化"


class SourceType(models.TextChoices):
    PROBE = "probe", "线路拨测"
    DEVICE = "device", "设备"
    INTERFACE = "interface", "设备接口"
    SERVER = "server", "服务器"


class DeviceKind(models.TextChoices):
    SWITCH = "switch", "交换机"
    FIREWALL = "firewall", "防火墙"
    ROUTER = "router", "路由器"


class Vendor(models.TextChoices):
    CISCO = "cisco", "Cisco"
    FORTINET = "fortinet", "Fortinet"
    HUAWEI = "huawei", "华为"
    H3C = "h3c", "H3C"
    GENERIC = "generic", "通用 SNMP"


class DeviceModel(models.TextChoices):
    """
    在册型号。需求点名必须支持的四款列在最前面 —— 它们各自有独立的采集画像
    (见 netcheck/devices/profiles.py):OID 差异、CLI 命令差异、以及
    C9200L 那种"没有独立温度传感器 OID"的缺项都在画像里声明。

    GENERIC_* 是兜底:同厂同系但不在册的型号走通用画像,能采到的照采,
    采不到的字段留空 —— 不因为型号不认识就整台设备不采。
    """

    # 交换机(Cisco Catalyst 9000 系列)
    C9300_48T = "c9300-48t", "Cisco C9300-48T"
    C9300_24T = "c9300-24t", "Cisco C9300-24T"
    C9200L_24T_4G = "c9200l-24t-4g", "Cisco C9200L-24T-4G"
    # 防火墙(Fortinet)
    FORTIGATE_401F = "fortigate-401f", "FortiGate-401F"
    # 兜底
    GENERIC_CISCO = "generic-cisco", "Cisco 通用"
    GENERIC_FORTIGATE = "generic-fortigate", "FortiGate 通用"
    GENERIC_SNMP = "generic-snmp", "通用 SNMP 设备"


class CollectMethod(models.TextChoices):
    SNMP = "snmp", "SNMP"
    SSH = "ssh", "SSH CLI"
    API = "api", "REST API"


class SnmpVersion(models.TextChoices):
    V2C = "2c", "SNMP v2c"
    V3 = "3", "SNMP v3"


class SnmpSecLevel(models.TextChoices):
    NO_AUTH = "noAuthNoPriv", "不认证不加密"
    AUTH_ONLY = "authNoPriv", "认证不加密"
    AUTH_PRIV = "authPriv", "认证并加密"


class ServerOS(models.TextChoices):
    """
    被监控主机的系统类型 —— **决定走哪一套采集命令**,不是一个展示标签。

    Linux 读 /proc,ESXi 读 esxcli / vim-cmd:两套命令没有一条是通用的。
    分不开的后果实测过一次:ESXi 的 shell 能跑 `echo`,所以分段标记全都
    出现了,而 `cat /proc/stat`、`cat /proc/meminfo` 一个都不存在 ——
    采集器认为"连上了、命令跑了",于是这台机器状态是 UP、每个指标是空的、
    **last_error 也是空的**。没有任何一个地方会报错。

    所以这个字段没有"自动探测"选项:探测失败时的退路仍然是猜,而猜错的
    表现就是上面那种"安静的空"。让人选一次,选错了第一次「测试」就会说清楚。
    """

    LINUX = "linux", "Linux / 类 Unix"
    ESXI = "esxi", "VMware ESXi"


class RollupBucket(models.TextChoices):
    M1 = "1m", "1 分钟"
    M5 = "5m", "5 分钟"
    H1 = "1h", "1 小时"


class NotifierKind(models.TextChoices):
    TELEGRAM = "telegram", "Telegram"
    WEBHOOK = "webhook", "Webhook"


class BackupStatus(models.TextChoices):
    """一次配置备份的结果。NEVER 是"还没备过",和"备份失败"要分得开。"""

    NEVER = "never", "从未备份"
    OK = "ok", "成功"
    FAILED = "failed", "失败"


class PolicyAction(models.TextChoices):
    """
    防火墙策略动作。**归一化过**:FortiOS 的 deny 和某些型号报的 drop
    是同一件事,页面上不该出现两个看着不一样的"拒绝"。认不出的落到 OTHER,
    原始字符串留在 raw 里 —— 不认识的动作宁可显示"其它"也不要猜成"允许"。
    """

    ACCEPT = "accept", "允许"
    DENY = "deny", "拒绝"
    IPSEC = "ipsec", "IPsec"
    OTHER = "other", "其它"


# =========================================================================
# 线路拨测
# =========================================================================


class ProbeGroup(BaseModel):
    """
    监控类 —— 大屏上"一个监控类一个大图"里的那个类。

    典型分法:互联网出口 / 专线 / 内网核心 / DNS / 业务域名。分组只影响展示
    聚合与图表分块,不影响探测本身。
    """

    name = models.CharField("名称", max_length=64, unique=True)
    description = models.CharField("说明", max_length=255, blank=True)
    # 大图里这条分组的强调色。留空则前端按 CATEGORICAL 色板按序分配 ——
    # 手填的值不参与色板校验,别填高饱和亮色(深色底上会发晕)
    color = models.CharField("强调色", max_length=16, blank=True)
    order = models.IntegerField("排序", default=0, db_index=True)
    enabled = models.BooleanField("启用", default=True)

    class Meta:
        verbose_name = verbose_name_plural = "监控类"
        ordering = ["order", "id"]

    def __str__(self) -> str:
        return self.name


class ProbeTarget(BaseModel):
    """
    一条被检测的线路。

    「频率按秒」是需求硬要求,所以 interval_seconds 最小值是 1 —— 但它同时
    受 settings.NETCHECK_TICK_SECONDS 约束:tick 是 5 秒的话,填 1 也只能
    每 5 秒探一次。派发器不会为了追上频率而在一拍里补跑多次(那样只会把
    worker 打满,画出来的图还是稀的)。
    """

    group = models.ForeignKey(
        ProbeGroup, on_delete=models.PROTECT, related_name="targets", verbose_name="监控类"
    )
    name = models.CharField("线路名称", max_length=128)
    host = models.CharField("目标地址", max_length=255, help_text="IP 或域名")
    protocol = models.CharField("协议", max_length=8, choices=Protocol.choices, default=Protocol.ICMP)
    port = models.IntegerField(
        "端口",
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(65535)],
        help_text="ICMP 不需要;TCP/UDP 必填;HTTP/HTTPS/DNS 留空则用协议默认端口",
    )
    interval_seconds = models.IntegerField(
        "检测频率(秒)", default=10, validators=[MinValueValidator(1), MaxValueValidator(86400)]
    )
    timeout_ms = models.IntegerField(
        "单次超时(毫秒)", default=2000, validators=[MinValueValidator(100), MaxValueValidator(60000)]
    )
    packets = models.IntegerField(
        "每次发包数",
        default=5,
        validators=[MinValueValidator(1), MaxValueValidator(50)],
        help_text="ICMP/UDP 有效。丢包率和抖动都是从这一组包里算出来的,填 1 就只有通断没有丢包率",
    )

    # ---- 协议专属参数 ----
    http_path = models.CharField("HTTP 路径", max_length=255, blank=True, default="/")
    http_method = models.CharField("HTTP 方法", max_length=8, blank=True, default="GET")
    http_expect_code = models.IntegerField("期望状态码", default=200)
    http_expect_keyword = models.CharField(
        "期望响应关键字", max_length=128, blank=True, help_text="留空不校验;填了则响应体必须包含它,否则记异常"
    )
    http_verify_tls = models.BooleanField("校验 TLS 证书", default=False)
    dns_query = models.CharField("DNS 查询域名", max_length=255, blank=True)
    dns_expect = models.CharField(
        "DNS 期望结果", max_length=255, blank=True, help_text="留空只要求解析成功;填了则解析结果必须包含它"
    )

    # ---- 阈值 ----
    # 阈值分 warn / crit 两档:warn 记 degraded 事件(警告),crit 记严重。
    # 全为 0 表示不判这一项。
    latency_warn_ms = models.IntegerField("延迟警告线(ms)", default=100)
    latency_crit_ms = models.IntegerField("延迟严重线(ms)", default=300)
    loss_warn_pct = models.FloatField("丢包警告线(%)", default=5)
    loss_crit_pct = models.FloatField("丢包严重线(%)", default=20)
    jitter_warn_ms = models.IntegerField("抖动警告线(ms)", default=30)
    jitter_crit_ms = models.IntegerField("抖动严重线(ms)", default=100)

    # ---- 事件抖动抑制 ----
    # 单次失败就报警会被瞬时丢包刷爆。连续 fail_threshold 次判定失败才开事件,
    # 连续 recover_threshold 次正常才关事件并推恢复。
    fail_threshold = models.IntegerField("连续失败次数开事件", default=3, validators=[MinValueValidator(1)])
    recover_threshold = models.IntegerField("连续正常次数关事件", default=3, validators=[MinValueValidator(1)])

    enabled = models.BooleanField("启用", default=True, db_index=True)
    order = models.IntegerField("排序", default=0)

    # ---- 运行时状态(由采集器回写,不要在页面上手改) ----
    state = models.CharField(
        "当前状态", max_length=12, choices=LinkState.choices, default=LinkState.UNKNOWN, db_index=True
    )
    last_checked_at = models.DateTimeField("最后检测时间", null=True, blank=True)
    last_rtt_ms = models.FloatField("最后延迟(ms)", null=True, blank=True)
    last_loss_pct = models.FloatField("最后丢包率(%)", null=True, blank=True)
    last_jitter_ms = models.FloatField("最后抖动(ms)", null=True, blank=True)
    last_error = models.CharField("最后错误", max_length=255, blank=True)
    consecutive_fail = models.IntegerField("连续失败次数", default=0)
    consecutive_ok = models.IntegerField("连续正常次数", default=0)
    # 累计量,给"可用率"用。事件次数不在这里数 —— 那个按时间窗从 Event 表聚合,
    # 否则页面上没法看"最近 1 小时断了几次"。
    total_checks = models.BigIntegerField("累计检测次数", default=0)
    total_fail = models.BigIntegerField("累计失败次数", default=0)

    class Meta:
        verbose_name = verbose_name_plural = "检测线路"
        ordering = ["group__order", "order", "id"]
        indexes = [models.Index(fields=["enabled", "state"])]
        constraints = [
            # 同一个监控类里不允许重复的端点;跨监控类允许 —— 现实中"出口探测"
            # 和"专线探测"两个分组各 ping 同一个对端是合理的配置。
            #
            # **必须用 Coalesce 把 port 的 NULL 折成 0。**PostgreSQL 里
            # NULL != NULL,所以 fields=["host","protocol","port"] 这种写法
            # 对 ICMP 线路(port 恒为 NULL)完全不生效 —— 同一个地址能无限添加。
            # 这一条是实测发现的:约束在那儿,但一行都没挡住。
            models.UniqueConstraint(
                "group",
                "host",
                "protocol",
                Coalesce("port", Value(0)),
                name="uniq_probe_endpoint_in_group",
            )
        ]

    def __str__(self) -> str:
        return f"{self.name}({self.host})"

    @property
    def availability(self) -> float:
        if not self.total_checks:
            return 0.0
        return round((self.total_checks - self.total_fail) / self.total_checks * 100, 3)

    def clean(self):
        """
        跨字段校验。

        **同样的规则必须在 ProbeTargetSerializer.validate() 里再写一遍** ——
        DRF 从不调用 full_clean(),只有 clean() 的话 API 写入这条就是死代码。
        """
        from django.core.exceptions import ValidationError

        errors = {}
        if self.protocol in (Protocol.TCP, Protocol.UDP) and not self.port:
            errors["port"] = f"{self.get_protocol_display()} 必须指定端口"
        if self.protocol == Protocol.DNS and not self.dns_query:
            errors["dns_query"] = "DNS 检测必须填写要查询的域名"
        if self.latency_crit_ms and self.latency_warn_ms > self.latency_crit_ms:
            errors["latency_warn_ms"] = "警告线不能高于严重线"
        if self.loss_crit_pct and self.loss_warn_pct > self.loss_crit_pct:
            errors["loss_warn_pct"] = "警告线不能高于严重线"
        if self.jitter_crit_ms and self.jitter_warn_ms > self.jitter_crit_ms:
            errors["jitter_warn_ms"] = "警告线不能高于严重线"
        if errors:
            raise ValidationError(errors)


class ProbeSample(models.Model):
    """
    一次拨测的原始结果。**这张表写入极频繁**,所以:
      - 不继承 BaseModel(不需要 updated_at / meta,省两列写入)
      - 只建 (target, ts) 复合索引,别再往上加索引
      - 过期数据由 purge_raw_samples 按 ts 批量删
    """

    target = models.ForeignKey(
        ProbeTarget, on_delete=models.CASCADE, related_name="samples", verbose_name="线路"
    )
    ts = models.DateTimeField("采样时间", db_index=True)
    ok = models.BooleanField("是否通", default=True)
    # 失败时 rtt 为空,不要写 0 —— 0 会把平均延迟拉低,图上看着比实际好
    rtt_ms = models.FloatField("延迟(ms)", null=True, blank=True)
    rtt_min_ms = models.FloatField("最小延迟(ms)", null=True, blank=True)
    rtt_max_ms = models.FloatField("最大延迟(ms)", null=True, blank=True)
    loss_pct = models.FloatField("丢包率(%)", default=0)
    jitter_ms = models.FloatField("抖动(ms)", null=True, blank=True)
    state = models.CharField("判定状态", max_length=12, choices=LinkState.choices, default=LinkState.UP)
    error_kind = models.CharField("错误类型", max_length=32, blank=True)
    error = models.CharField("错误信息", max_length=255, blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "拨测样本"
        ordering = ["-ts"]
        indexes = [models.Index(fields=["target", "-ts"], name="idx_sample_target_ts")]

    def __str__(self) -> str:
        return f"{self.target_id}@{self.ts:%H:%M:%S}"


class ProbeRollup(models.Model):
    """
    降采样桶。1m 桶由原始样本聚合,5m/1h 桶再由 1m 桶聚合(不重扫原始表)。

    p95 存成一列是有意的:图上要画"绝大多数请求有多慢",平均值会被个别
    超时点带偏,而算 p95 需要全量点 —— 原始点删掉之后就再也算不回来了。
    """

    target = models.ForeignKey(
        ProbeTarget, on_delete=models.CASCADE, related_name="rollups", verbose_name="线路"
    )
    bucket = models.CharField("粒度", max_length=4, choices=RollupBucket.choices)
    ts = models.DateTimeField("桶起始时间")
    samples = models.IntegerField("样本数", default=0)
    ok_count = models.IntegerField("正常数", default=0)
    fail_count = models.IntegerField("失败数", default=0)
    rtt_avg_ms = models.FloatField("平均延迟", null=True, blank=True)
    rtt_min_ms = models.FloatField("最小延迟", null=True, blank=True)
    rtt_max_ms = models.FloatField("最大延迟", null=True, blank=True)
    rtt_p95_ms = models.FloatField("P95 延迟", null=True, blank=True)
    loss_avg_pct = models.FloatField("平均丢包率", default=0)
    loss_max_pct = models.FloatField("最大丢包率", default=0)
    jitter_avg_ms = models.FloatField("平均抖动", null=True, blank=True)
    jitter_max_ms = models.FloatField("最大抖动", null=True, blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "拨测聚合"
        ordering = ["-ts"]
        constraints = [
            models.UniqueConstraint(fields=["target", "bucket", "ts"], name="uniq_rollup_bucket")
        ]
        indexes = [models.Index(fields=["target", "bucket", "-ts"], name="idx_rollup_lookup")]

    @property
    def availability(self) -> float:
        return round(self.ok_count / self.samples * 100, 3) if self.samples else 0.0


# =========================================================================
# 设备采集(交换机 / 防火墙)
# =========================================================================


class Device(BaseModel):
    """
    一台被监控的网络设备。

    「支持多种版本」的落地方式:型号(model)决定采集画像 —— 采哪些 OID、
    走哪条 CLI 命令;os_version 只用于**画像内部的分支**和页面展示。
    也就是说加一个新固件版本通常不用改这张表,改 devices/profiles.py 就够。

    三条采集通道(snmp / ssh / api)按 collect_method 选一条主通道,
    fallback_method 是主通道失败时的降级通道 —— 留空表示不降级。
    FortiGate 的典型配法是 api 主 + snmp 降级:REST API 能拿到会话数、
    策略命中、HA 状态、License 到期,SNMP 拿不到;反过来 API token 过期时
    SNMP 至少还能告诉你设备是活的。
    """

    name = models.CharField("设备名称", max_length=128, unique=True)
    kind = models.CharField("设备类型", max_length=12, choices=DeviceKind.choices, db_index=True)
    vendor = models.CharField("厂商", max_length=16, choices=Vendor.choices, default=Vendor.CISCO)
    model = models.CharField(
        "型号", max_length=32, choices=DeviceModel.choices, default=DeviceModel.GENERIC_SNMP
    )
    mgmt_ip = models.GenericIPAddressField("管理地址", db_index=True)
    site = models.CharField("机房/位置", max_length=64, blank=True)
    os_version = models.CharField(
        "固件版本", max_length=64, blank=True, help_text="如 17.09.04a / v7.4.4;留空则首次采集后自动回填"
    )
    serial = models.CharField("序列号", max_length=64, blank=True)

    collect_method = models.CharField(
        "采集方式", max_length=8, choices=CollectMethod.choices, default=CollectMethod.SNMP
    )
    fallback_method = models.CharField(
        "降级采集方式", max_length=8, choices=CollectMethod.choices, blank=True
    )
    interval_seconds = models.IntegerField(
        "采集频率(秒)",
        default=60,
        validators=[MinValueValidator(10), MaxValueValidator(86400)],
        help_text="设备采集比线路拨测重得多(一次要走几十个 OID),最小 10 秒",
    )
    timeout_ms = models.IntegerField("超时(毫秒)", default=5000)

    # ---- SNMP 凭据 ----
    snmp_port = models.IntegerField("SNMP 端口", default=161)
    snmp_version = models.CharField(
        "SNMP 版本", max_length=4, choices=SnmpVersion.choices, default=SnmpVersion.V2C
    )
    snmp_community = EncryptedTextField("SNMP Community", blank=True, default="")
    # v3 才用得到下面五项
    snmp_v3_user = models.CharField("v3 用户名", max_length=64, blank=True)
    snmp_v3_level = models.CharField(
        "v3 安全级别", max_length=16, choices=SnmpSecLevel.choices, blank=True
    )
    snmp_v3_auth_proto = models.CharField(
        "v3 认证算法", max_length=16, blank=True, help_text="MD5 / SHA / SHA224 / SHA256 / SHA384 / SHA512"
    )
    snmp_v3_auth_key = EncryptedTextField("v3 认证口令", blank=True, default="")
    snmp_v3_priv_proto = models.CharField(
        "v3 加密算法", max_length=16, blank=True, help_text="DES / 3DES / AES / AES192 / AES256"
    )
    snmp_v3_priv_key = EncryptedTextField("v3 加密口令", blank=True, default="")

    # ---- SSH 凭据 ----
    ssh_port = models.IntegerField("SSH 端口", default=22)
    ssh_username = models.CharField("SSH 用户名", max_length=64, blank=True)
    ssh_password = EncryptedTextField("SSH 密码", blank=True, default="")
    ssh_private_key = EncryptedTextField("SSH 私钥", blank=True, default="")
    ssh_enable_password = EncryptedTextField(
        "enable 密码", blank=True, default="", help_text="Cisco 需要进 enable 模式时填"
    )

    # ---- REST API 凭据(FortiGate) ----
    api_scheme = models.CharField("API 协议", max_length=8, blank=True, default="https")
    api_port = models.IntegerField("API 端口", null=True, blank=True, default=443)
    api_token = EncryptedTextField(
        "API Token", blank=True, default="", help_text="FortiGate:系统 → 管理员 → REST API 管理员生成的 token"
    )
    api_vdom = models.CharField(
        "VDOM", max_length=64, blank=True, default="root", help_text="FortiGate 多 VDOM 时指定;单 VDOM 填 root"
    )
    api_verify_tls = models.BooleanField("校验 API 证书", default=False)

    # ---- 阈值 ----
    cpu_warn_pct = models.IntegerField("CPU 警告线(%)", default=75)
    cpu_crit_pct = models.IntegerField("CPU 严重线(%)", default=90)
    mem_warn_pct = models.IntegerField("内存警告线(%)", default=80)
    mem_crit_pct = models.IntegerField("内存严重线(%)", default=92)
    temp_warn_c = models.IntegerField("温度警告线(℃)", default=55)
    temp_crit_c = models.IntegerField("温度严重线(℃)", default=68)
    session_warn = models.BigIntegerField(
        "会话数警告线", default=0, help_text="防火墙有效;0 表示不判。401F 满配约 400 万并发"
    )
    if_util_warn_pct = models.IntegerField(
        "接口带宽警告线(%)", default=80, help_text="出/入方向任一超过即记饱和事件"
    )

    # ---- 配置备份 ----
    # 备份**不走 collect_method**:采指标可以用 SNMP,但 SNMP 拿不到配置文本。
    # 备份通道是 SSH(Cisco `show running-config` / FortiOS `show`),
    # FortiGate 配了 API token 时优先走 API 的 config/backup 端点(拿到的是
    # 可直接回灌的备份文件,CLI 输出不是)。见 devices/backup.py。
    backup_enabled = models.BooleanField(
        "启用配置备份", default=False,
        help_text="需要 SSH 凭据(FortiGate 也可用 API Token)。型号画像里没定义备份命令的型号开了也备不了",
    )
    backup_interval_hours = models.IntegerField(
        "备份间隔(小时)", default=24,
        validators=[MinValueValidator(1), MaxValueValidator(8760)],
        help_text="配置不是时序数据,一天一次足够。改配置后想立刻留档用页面上的「立即备份」",
    )
    backup_keep = models.IntegerField(
        "保留版本数", default=20, validators=[MinValueValidator(1), MaxValueValidator(500)],
        help_text="**只数「变更过的版本」**:配置没变不会新增版本,所以 20 个版本通常够回溯很久",
    )
    backup_check_unsaved = models.BooleanField(
        "检查配置是否未保存", default=True,
        help_text=(
            "只对 Cisco 有效(比对 running-config 和 startup-config)。"
            "**代价是每次备份多取一份配置**,时间大约翻倍。"
            "FortiOS 改完即存,没有这个概念"
        ),
    )
    # 三态:True=有未保存的改动 / False=已保存 / None=没检查过(或不支持)。
    # **None 不能显示成"已保存"** —— 那是在替设备做一个我们没验证过的保证
    config_unsaved = models.BooleanField("配置未保存", null=True, blank=True)
    config_unsaved_lines = models.IntegerField(
        "未保存的差异行数", null=True, blank=True,
        help_text="running 和 startup 之间的差异行数。具体 diff 在 meta.unsaved_diff 里",
    )
    config_checked_at = models.DateTimeField("最后检查时间", null=True, blank=True)

    last_backup_at = models.DateTimeField("最后备份时间", null=True, blank=True)
    last_backup_status = models.CharField(
        "最后备份结果", max_length=8, choices=BackupStatus.choices, default=BackupStatus.NEVER
    )
    last_backup_error = models.CharField("最后备份错误", max_length=255, blank=True)

    # ---- 防火墙策略同步 ----
    # 只对 kind=firewall 有意义。同步是**全量替换**:设备上删掉的策略
    # 在这边也要消失,否则页面上会留着一条现实中已经不存在的规则 ——
    # 那比没有这个页面更危险。
    policy_sync_enabled = models.BooleanField(
        "同步防火墙策略", default=False,
        help_text="仅防火墙。FortiGate 走 API(带命中计数)或 SSH(只有配置,没有命中数)",
    )
    policy_sync_interval_minutes = models.IntegerField(
        "策略同步间隔(分钟)", default=30,
        validators=[MinValueValidator(5), MaxValueValidator(1440)],
        help_text="策略表几百条起,一次同步要拉两个端点;5 分钟以下没有意义",
    )
    last_policy_sync_at = models.DateTimeField("最后策略同步时间", null=True, blank=True)
    last_policy_error = models.CharField("最后策略同步错误", max_length=255, blank=True)
    policy_count = models.IntegerField("策略条数", default=0)

    fail_threshold = models.IntegerField("连续失败次数开事件", default=2, validators=[MinValueValidator(1)])
    recover_threshold = models.IntegerField("连续正常次数关事件", default=2, validators=[MinValueValidator(1)])

    collect_interfaces = models.BooleanField(
        "采集接口明细", default=True, help_text="48 口设备一次要走近百个 OID;只关心整机指标可以关掉"
    )
    collect_neighbors = models.BooleanField(
        "采集邻居(LLDP/CDP)", default=True,
        help_text=(
            "「这个口对面接的是谁」。多走两张表(LLDP + CDP),"
            "邻居关系变化很慢所以代价不大 —— 但它是排障时第一个要看的东西"
        ),
    )
    enabled = models.BooleanField("启用", default=True, db_index=True)
    order = models.IntegerField("排序", default=0)

    # ---- 运行时状态 ----
    state = models.CharField(
        "当前状态", max_length=12, choices=LinkState.choices, default=LinkState.UNKNOWN, db_index=True
    )
    last_collected_at = models.DateTimeField("最后采集时间", null=True, blank=True)
    last_method_used = models.CharField("实际使用的通道", max_length=8, blank=True)
    last_error = models.CharField("最后错误", max_length=255, blank=True)
    consecutive_fail = models.IntegerField("连续失败次数", default=0)
    consecutive_ok = models.IntegerField("连续正常次数", default=0)

    class Meta:
        verbose_name = verbose_name_plural = "网络设备"
        ordering = ["order", "id"]
        indexes = [models.Index(fields=["enabled", "kind", "state"])]

    def __str__(self) -> str:
        return f"{self.name}({self.mgmt_ip})"

    def clean(self):
        """跨字段校验;同样的规则在 DeviceSerializer.validate() 里有一份镜像。"""
        from django.core.exceptions import ValidationError

        errors = {}
        methods = [m for m in (self.collect_method, self.fallback_method) if m]
        if self.fallback_method and self.fallback_method == self.collect_method:
            errors["fallback_method"] = "降级通道不能和主通道相同"

        if CollectMethod.SNMP in methods:
            if self.snmp_version == SnmpVersion.V2C and not self.snmp_community:
                errors["snmp_community"] = "SNMP v2c 必须填 Community"
            if self.snmp_version == SnmpVersion.V3:
                if not self.snmp_v3_user:
                    errors["snmp_v3_user"] = "SNMP v3 必须填用户名"
                if not self.snmp_v3_level:
                    errors["snmp_v3_level"] = "SNMP v3 必须选安全级别"
                elif self.snmp_v3_level != SnmpSecLevel.NO_AUTH and not self.snmp_v3_auth_key:
                    errors["snmp_v3_auth_key"] = "该安全级别需要认证口令"
                elif self.snmp_v3_level == SnmpSecLevel.AUTH_PRIV and not self.snmp_v3_priv_key:
                    errors["snmp_v3_priv_key"] = "authPriv 需要加密口令"
        if CollectMethod.SSH in methods:
            if not self.ssh_username:
                errors["ssh_username"] = "SSH 采集必须填用户名"
            if not self.ssh_password and not self.ssh_private_key:
                errors["ssh_password"] = "SSH 采集需要密码或私钥"
        if CollectMethod.API in methods:
            if not self.api_token:
                errors["api_token"] = "API 采集必须填 Token"
            if self.vendor != Vendor.FORTINET:
                errors["collect_method"] = "REST API 通道目前只实现了 FortiGate(FortiOS)"

        # 备份和策略同步**不看 collect_method** —— 它们各有自己的通道要求:
        # 一台 SNMP 采指标的交换机想备份配置,仍然要 SSH 凭据(SNMP 拿不到配置)。
        # 不在这里拦住的话,开关能打开、任务每天跑一次、每次都失败,
        # 而人要到「配置备份」页面上才看得见。
        has_ssh = bool(self.ssh_username and (self.ssh_password or self.ssh_private_key))
        has_api = bool(self.api_token and self.vendor == Vendor.FORTINET)
        if self.backup_enabled:
            if not (has_ssh or has_api):
                errors["backup_enabled"] = (
                    "配置备份需要 SSH 用户名 + 密码/私钥(FortiGate 也可只填 API Token)"
                    " —— SNMP 拿不到配置文本"
                )
            else:
                # 型号画像里没有备份命令 = 这款型号不支持备份。**在这里拦住**,
                # 否则开关能打开、任务每天跑一次、每次都失败,而人要到
                # 「配置备份」页面上才看得见
                from netcheck.devices.profiles import get_profile

                profile = get_profile(self.model, self.vendor)
                if not profile.backup_cli and not has_api:
                    errors["backup_enabled"] = (
                        f"型号「{self.get_model_display()}」的采集画像里没有定义备份命令,"
                        "开了也备不了。选一个在册型号,或在 devices/profiles.py 里"
                        "给这款型号补一条 backup_cli"
                    )
        if self.policy_sync_enabled:
            if self.kind != DeviceKind.FIREWALL:
                errors["policy_sync_enabled"] = "策略同步只对防火墙有意义"
            elif self.vendor != Vendor.FORTINET:
                errors["policy_sync_enabled"] = (
                    "策略同步目前只实现了 FortiGate(FortiOS)。"
                    "加别的厂商在 devices/policies.py 里补一个解析器"
                )
            elif not (has_api or has_ssh):
                errors["policy_sync_enabled"] = "策略同步需要 API Token(推荐,带命中计数)或 SSH 凭据"

        if errors:
            raise ValidationError(errors)


class DeviceSample(models.Model):
    """
    整机指标一次采样。字段是「交换机和防火墙的并集」,采不到的留空 ——
    比如 C9200L 没有独立温度传感器 OID,它的 temp_c 一直是 null,
    这不是故障,是画像里声明过的缺项(前端显示 "—" 而不是 0)。
    """

    device = models.ForeignKey(
        Device, on_delete=models.CASCADE, related_name="samples", verbose_name="设备"
    )
    ts = models.DateTimeField("采样时间", db_index=True)
    reachable = models.BooleanField("可达", default=True)
    method = models.CharField("采集通道", max_length=8, blank=True)
    latency_ms = models.FloatField("采集耗时(ms)", null=True, blank=True)

    cpu_pct = models.FloatField("CPU 使用率(%)", null=True, blank=True)
    mem_pct = models.FloatField("内存使用率(%)", null=True, blank=True)
    temp_c = models.FloatField("温度(℃)", null=True, blank=True)
    uptime_s = models.BigIntegerField("运行时长(秒)", null=True, blank=True)
    # 防火墙专属
    session_count = models.BigIntegerField("并发会话数", null=True, blank=True)
    session_rate = models.FloatField("新建会话速率(/s)", null=True, blank=True)
    ha_state = models.CharField("HA 状态", max_length=32, blank=True)
    vpn_tunnels_up = models.IntegerField("VPN 隧道数(up)", null=True, blank=True)
    # 交换机专属
    if_total = models.IntegerField("接口总数", null=True, blank=True)
    if_up = models.IntegerField("接口 up 数", null=True, blank=True)
    psu_ok = models.BooleanField("电源正常", null=True, blank=True)
    fan_ok = models.BooleanField("风扇正常", null=True, blank=True)
    # 画像里声明但这次没采到的字段名,用于前端区分"没这个能力"和"采集失败"
    extra = models.JSONField("其它指标", default=dict, blank=True)
    error = models.CharField("错误信息", max_length=255, blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "设备样本"
        ordering = ["-ts"]
        indexes = [models.Index(fields=["device", "-ts"], name="idx_devsample_ts")]


class DeviceInterface(BaseModel):
    """
    设备的一个接口。这是**当前状态表**(每台设备每个口一行,原地更新),
    历史流量在 InterfaceSample 里 —— 两者别混:接口清单要能直接列表展示,
    不该每次去时序表里找最新一行。
    """

    device = models.ForeignKey(
        Device, on_delete=models.CASCADE, related_name="interfaces", verbose_name="设备"
    )
    if_index = models.IntegerField("ifIndex")
    if_name = models.CharField("接口名", max_length=128)
    if_alias = models.CharField("接口描述", max_length=255, blank=True)
    if_type = models.CharField("接口类型", max_length=32, blank=True)
    mac = models.CharField("MAC", max_length=32, blank=True)
    speed_bps = models.BigIntegerField("协商速率(bps)", null=True, blank=True)
    admin_up = models.BooleanField("管理状态 up", null=True, blank=True)
    oper_up = models.BooleanField("运行状态 up", null=True, blank=True)
    last_change = models.DateTimeField("最后状态变化", null=True, blank=True)
    monitored = models.BooleanField(
        "纳入监控", default=True, help_text="关掉则不判 if_down / 带宽饱和事件,但仍采流量"
    )

    # 最新一次的速率,列表页直接用
    in_bps = models.FloatField("入向速率(bps)", null=True, blank=True)
    out_bps = models.FloatField("出向速率(bps)", null=True, blank=True)
    in_err_delta = models.BigIntegerField("入向错包增量", null=True, blank=True)
    out_err_delta = models.BigIntegerField("出向错包增量", null=True, blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "设备接口"
        ordering = ["device_id", "if_index"]
        constraints = [
            models.UniqueConstraint(fields=["device", "if_index"], name="uniq_device_ifindex")
        ]

    def __str__(self) -> str:
        return f"{self.device_id}:{self.if_name}"

    @property
    def util_in_pct(self):
        if not self.speed_bps or self.in_bps is None:
            return None
        return round(self.in_bps / self.speed_bps * 100, 2)

    @property
    def util_out_pct(self):
        if not self.speed_bps or self.out_bps is None:
            return None
        return round(self.out_bps / self.speed_bps * 100, 2)


class InterfaceSample(models.Model):
    """
    接口流量样本。

    SNMP 拿到的是**单调递增的字节计数器**,不是速率 —— 速率是本次和上次
    计数器的差除以时间差。所以这里同时存了原始计数器:设备重启或计数器
    32 位回绕时,靠比对原始值才能识别出"这次的差是假的",直接丢掉而不是
    在图上画出一根冲天的尖峰。
    """

    interface = models.ForeignKey(
        DeviceInterface, on_delete=models.CASCADE, related_name="samples", verbose_name="接口"
    )
    ts = models.DateTimeField("采样时间", db_index=True)
    in_octets = models.BigIntegerField("入向字节计数", null=True, blank=True)
    out_octets = models.BigIntegerField("出向字节计数", null=True, blank=True)
    in_bps = models.FloatField("入向速率(bps)", null=True, blank=True)
    out_bps = models.FloatField("出向速率(bps)", null=True, blank=True)
    in_errors = models.BigIntegerField("入向错包计数", null=True, blank=True)
    out_errors = models.BigIntegerField("出向错包计数", null=True, blank=True)
    in_discards = models.BigIntegerField("入向丢弃计数", null=True, blank=True)
    out_discards = models.BigIntegerField("出向丢弃计数", null=True, blank=True)
    oper_up = models.BooleanField("运行 up", null=True, blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "接口样本"
        ordering = ["-ts"]
        indexes = [models.Index(fields=["interface", "-ts"], name="idx_ifsample_ts")]


class DeviceNeighbor(BaseModel):
    """
    一条邻居关系 —— **「这个口对面接的是谁」**。

    这是 `show lldp neighbors` / `show cdp neighbors` 的落库版本,
    也是网络工程师排障时问的第一个问题:一个口 down 了,对面是谁?
    一台设备失联了,它挂在哪台交换机的哪个口上?

    ## 为什么是**当前状态表**而不是时序表

    邻居关系变化很慢(一年可能不变),但**变化本身是重要信息** ——
    "这个口对面换人了"通常意味着有人插错线或者改了拓扑。所以:
    行是原地更新的(每台每口每协议一行),而 `first_seen` / `changed_at`
    留着变化的痕迹,变化时另外记一条瞬时事件。

    存成时序表的话,一台 48 口交换机每分钟 48 行,一年两千五百万行,
    而其中有信息量的可能只有几十行。

    ## LLDP 和 CDP 两套都存

    LLDP 是标准,CDP 是 Cisco 私有 —— 纯 Cisco 环境里往往只开了 CDP。
    只采一套的结果是"有些口对面是空的",而那是最容易被当成"没接线"的误读。
    同一个口两套都有时,页面上按 LLDP 优先显示,但两行都留着
    (它们的 remote_port 格式不一样,对不上时能互相印证)。
    """

    device = models.ForeignKey(
        Device, on_delete=models.CASCADE, related_name="neighbors", verbose_name="设备"
    )
    protocol = models.CharField(
        "发现协议", max_length=8, help_text="lldp / cdp", db_index=True
    )
    local_if_index = models.IntegerField("本地 ifIndex", null=True, blank=True)
    local_if_name = models.CharField("本地接口", max_length=128)

    remote_device = models.CharField("对端设备名", max_length=255, blank=True)
    remote_port = models.CharField("对端接口", max_length=255, blank=True)
    remote_platform = models.CharField(
        "对端型号/平台", max_length=255, blank=True,
        help_text="CDP 的 cdpCachePlatform 或 LLDP 的 sysDesc 头部",
    )
    remote_mgmt_ip = models.CharField("对端管理地址", max_length=64, blank=True)
    remote_chassis_id = models.CharField(
        "对端 chassis id", max_length=128, blank=True,
        help_text="LLDP 的机箱标识,通常是对端的一个 MAC。**换设备时它会变**,是判断"
                  "「对面是不是同一台机器」最可靠的字段",
    )
    # 对端如果也是这个平台在管的设备,关联过去 —— 这样能画出"受管链路"
    matched_device = models.ForeignKey(
        Device, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="neighbor_of", verbose_name="对端(已纳管)",
    )

    first_seen = models.DateTimeField("首次发现")
    last_seen = models.DateTimeField("最后确认", db_index=True)
    changed_at = models.DateTimeField(
        "最后变化时间", null=True, blank=True,
        help_text="对端设备名/接口/chassis id 变过的时间 —— 通常意味着有人动了线",
    )
    raw = models.JSONField("原始记录", default=dict, blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "设备邻居"
        ordering = ["device_id", "local_if_index", "protocol"]
        constraints = [
            # 一个口在一个协议下**可以有多个邻居**(接了个哑交换机、
            # 或者一个口上挂了 IP 电话 + PC 这种级联),所以对端也进唯一键。
            # nulls_distinct=False:local_if_index 可能取不到
            models.UniqueConstraint(
                fields=["device", "protocol", "local_if_name", "remote_device", "remote_port"],
                name="uniq_neighbor_per_port",
                nulls_distinct=False,
            )
        ]
        indexes = [
            models.Index(fields=["device", "local_if_index"], name="idx_neighbor_local"),
            models.Index(fields=["remote_device"], name="idx_neighbor_remote"),
        ]

    def __str__(self) -> str:
        return f"{self.device_id}:{self.local_if_name} → {self.remote_device}/{self.remote_port}"

    @property
    def identity(self) -> tuple:
        """判断"对面是不是同一台机器"用的那几个字段。"""
        return (self.remote_device, self.remote_port, self.remote_chassis_id)


# =========================================================================
# 服务器采集(SSH,端口 22)
# =========================================================================


class Server(BaseModel):
    """
    一台被监控的服务器。**只走 SSH**,不装 agent。

    为什么不装 agent:这个平台的定位是"从外面看",加装 agent 意味着要为
    每台机器做安装、升级、防火墙放行三件事,而 SSH 是这些机器本来就开着的
    唯一入口。代价是采集频率不能太高(每次一个 SSH 握手),所以最小 15 秒。

    **两套系统,两套命令,由 `os_type` 分开**(见 ServerOS):

      - Linux:全部读 `/proc` 和 `df`,不解析 `top` 的输出 —— `top` 的格式
        随发行版和 locale 变,而 `/proc` 的格式是内核 ABI,十年没变过。
      - ESXi:走 `esxcli` 和 `vim-cmd`。VMkernel 的 `/proc` 里没有 `stat` /
        `meminfo` / `loadavg` / `net/dev`,一条 Linux 的采集命令在上面
        **不会报错,只会全是空的**。

    Windows 要走 WinRM,那是另一条通道,这里没有实现。

    Linux 的 CPU 使用率是**两次采集之间的平均值**(靠 /proc/stat 的 jiffies
    差值),不是某一瞬间的值:
      - 瞬时值要在设备上 sleep 1 秒再读一次,每次采集多挂一秒
      - 而且瞬时值在趋势图上噪声很大,和 load 对不上
    代价是**刚加进来的第一拍没有 CPU 数据**(没有上一次的计数器可减),
    第二拍开始才有。这是有意的,不要填 0 —— 0 是"CPU 空闲"的意思。

    **ESXi 没有这个代价**:hostd 自己就在算,`overallCpuUsage` 是一个当前值,
    第一拍就有数。两条路径给的是同一个字段,但口径不同(一个是区间平均、
    一个是瞬时),这一点在页面上标出来了。
    """

    name = models.CharField("服务器名称", max_length=128, unique=True)
    host = models.CharField("地址", max_length=255, help_text="IP 或域名")
    os_type = models.CharField(
        "系统类型",
        max_length=12,
        choices=ServerOS.choices,
        default=ServerOS.LINUX,
        db_index=True,
        help_text=(
            "决定走哪一套采集命令。选错了指标会**全是空的而且不报错** —— "
            "ESXi 上没有 /proc/stat 也没有 /proc/meminfo,但 shell 跑得通"
        ),
    )
    ssh_port = models.IntegerField(
        "SSH 端口", default=22, validators=[MinValueValidator(1), MaxValueValidator(65535)]
    )
    ssh_username = models.CharField("SSH 用户名", max_length=64)
    ssh_password = EncryptedTextField("SSH 密码", blank=True, default="")
    ssh_private_key = EncryptedTextField(
        "SSH 私钥", blank=True, default="", help_text="和密码填一个即可;私钥更适合无人值守"
    )
    ssh_key_passphrase = EncryptedTextField(
        "私钥口令", blank=True, default="", help_text="私钥带口令时填"
    )
    site = models.CharField("机房/位置", max_length=64, blank=True)
    role = models.CharField(
        "用途", max_length=64, blank=True, help_text="如 应用 / 数据库 / 网关。只用于展示分组"
    )

    interval_seconds = models.IntegerField(
        "采集频率(秒)",
        default=60,
        validators=[MinValueValidator(15), MaxValueValidator(86400)],
        help_text="每次采集是一次完整的 SSH 握手 + 一批 /proc 读取,最小 15 秒",
    )
    timeout_ms = models.IntegerField(
        "超时(毫秒)", default=8000, validators=[MinValueValidator(1000), MaxValueValidator(60000)]
    )
    net_interface = models.CharField(
        "流量统计网卡",
        max_length=32,
        blank=True,
        help_text=(
            "留空 = 自动选。**不要把所有网卡加起来** —— docker0 / veth / br- "
            "这些虚拟口会把同一份流量数两三遍。"
            "Linux 上自动 = 默认路由那块;ESXi 上填 vmnicN,自动 = 累计收字节最多的那块 Up 上行口"
        ),
    )

    # ---- 阈值 ----
    cpu_warn_pct = models.IntegerField("CPU 警告线(%)", default=80)
    cpu_crit_pct = models.IntegerField("CPU 严重线(%)", default=92)
    mem_warn_pct = models.IntegerField("内存警告线(%)", default=85)
    mem_crit_pct = models.IntegerField("内存严重线(%)", default=95)
    disk_warn_pct = models.IntegerField(
        "磁盘警告线(%)", default=80, help_text="按**占用率最高的那个挂载点**判,不是根分区"
    )
    disk_crit_pct = models.IntegerField("磁盘严重线(%)", default=90)
    # 负载按**每核**判。绝对值没有可比性:一台 64 核的机器 load 8 很闲,
    # 一台 2 核的 load 8 已经跑不动了 —— 用同一个绝对阈值必然错一边。
    load_warn = models.FloatField(
        "负载警告线(每核)", default=1.5,
        help_text="判的是 load1 ÷ 核数。1.0 = 刚好跑满。**ESXi 没有 loadavg,这两项不生效**",
    )
    load_crit = models.FloatField("负载严重线(每核)", default=3.0)

    fail_threshold = models.IntegerField("连续失败次数开事件", default=2, validators=[MinValueValidator(1)])
    recover_threshold = models.IntegerField("连续正常次数关事件", default=2, validators=[MinValueValidator(1)])

    collect_processes = models.BooleanField(
        "采集进程 / 虚拟机清单",
        default=True,
        help_text=(
            "Linux:多一条 ps,换来「是谁在吃 CPU」。"
            "ESXi:多一条 `esxcli vm process list`,换来「这台宿主上正在跑哪些虚拟机」"
        ),
    )
    enabled = models.BooleanField("启用", default=True, db_index=True)
    order = models.IntegerField("排序", default=0)

    # ---- 运行时状态(采集器回写) ----
    state = models.CharField(
        "当前状态", max_length=12, choices=LinkState.choices, default=LinkState.UNKNOWN, db_index=True
    )
    last_collected_at = models.DateTimeField("最后采集时间", null=True, blank=True)
    last_error = models.CharField("最后错误", max_length=255, blank=True)
    consecutive_fail = models.IntegerField("连续失败次数", default=0)
    consecutive_ok = models.IntegerField("连续正常次数", default=0)
    # 首次采集回填,不用手填
    hostname = models.CharField("主机名", max_length=128, blank=True)
    os_name = models.CharField("操作系统", max_length=128, blank=True)
    kernel = models.CharField("内核版本", max_length=64, blank=True)
    cpu_cores = models.IntegerField("CPU 核数", null=True, blank=True)
    mem_total_bytes = models.BigIntegerField("内存总量(字节)", null=True, blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "服务器"
        ordering = ["order", "id"]
        indexes = [models.Index(fields=["enabled", "state"])]
        constraints = [
            # 同一个地址 + 端口只允许一台 —— 重复添加会让同一台机器被采两遍,
            # 图上是两条一模一样的线,而且事件也会开两条
            models.UniqueConstraint(fields=["host", "ssh_port"], name="uniq_server_endpoint"),
        ]

    def __str__(self) -> str:
        return f"{self.name}({self.host})"

    def clean(self):
        """
        跨字段校验。**镜像在 ServerSerializer.validate() 里,两边一起改**
        —— DRF 不调用 full_clean()。
        """

        from django.core.exceptions import ValidationError

        errors = {}
        if not self.ssh_password and not self.ssh_private_key:
            errors["ssh_password"] = "SSH 采集需要密码或私钥"
        for warn_field, crit_field, label in (
            ("cpu_warn_pct", "cpu_crit_pct", "CPU"),
            ("mem_warn_pct", "mem_crit_pct", "内存"),
            ("disk_warn_pct", "disk_crit_pct", "磁盘"),
            ("load_warn", "load_crit", "负载"),
        ):
            warn, crit = getattr(self, warn_field), getattr(self, crit_field)
            if crit and warn and warn > crit:
                errors[warn_field] = f"{label}警告线不能高于严重线"
        if errors:
            raise ValidationError(errors)


class ServerSample(models.Model):
    """
    一台服务器一次采集的结果。

    和 DeviceSample 一样是**原始点直接存,不做降采样** —— 服务器采集频率
    最快 15 秒,一天最多 5760 行,和秒级拨测不是一个量级。代价是能看的
    历史跨度受原始样本保留期(默认 48 小时)约束,要看更久得先调大它。

    `net_in_bps` / `net_out_bps` 只统计**一块网卡**(Server.net_interface,
    留空则默认路由那块)。把所有网卡加起来会把同一份流量数好几遍:
    容器机上 eth0 的包会同时出现在 docker0 和一堆 veth 上。
    """

    server = models.ForeignKey(
        Server, on_delete=models.CASCADE, related_name="samples", verbose_name="服务器"
    )
    ts = models.DateTimeField("采样时间", db_index=True)
    reachable = models.BooleanField("可达", default=True)
    latency_ms = models.FloatField("采集耗时(ms)", null=True, blank=True)

    cpu_pct = models.FloatField("CPU 使用率(%)", null=True, blank=True)
    cpu_iowait_pct = models.FloatField(
        "iowait(%)", null=True, blank=True,
        help_text="CPU 不高但系统很卡时看它 —— 那是在等磁盘,不是在算",
    )
    mem_pct = models.FloatField("内存使用率(%)", null=True, blank=True)
    swap_pct = models.FloatField("Swap 使用率(%)", null=True, blank=True)
    disk_pct = models.FloatField(
        "磁盘使用率(%)", null=True, blank=True, help_text="占用率最高的那个挂载点"
    )
    load1 = models.FloatField("1 分钟负载", null=True, blank=True)
    load5 = models.FloatField("5 分钟负载", null=True, blank=True)
    load15 = models.FloatField("15 分钟负载", null=True, blank=True)
    uptime_s = models.BigIntegerField("运行时长(秒)", null=True, blank=True)
    process_count = models.IntegerField("进程数", null=True, blank=True)
    tcp_established = models.IntegerField("ESTABLISHED 连接数", null=True, blank=True)

    net_in_bps = models.FloatField("入向速率(bps)", null=True, blank=True)
    net_out_bps = models.FloatField("出向速率(bps)", null=True, blank=True)

    # 挂载点明细、进程 Top、网卡明细都在这里 —— 它们是"一次一个形状"的东西,
    # 拆成列意味着挂载点多一个就要改表
    extra = models.JSONField("其它指标", default=dict, blank=True)
    error = models.CharField("错误信息", max_length=255, blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "服务器样本"
        ordering = ["-ts"]
        indexes = [models.Index(fields=["server", "-ts"], name="idx_srvsample_ts")]

    def __str__(self) -> str:
        return f"{self.server_id}@{self.ts:%H:%M:%S}"


class ServerInterface(BaseModel):
    """
    服务器的一块网卡,**当前状态表**(每台每块一行,原地更新)。

    历史流量不在这里 —— 那在 ServerSample 的 net_in_bps / net_out_bps 里,
    只统计主网卡。这里存的是"这台机器上有哪些网卡、现在各跑多少",
    给服务器详情页的网卡列表用。为每块网卡都存一张时序表的话,
    一台容器宿主机能有几十个 veth,那张表会比拨测样本还大。

    上一次的字节计数器存在 meta 里(和 DeviceInterface 同一套做法),
    速率由差值算,计数器回绕/重启时丢弃这一拍(不取绝对值,见 _rate)。
    """

    server = models.ForeignKey(
        Server, on_delete=models.CASCADE, related_name="interfaces", verbose_name="服务器"
    )
    if_name = models.CharField("网卡名", max_length=32)
    is_primary = models.BooleanField(
        "主网卡", default=False, help_text="默认路由走的那块,ServerSample 的流量统计用它"
    )
    is_virtual = models.BooleanField(
        "虚拟口", default=False,
        help_text="docker0 / veth* / br-* / lo 之类。**不计入总流量**,否则同一份流量被数几遍",
    )
    in_bps = models.FloatField("入向速率(bps)", null=True, blank=True)
    out_bps = models.FloatField("出向速率(bps)", null=True, blank=True)
    in_err_delta = models.BigIntegerField("入向错包增量", null=True, blank=True)
    out_err_delta = models.BigIntegerField("出向错包增量", null=True, blank=True)
    in_octets = models.BigIntegerField("入向字节计数", null=True, blank=True)
    out_octets = models.BigIntegerField("出向字节计数", null=True, blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "服务器网卡"
        ordering = ["server_id", "-is_primary", "if_name"]
        constraints = [
            models.UniqueConstraint(fields=["server", "if_name"], name="uniq_server_ifname")
        ]

    def __str__(self) -> str:
        return f"{self.server_id}:{self.if_name}"


# =========================================================================
# 设备配置备份
# =========================================================================


class DeviceBackup(models.Model):
    """
    一个**配置版本**,不是一次备份动作。

    这个区别是整张表的设计要点:交换机的配置一年可能只改三次,而备份一天
    跑一次 —— 按"每次备份一行"存,一年三百多行里只有三行是有信息的,
    而且想回答"这台设备的配置什么时候被改过"要自己去比对相邻行。

    所以:**配置文本和上一版一样时不新增行**,只把最新那行的
    `last_seen_at` 往后推、`seen_count` 加一。于是这张表天然就是一份
    变更历史,行数 = 真实变更次数。

    比对用的是**清洗过**的文本(sanitize):Cisco 的
    `! Last configuration change ...` 和 FortiOS 的 `#conf_file_ver=` 每次
    导出都不一样,不去掉的话每次备份都"变更过",这张表就退化成一天一行,
    而且变更历史全是噪声。**存的是原始文本**(下载要能直接回灌),
    只有哈希和 diff 走清洗后的版本。
    """

    device = models.ForeignKey(
        Device, on_delete=models.CASCADE, related_name="backups", verbose_name="设备"
    )
    ts = models.DateTimeField("首次出现时间", db_index=True, help_text="这个版本第一次被备份到的时间")
    last_seen_at = models.DateTimeField("最后确认时间", help_text="最近一次备份确认配置仍是这个版本的时间")
    seen_count = models.IntegerField("确认次数", default=1)

    method = models.CharField("备份通道", max_length=8, help_text="ssh / api")
    content = models.TextField("配置文本", blank=True)
    size_bytes = models.IntegerField("字节数", default=0)
    line_count = models.IntegerField("行数", default=0)
    # 清洗后文本的 sha256。**唯一键的一半** —— 判"配置变了没有"就看它
    content_hash = models.CharField("内容哈希", max_length=64, db_index=True)

    # 和上一个版本相比增删了多少行。页面上"这次改了什么"先看这两个数字,
    # 要看细节再点 diff —— 存下来是因为算 diff 要把两份全文都读出来,
    # 列表页不该为了显示"+3 -1"去读两份几 MB 的文本
    lines_added = models.IntegerField("新增行数", null=True, blank=True)
    lines_removed = models.IntegerField("删除行数", null=True, blank=True)
    is_first = models.BooleanField("首个版本", default=False)

    class Meta:
        verbose_name = verbose_name_plural = "配置备份"
        # **按 (ts, id) 排,不只按 ts。**同一秒里出现两个版本时,只按 ts
        # 排序的结果是不确定的 —— 而"上一个版本是哪个"直接决定 diff 给出
        # 的是什么,拿到一个随机的顺序会让 diff 时正时反
        ordering = ["-ts", "-id"]
        indexes = [models.Index(fields=["device", "-ts"], name="idx_backup_device_ts")]

    def __str__(self) -> str:
        return f"{self.device_id}@{self.ts:%Y-%m-%d %H:%M} ({self.content_hash[:8]})"

    @property
    def short_hash(self) -> str:
        return self.content_hash[:12]


# =========================================================================
# 防火墙策略(只读快照)
# =========================================================================


class FirewallPolicy(models.Model):
    """
    防火墙上的一条策略,**快照**。

    为什么存快照而不是每次打开页面去设备上现拉:

      1. 现拉一次要 2~5 秒(FortiGate 上策略表几百条 + 命中计数是第二个端点),
         而这个页面是要被翻、被筛、被排序的
      2. 设备连不上的时候页面要**还能看**,只是标明"数据截止于什么时候" ——
         防火墙不通恰恰是最需要查规则的时候

    同步是**全量替换**(在一个事务里删掉旧的写入新的):设备上被删掉的策略
    必须在这边也消失。留着一条现实中已经不存在的规则比没有这个页面更危险
    —— 有人会照着它去判断"这个访问是被允许的"。

    `hit_count` / `bytes` 只有 API 通道拿得到(FortiOS 的 monitor 端点);
    SSH 通道只能拿到配置,命中计数是 null。**null 不要显示成 0** ——
    "这条规则从没命中过"和"我们不知道它有没有命中"是两个结论,
    前者可以拿去删规则,后者不行。
    """

    device = models.ForeignKey(
        Device, on_delete=models.CASCADE, related_name="policies", verbose_name="设备"
    )
    vdom = models.CharField("VDOM", max_length=64, blank=True, default="root")
    policy_id = models.IntegerField("策略 ID", help_text="设备上的 policyid,不是这张表的主键")
    seq = models.IntegerField(
        "顺序", default=0,
        help_text="策略表里的先后。**防火墙是先匹配先生效的**,顺序本身是语义",
    )
    name = models.CharField("名称", max_length=128, blank=True)

    # 地址/接口/服务都是"一条策略可以有多个"的,存成 JSON 数组。
    # 拆成关联表的话,页面上要展示一条策略得做四次 join,而这些值来自设备、
    # 不参与本地的引用完整性
    src_intf = models.JSONField("源接口", default=list, blank=True)
    dst_intf = models.JSONField("目的接口", default=list, blank=True)
    src_addr = models.JSONField("源地址", default=list, blank=True)
    dst_addr = models.JSONField("目的地址", default=list, blank=True)
    service = models.JSONField("服务", default=list, blank=True)
    schedule = models.CharField("生效时间", max_length=64, blank=True)

    action = models.CharField(
        "动作", max_length=10, choices=PolicyAction.choices, default=PolicyAction.OTHER
    )
    enabled = models.BooleanField("已启用", default=True)
    nat = models.BooleanField("NAT", default=False)
    log_traffic = models.CharField("日志", max_length=16, blank=True)
    comments = models.CharField("备注", max_length=255, blank=True)
    uuid = models.CharField("UUID", max_length=64, blank=True)

    # ---- 命中统计(只有 API 通道有;SSH 通道是 null,不是 0) ----
    hit_count = models.BigIntegerField("命中次数", null=True, blank=True)
    bytes_count = models.BigIntegerField("字节数", null=True, blank=True)
    packets = models.BigIntegerField("包数", null=True, blank=True)
    sessions = models.IntegerField("活动会话", null=True, blank=True)
    first_hit_at = models.DateTimeField("首次命中", null=True, blank=True)
    last_hit_at = models.DateTimeField("最后命中", null=True, blank=True)

    # 设备原样返回的那条记录。页面上"查看原始"用它 —— FortiOS 的策略有
    # 上百个字段,这里只提取了常看的十几个,剩下的不该丢
    raw = models.JSONField("原始记录", default=dict, blank=True)
    synced_at = models.DateTimeField("同步时间", db_index=True)
    method = models.CharField("同步通道", max_length=8, blank=True, help_text="api / ssh")

    class Meta:
        verbose_name = verbose_name_plural = "防火墙策略"
        ordering = ["device_id", "vdom", "seq", "policy_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["device", "vdom", "policy_id"], name="uniq_policy_per_device_vdom"
            )
        ]
        indexes = [
            models.Index(fields=["device", "seq"], name="idx_policy_device_seq"),
            models.Index(fields=["device", "action"], name="idx_policy_device_action"),
        ]

    def __str__(self) -> str:
        return f"{self.device_id}#{self.policy_id} {self.name or ''}".strip()

    @property
    def never_hit(self) -> bool | None:
        """
        从来没命中过 —— 可以考虑删的规则。

        **返回 None 表示"不知道"**(SSH 通道没有命中计数)。
        把不知道当成"没命中"会让人删掉一条其实在用的规则。
        """
        if self.hit_count is None:
            return None
        return self.hit_count == 0

    # ---- 规则审计 ----
    #
    # 下面这几项是**防火墙评审时真正要回答的问题**,不是展示字段。
    # 它们只依赖这一行自己(不需要看别的规则),所以做成属性由序列化器带出去;
    # 需要看"前后顺序"的那一类(影子规则)算不出来,在 audit 接口里做。
    #
    # 判定一律**只对 enabled 且 action=accept 的规则**:一条停用的规则或者
    # 一条拒绝规则写成 any-any-any 不是风险(前者不生效,后者是兜底拒绝,
    # 那正是该有的写法)。把它们也标红会让真正的问题淹在噪声里。

    # FortiOS 里"任意"有两种写法:地址是 all,服务是 ALL,接口是 any。
    # 大小写不统一(实测两种都见过),所以一律折成小写比
    _ANY = {"all", "any"}

    def _is_any(self, values) -> bool:
        if not values:
            # 空数组也是"任意" —— 策略里没写这一维就等于不限制。
            # 把空当成"已限制"是这里最危险的误判
            return True
        return any(str(v).strip().lower() in self._ANY for v in values)

    @property
    def permissive_level(self) -> str:
        """
        过宽规则。返回 "critical" / "warning" / ""。

        `critical` = 源、目的、服务**三者全是任意**的放行规则,也就是
        any-any-any allow。这是防火墙评审里第一条要挑出来的东西:
        它等于在这对接口之间没有防火墙,而且它会让**它后面所有规则永远
        匹配不到**(见 audit 接口的影子规则)。

        `warning` = 服务是任意,且源或目的之一是任意。这类规则通常是
        "先放开再说"留下来的,应该收窄。
        """
        if not self.enabled or self.action != PolicyAction.ACCEPT:
            return ""
        src_any = self._is_any(self.src_addr)
        dst_any = self._is_any(self.dst_addr)
        svc_any = self._is_any(self.service)
        if src_any and dst_any and svc_any:
            return "critical"
        if svc_any and (src_any or dst_any):
            return "warning"
        return ""

    @property
    def logging_off(self) -> bool:
        """
        放行但不记日志。

        出了事之后"这个访问是从哪儿来的"就查不出来了 —— 而放行规则恰恰
        是最需要留痕的那一类。FortiOS 里 `set logtraffic disable`,
        或者这一项根本没配(那也是不记)。
        """
        if not self.enabled or self.action != PolicyAction.ACCEPT:
            return False
        return str(self.log_traffic or "").strip().lower() in ("", "disable", "disabled")

    @property
    def intf_pair(self) -> tuple:
        """(源接口集合, 目的接口集合) —— 影子规则判定要按接口对分组。"""
        return (
            frozenset(str(v).strip().lower() for v in (self.src_intf or ["any"])),
            frozenset(str(v).strip().lower() for v in (self.dst_intf or ["any"])),
        )


# =========================================================================
# 事件 —— 需求里的「事件报告」表
# =========================================================================


class Event(models.Model):
    """
    一次异常的完整生命周期:什么时候发生、发生了什么、什么时候恢复的。

    设计成「一行一次异常」而不是「一行一条告警日志」是关键取舍:
    页面上的事件表要能回答「昨天这条线断了几次、每次多久」,
    所以 started_at / resolved_at / duration_s 在同一行里,
    未恢复的事件 resolved_at 为 null —— **判断"当前是否还在故障"就是
    filter(resolved_at__isnull=True)**,不要去比对最新一条日志的类型。

    同一个 (source, kind) 同时最多只有一条未恢复事件(见下面的唯一约束),
    这保证了抖动的线路不会刷出几百条重复事件。**那条约束必须带
    nulls_distinct=False** —— 四个来源外键里只有一个非空,默认的
    "NULL != NULL" 语义会让它一行都挡不住。
    """

    source_type = models.CharField(
        "来源类型", max_length=12, choices=SourceType.choices, db_index=True
    )
    # 三个来源各自的外键,只有一个非空。用三个 FK 而不是 GenericForeignKey,
    # 是为了列表接口能 select_related 一次带出名字 —— GFK 做不到,
    # 事件表是要按页翻的,N+1 查询在这里代价很直接。
    target = models.ForeignKey(
        ProbeTarget, null=True, blank=True, on_delete=models.CASCADE,
        related_name="events", verbose_name="线路",
    )
    device = models.ForeignKey(
        Device, null=True, blank=True, on_delete=models.CASCADE,
        related_name="events", verbose_name="设备",
    )
    interface = models.ForeignKey(
        DeviceInterface, null=True, blank=True, on_delete=models.CASCADE,
        related_name="events", verbose_name="接口",
    )
    server = models.ForeignKey(
        Server, null=True, blank=True, on_delete=models.CASCADE,
        related_name="events", verbose_name="服务器",
    )

    kind = models.CharField("事件类型", max_length=16, choices=EventKind.choices, db_index=True)
    severity = models.CharField("级别", max_length=10, choices=Severity.choices, db_index=True)
    title = models.CharField("标题", max_length=200)
    message = models.TextField("详情", blank=True)

    started_at = models.DateTimeField("发生时间", db_index=True)
    resolved_at = models.DateTimeField("恢复时间", null=True, blank=True, db_index=True)
    duration_s = models.IntegerField(
        "持续时长(秒)", null=True, blank=True, help_text="恢复时回填;未恢复为空,页面按 now-started_at 实时算"
    )

    # 触发时的实测值与当时的阈值,一起存下来 —— 事后阈值被人调过,
    # 光看当前配置就解释不了"当年为什么报的这条"
    trigger_value = models.FloatField("触发值", null=True, blank=True)
    threshold = models.FloatField("当时阈值", null=True, blank=True)
    unit = models.CharField("单位", max_length=16, blank=True)
    # 故障期间累计探测/失败次数,用来算这次事件的严重程度
    fail_count = models.IntegerField("期间失败次数", default=0)
    recovery_value = models.FloatField("恢复时的值", null=True, blank=True)

    notified_alert = models.BooleanField("告警已推送", default=False)
    notified_recover = models.BooleanField("恢复已推送", default=False)
    acknowledged_at = models.DateTimeField("认领时间", null=True, blank=True)
    acknowledged_by = models.CharField("认领人", max_length=64, blank=True)
    note = models.TextField("处理备注", blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "事件"
        ordering = ["-started_at"]
        indexes = [
            models.Index(fields=["-started_at", "severity"], name="idx_event_time_sev"),
            models.Index(fields=["resolved_at"], name="idx_event_open"),
            models.Index(fields=["source_type", "kind", "-started_at"], name="idx_event_src_kind"),
        ]
        constraints = [
            # 每个来源每种类型同时只允许一条未恢复事件。
            # Postgres 的部分唯一索引 —— resolved_at 非空的行不受约束,
            # 所以历史事件可以有任意多条。
            # **nulls_distinct=False 是这条约束能生效的前提。**
            # 四个来源外键里永远只有一个非空,而 PostgreSQL 默认认为
            # NULL != NULL —— 也就是说带默认语义的话,任何一行只要有一个
            # NULL 列就永远不会和别的行冲突,这条约束一行都挡不住
            # (见 CLAUDE.md 第 2 条,ProbeTarget 的端点约束踩的是同一个坑,
            #  那边用 Coalesce 折成 0,这边列是外键没法 Coalesce,
            #  用 PG 15+ 的 NULLS NOT DISTINCT)。
            models.UniqueConstraint(
                fields=["source_type", "target", "device", "interface", "server", "kind"],
                condition=models.Q(resolved_at__isnull=True),
                nulls_distinct=False,
                name="uniq_open_event_per_source_kind",
            )
        ]

    def __str__(self) -> str:
        return f"[{self.get_severity_display()}] {self.title}"

    @property
    def is_open(self) -> bool:
        return self.resolved_at is None

    @property
    def source_name(self) -> str:
        if self.interface_id and self.interface:
            return f"{self.interface.device.name} / {self.interface.if_name}"
        if self.device_id and self.device:
            return self.device.name
        if self.server_id and self.server:
            return self.server.name
        if self.target_id and self.target:
            return self.target.name
        return "-"


# =========================================================================
# 通知
# =========================================================================


class Notifier(BaseModel):
    """
    一个推送渠道。两种实现:Telegram Bot 和通用 Webhook。

    过滤条件(min_severity / kinds / groups)是**在推送侧**做的,不是在事件
    生成侧 —— 事件该记的照记,只是不一定推。这样调完过滤条件回头看事件表,
    历史是完整的。
    """

    name = models.CharField("渠道名称", max_length=64, unique=True)
    kind = models.CharField("类型", max_length=12, choices=NotifierKind.choices)
    enabled = models.BooleanField("启用", default=True, db_index=True)

    # ---- Telegram ----
    telegram_bot_token = EncryptedTextField(
        "Bot Token", blank=True, default="", help_text="向 @BotFather 申请,形如 123456:ABC-DEF..."
    )
    telegram_chat_id = models.CharField(
        "Chat ID", max_length=64, blank=True, help_text="个人是数字 id,群组是负数,频道可用 @channelname"
    )
    telegram_api_base = models.CharField(
        "API 地址", max_length=255, blank=True, default="https://api.telegram.org",
        help_text="内网无法直连 Telegram 时填反代地址",
    )
    telegram_thread_id = models.CharField(
        "话题 ID", max_length=32, blank=True, help_text="群组开了话题(Topics)时指定,否则留空"
    )

    # ---- Webhook ----
    webhook_url = models.CharField("Webhook 地址", max_length=500, blank=True)
    webhook_method = models.CharField("HTTP 方法", max_length=8, blank=True, default="POST")
    webhook_headers = models.JSONField(
        "自定义请求头", default=dict, blank=True, help_text='如 {"Authorization": "Bearer xxx"}'
    )
    webhook_template = models.TextField(
        "消息模板",
        blank=True,
        help_text=(
            "留空则发平台标准 JSON。填了则按模板渲染,可用占位符:"
            "{event_id} {status} {severity} {kind} {kind_label} {title} {source} "
            "{message} {value} {threshold} {unit} {started_at} {resolved_at} {duration}"
        ),
    )
    webhook_verify_tls = models.BooleanField("校验 TLS 证书", default=True)

    # ---- 通用 ----
    timeout_seconds = models.IntegerField("超时(秒)", default=10)
    on_alert = models.BooleanField("推送告警", default=True)
    on_recover = models.BooleanField("推送恢复", default=True)
    min_severity = models.CharField(
        "最低级别", max_length=10, choices=Severity.choices, default=Severity.WARNING,
        help_text="低于这个级别的事件不推。info 表示全推",
    )
    kinds = models.JSONField(
        "只推这些类型", default=list, blank=True, help_text="空数组表示不限类型"
    )
    groups = models.ManyToManyField(
        ProbeGroup, blank=True, related_name="notifiers", verbose_name="只推这些监控类",
        help_text="不选表示全部;只对线路事件生效,设备事件不受此项过滤",
    )
    # 同一事件在这个窗口内不重复推(告警和恢复各自独立计)。
    # 主要防的是事件被反复开关(flapping)造成的消息轰炸。
    cooldown_seconds = models.IntegerField("静默窗口(秒)", default=300)

    last_sent_at = models.DateTimeField("最后发送时间", null=True, blank=True)
    last_error = models.CharField("最后错误", max_length=255, blank=True)
    total_sent = models.IntegerField("累计发送", default=0)
    total_failed = models.IntegerField("累计失败", default=0)

    class Meta:
        verbose_name = verbose_name_plural = "通知渠道"
        ordering = ["id"]

    def __str__(self) -> str:
        return f"{self.name}({self.get_kind_display()})"

    def clean(self):
        """跨字段校验;镜像在 NotifierSerializer.validate()。"""
        from django.core.exceptions import ValidationError

        errors = {}
        if self.kind == NotifierKind.TELEGRAM:
            if not self.telegram_bot_token:
                errors["telegram_bot_token"] = "Telegram 渠道必须填 Bot Token"
            if not self.telegram_chat_id:
                errors["telegram_chat_id"] = "Telegram 渠道必须填 Chat ID"
        elif self.kind == NotifierKind.WEBHOOK:
            if not self.webhook_url:
                errors["webhook_url"] = "Webhook 渠道必须填地址"
            elif not self.webhook_url.startswith(("http://", "https://")):
                errors["webhook_url"] = "地址必须以 http:// 或 https:// 开头"
        if errors:
            raise ValidationError(errors)


class NotifyLog(models.Model):
    """
    每次推送的结果。留着它是为了回答「告警到底发出去没有」——
    这个问题在故障复盘时几乎每次都会被问到。
    """

    class Status(models.TextChoices):
        SUCCESS = "success", "成功"
        FAILED = "failed", "失败"
        SKIPPED = "skipped", "已跳过"

    notifier = models.ForeignKey(
        Notifier, on_delete=models.CASCADE, related_name="logs", verbose_name="渠道"
    )
    event = models.ForeignKey(
        Event, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="notify_logs", verbose_name="事件",
    )
    phase = models.CharField(
        "阶段", max_length=10,
        choices=[("alert", "告警"), ("recover", "恢复"), ("test", "测试")],
    )
    status = models.CharField("结果", max_length=10, choices=Status.choices, db_index=True)
    ts = models.DateTimeField("发送时间", auto_now_add=True, db_index=True)
    http_status = models.IntegerField("HTTP 状态码", null=True, blank=True)
    duration_ms = models.IntegerField("耗时(ms)", null=True, blank=True)
    detail = models.TextField("请求/响应摘要", blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "推送记录"
        ordering = ["-ts"]
        indexes = [models.Index(fields=["notifier", "-ts"], name="idx_notifylog_ts")]


# ============================================================================
# 保留策略
# ============================================================================


class RetentionPolicy(models.Model):
    """
    数据保留策略。**单例**(pk 恒为 1),在管理后台的「系统信息」里改。

    为什么要落库而不是继续用环境变量:这是个**数据采集平台,磁盘是会满的**,
    而"快满了要缩短保留期"这个动作发生在半夜、发生在人只能开个页面的时候。
    改环境变量要改文件、重启容器、还得有 SSH —— 那时候这三样通常都不方便。

    四条粒度是一条链(原始 → 1m → 5m → 1h),**粗粒度的保留必须不短于细粒度的**。
    反过来的话图上会出现"最近没有数据、更早反而有"的怪现象:图表按跨度选粒度
    (≤2h 原始 / ≤2d 1m / ≤14d 5m / 更长 1h),细桶比粗桶留得久时,
    查粗桶的那个跨度就是空的。这条约束在 clean() 和序列化器里各写了一份 ——
    **DRF 不调用 full_clean(),两边都要有。**

    `0` 一律表示"永久保留",只对 1h 桶和事件开放:
    前面几档不允许永久,那等于关掉清理,而这张表每天涨几十万行。
    """

    SINGLETON_PK = 1

    raw_hours = models.PositiveIntegerField(
        "原始秒级样本保留(小时)", default=48,
        help_text="磁盘的主要消费者。一条 1 秒频率的线路一天约 86400 行",
    )
    rollup_1m_days = models.PositiveIntegerField("1 分钟桶保留(天)", default=7)
    rollup_5m_days = models.PositiveIntegerField("5 分钟桶保留(天)", default=30)
    rollup_1h_days = models.PositiveIntegerField(
        "1 小时桶保留(天)", default=0,
        help_text="0 = 永久。一条线路一年才 8760 行,是唯一能回答「去年这条线怎么样」的数据",
    )
    event_days = models.PositiveIntegerField(
        "事件保留(天)", default=0, help_text="0 = 永久。事件是故障复盘的材料,建议别删",
    )
    notify_log_days = models.PositiveIntegerField("推送记录保留(天)", default=30)
    login_audit_days = models.PositiveIntegerField("登录审计保留(天)", default=180)

    updated_at = models.DateTimeField("更新时间", auto_now=True)
    updated_by = models.CharField("最后修改人", max_length=64, blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "数据保留策略"

    def __str__(self) -> str:
        return f"保留策略(原始 {self.raw_hours}h / 1m {self.rollup_1m_days}d)"

    def save(self, *args, **kwargs):
        self.pk = self.SINGLETON_PK      # 永远只有一行
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        # 删掉它等于让清理任务失去依据。要恢复默认值就改字段,不是删行
        raise RuntimeError("保留策略是单例,不能删除")

    @classmethod
    def load(cls) -> RetentionPolicy:
        """
        取当前策略,没有就用环境变量里的值建一行。

        环境变量在这里只是**首次建行时的默认值**,建完之后以库里的为准 ——
        否则页面上改完,下次重启又被环境变量盖回去。
        """

        from django.conf import settings

        obj, created = cls.objects.get_or_create(
            pk=cls.SINGLETON_PK,
            defaults={
                "raw_hours": getattr(settings, "NETCHECK_RAW_RETENTION_HOURS", 48),
                "login_audit_days": getattr(settings, "NETCHECK_LOGIN_AUDIT_DAYS", 180),
            },
        )
        return obj

    def clean(self):
        """
        跨字段校验。**序列化器里有一份镜像,改这里要一起改**
        (见 CLAUDE.md「模型的跨字段校验必须在序列化器里写第二遍」)。
        """

        from django.core.exceptions import ValidationError

        errors = {}
        if self.raw_hours < 1:
            errors["raw_hours"] = "原始样本至少保留 1 小时,填 0 等于关掉采集的意义"
        if self.rollup_1m_days < 1:
            errors["rollup_1m_days"] = "1 分钟桶不允许永久保留,它每天每条线路 1440 行"
        if self.rollup_5m_days < self.rollup_1m_days:
            errors["rollup_5m_days"] = (
                f"5 分钟桶要不短于 1 分钟桶({self.rollup_1m_days} 天)—— "
                "粗桶比细桶先删,图上会出现「最近有数据、更早反而没有」"
            )
        if self.rollup_1h_days and self.rollup_1h_days < self.rollup_5m_days:
            errors["rollup_1h_days"] = (
                f"1 小时桶要不短于 5 分钟桶({self.rollup_5m_days} 天),或填 0 表示永久"
            )
        if self.raw_hours > self.rollup_1m_days * 24:
            errors["raw_hours"] = (
                f"原始样本不能比 1 分钟桶({self.rollup_1m_days} 天)留得久 —— "
                "图表按跨度选粒度,超过 2 小时就查 1m 桶了,那段时间会是空白"
            )
        if errors:
            raise ValidationError(errors)
