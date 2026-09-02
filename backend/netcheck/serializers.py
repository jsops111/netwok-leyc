"""
DRF 序列化器。

一条贯穿全文件的规矩:**模型 clean() 里的跨字段校验必须在 validate() 里
再写一遍**。DRF 从不调用 full_clean(),只写在模型上等于对 API 写入无效。
而且 validate() 版本必须**合并 self.instance 的现值** —— 否则一个只改
一个字段的 PATCH 能绕过那些约束(前端的表单就是这么提交的)。

凭据字段一律 write_only。列表接口不返回密文也不返回明文,只返回一个
"已配置 / 未配置"的布尔 —— 页面上要知道填过没有,但不需要看见内容。
"""

from __future__ import annotations

from rest_framework import serializers

from netcheck.models import (
    CollectMethod,
    Device,
    DeviceBackup,
    DeviceInterface,
    DeviceKind,
    DeviceNeighbor,
    DeviceSample,
    Event,
    FirewallPolicy,
    InterfaceSample,
    Notifier,
    NotifierKind,
    NotifyLog,
    ProbeGroup,
    ProbeRollup,
    ProbeSample,
    ProbeTarget,
    Protocol,
    Server,
    ServerInterface,
    ServerSample,
    SnmpSecLevel,
    SnmpVersion,
    Vendor,
)


def _merged(serializer, attrs: dict, field: str, default=None):
    """
    取"这次提交后"的字段值。

    PATCH 只带部分字段,所以校验必须看合并后的结果:attrs 里有就用 attrs 的,
    没有就用数据库里的现值。少了这一步,`PATCH {"protocol":"tcp"}` 就能造出
    一条没有端口的 TCP 线路。
    """
    if field in attrs:
        return attrs[field]
    if serializer.instance is not None:
        return getattr(serializer.instance, field, default)
    return default


# =========================================================================
# 监控类 / 线路
# =========================================================================


class ProbeGroupSerializer(serializers.ModelSerializer):
    target_count = serializers.SerializerMethodField()

    class Meta:
        model = ProbeGroup
        fields = [
            "id", "name", "description", "color", "order", "enabled",
            "target_count", "created_at", "updated_at",
        ]

    def get_target_count(self, obj) -> int:
        # 列表接口用 annotate 预先算好了(见 views 的 get_queryset),
        # 单条取用则回落到查询
        return getattr(obj, "target_count_ann", None) or obj.targets.count()


class ProbeTargetSerializer(serializers.ModelSerializer):
    group_name = serializers.CharField(source="group.name", read_only=True)
    group_color = serializers.CharField(source="group.color", read_only=True)
    protocol_label = serializers.CharField(source="get_protocol_display", read_only=True)
    state_label = serializers.CharField(source="get_state_display", read_only=True)
    availability = serializers.FloatField(read_only=True)
    open_event_count = serializers.SerializerMethodField()

    class Meta:
        model = ProbeTarget
        fields = "__all__"
        read_only_fields = [
            "state", "last_checked_at", "last_rtt_ms", "last_loss_pct", "last_jitter_ms",
            "last_error", "consecutive_fail", "consecutive_ok", "total_checks", "total_fail",
        ]

    def get_open_event_count(self, obj) -> int:
        return getattr(obj, "open_event_count_ann", None) or obj.events.filter(
            resolved_at__isnull=True
        ).count()

    def validate(self, attrs):
        """ProbeTarget.clean() 的镜像 —— 两边必须一起改。"""

        protocol = _merged(self, attrs, "protocol", Protocol.ICMP)
        port = _merged(self, attrs, "port")
        errors = {}

        if protocol in (Protocol.TCP, Protocol.UDP) and not port:
            errors["port"] = "TCP / UDP 检测必须指定端口"
        if protocol == Protocol.DNS and not _merged(self, attrs, "dns_query"):
            errors["dns_query"] = "DNS 检测必须填写要查询的域名"

        for warn_field, crit_field, label in (
            ("latency_warn_ms", "latency_crit_ms", "延迟"),
            ("loss_warn_pct", "loss_crit_pct", "丢包"),
            ("jitter_warn_ms", "jitter_crit_ms", "抖动"),
        ):
            warn = _merged(self, attrs, warn_field, 0)
            crit = _merged(self, attrs, crit_field, 0)
            if crit and warn and warn > crit:
                errors[warn_field] = f"{label}警告线不能高于严重线"

        # 端点重复。**必须手写** —— DRF 只会为"纯字段列表"的 UniqueConstraint
        # 自动生成校验器,而这条约束里带了 Coalesce 表达式(见 models.py 里
        # 为什么必须带),DRF 认不出来。不写这一段,重复端点会以 IntegrityError
        # 的形式冒成 500,页面上看到的是"服务器错误"而不是"这个端点已经有了"。
        group = _merged(self, attrs, "group")
        host = _merged(self, attrs, "host")
        if group and host and "port" not in errors:
            from netcheck.models import ProbeTarget as _PT

            clash = _PT.objects.filter(
                group=group, host=host, protocol=protocol, port=port
            )
            if self.instance is not None:
                clash = clash.exclude(pk=self.instance.pk)
            if clash.exists():
                errors["host"] = (
                    f"这个监控类里已经有一条 {host} 的 "
                    f"{dict(Protocol.choices).get(protocol, protocol)} 检测了"
                    + (f"(端口 {port})" if port else "")
                    + "。换个监控类,或改这条已有的线路"
                )

        interval = _merged(self, attrs, "interval_seconds", 10)
        timeout = _merged(self, attrs, "timeout_ms", 2000)
        packets = _merged(self, attrs, "packets", 5)
        # 一次探测的最坏耗时不能超过检测间隔,否则这条线路永远在"上一次还没
        # 跑完就该跑下一次"的状态,派发器会一直跳过它 —— 表现是图上的点
        # 稀稀拉拉,而配置看起来是对的。这是最容易踩的一个坑,所以拦在这里。
        if protocol in (Protocol.ICMP, Protocol.UDP):
            worst_ms = packets * timeout
        elif protocol == Protocol.TCP:
            worst_ms = min(packets, 5) * timeout
        else:
            worst_ms = timeout
        if worst_ms > interval * 1000:
            errors["interval_seconds"] = (
                f"最坏情况一次探测要 {worst_ms / 1000:.1f}s(发包数 × 超时),"
                f"超过了检测间隔 {interval}s。调大间隔、调小超时,或减少发包数"
            )

        if errors:
            raise serializers.ValidationError(errors)
        return attrs


class ProbeSampleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProbeSample
        fields = [
            "id", "target", "ts", "ok", "rtt_ms", "rtt_min_ms", "rtt_max_ms",
            "loss_pct", "jitter_ms", "state", "error_kind", "error",
        ]


class ProbeRollupSerializer(serializers.ModelSerializer):
    availability = serializers.FloatField(read_only=True)

    class Meta:
        model = ProbeRollup
        fields = [
            "id", "target", "bucket", "ts", "samples", "ok_count", "fail_count",
            "rtt_avg_ms", "rtt_min_ms", "rtt_max_ms", "rtt_p95_ms",
            "loss_avg_pct", "loss_max_pct", "jitter_avg_ms", "jitter_max_ms", "availability",
        ]


# =========================================================================
# 设备
# =========================================================================


class DeviceSerializer(serializers.ModelSerializer):
    kind_label = serializers.CharField(source="get_kind_display", read_only=True)
    vendor_label = serializers.CharField(source="get_vendor_display", read_only=True)
    model_label = serializers.CharField(source="get_model_display", read_only=True)
    state_label = serializers.CharField(source="get_state_display", read_only=True)
    method_label = serializers.CharField(source="get_collect_method_display", read_only=True)
    # 凭据只回"填过没有",不回内容
    has_snmp_community = serializers.SerializerMethodField()
    has_ssh_credential = serializers.SerializerMethodField()
    has_api_token = serializers.SerializerMethodField()
    interface_count = serializers.SerializerMethodField()
    profile_notes = serializers.SerializerMethodField()
    # 这款型号支不支持备份 / 策略同步 / 未保存检查 —— 前端据此禁掉开关,
    # 而不是让人打开一个必然失败的功能
    profile_supports = serializers.SerializerMethodField()
    # running 和 startup 的差异(前 200 行)。存在 meta 里,不单独建列
    unsaved_diff = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = "__all__"
        read_only_fields = [
            "state", "last_collected_at", "last_method_used", "last_error",
            "consecutive_fail", "consecutive_ok",
        ]
        extra_kwargs = {
            "snmp_community": {"write_only": True, "required": False, "allow_blank": True},
            "snmp_v3_auth_key": {"write_only": True, "required": False, "allow_blank": True},
            "snmp_v3_priv_key": {"write_only": True, "required": False, "allow_blank": True},
            "ssh_password": {"write_only": True, "required": False, "allow_blank": True},
            "ssh_private_key": {"write_only": True, "required": False, "allow_blank": True},
            "ssh_enable_password": {"write_only": True, "required": False, "allow_blank": True},
            "api_token": {"write_only": True, "required": False, "allow_blank": True},
        }

    def get_has_snmp_community(self, obj) -> bool:
        return bool(obj.snmp_community or obj.snmp_v3_auth_key)

    def get_has_ssh_credential(self, obj) -> bool:
        return bool(obj.ssh_password or obj.ssh_private_key)

    def get_has_api_token(self, obj) -> bool:
        return bool(obj.api_token)

    def get_interface_count(self, obj) -> int:
        return getattr(obj, "interface_count_ann", None) or obj.interfaces.count()

    def get_profile_notes(self, obj) -> str:
        """把型号画像的说明带给前端 —— 配置页面上要能看到这款型号的采集特点。"""
        from netcheck.devices.profiles import get_profile

        return get_profile(obj.model, obj.vendor).notes

    def get_profile_supports(self, obj) -> dict:
        from netcheck.devices.profiles import get_profile

        profile = get_profile(obj.model, obj.vendor)
        return {
            "backup": bool(profile.backup_cli),
            "policy": bool(profile.policy_cli),
            # 「未保存检查」要有 startup 命令。FortiOS 改完即存,没这个概念 ——
            # 前端把开关灰掉并说明原因,比让人打开一个永远返回"未检查"的开关好
            "unsaved_check": bool(profile.startup_cli),
        }

    def get_unsaved_diff(self, obj) -> list:
        return (obj.meta or {}).get("unsaved_diff") or []

    def validate(self, attrs):
        """Device.clean() 的镜像。"""

        errors = {}
        method = _merged(self, attrs, "collect_method", CollectMethod.SNMP)
        fallback = _merged(self, attrs, "fallback_method", "")
        vendor = _merged(self, attrs, "vendor", Vendor.CISCO)

        if fallback and fallback == method:
            errors["fallback_method"] = "降级通道不能和主通道相同"

        methods = [m for m in (method, fallback) if m]

        if CollectMethod.SNMP in methods:
            version = _merged(self, attrs, "snmp_version", SnmpVersion.V2C)
            if version == SnmpVersion.V2C and not _merged(self, attrs, "snmp_community"):
                errors["snmp_community"] = "SNMP v2c 必须填 Community"
            elif version == SnmpVersion.V3:
                if not _merged(self, attrs, "snmp_v3_user"):
                    errors["snmp_v3_user"] = "SNMP v3 必须填用户名"
                level = _merged(self, attrs, "snmp_v3_level", "")
                if not level:
                    errors["snmp_v3_level"] = "SNMP v3 必须选安全级别"
                elif level != SnmpSecLevel.NO_AUTH and not _merged(self, attrs, "snmp_v3_auth_key"):
                    errors["snmp_v3_auth_key"] = "该安全级别需要认证口令"
                elif level == SnmpSecLevel.AUTH_PRIV and not _merged(self, attrs, "snmp_v3_priv_key"):
                    errors["snmp_v3_priv_key"] = "authPriv 需要加密口令"

        if CollectMethod.SSH in methods:
            if not _merged(self, attrs, "ssh_username"):
                errors["ssh_username"] = "SSH 采集必须填用户名"
            if not _merged(self, attrs, "ssh_password") and not _merged(self, attrs, "ssh_private_key"):
                errors["ssh_password"] = "SSH 采集需要密码或私钥"

        if CollectMethod.API in methods:
            if not _merged(self, attrs, "api_token"):
                errors["api_token"] = "API 采集必须填 Token"
            if vendor != Vendor.FORTINET:
                errors["collect_method"] = "REST API 通道目前只实现了 FortiGate(FortiOS)"

        for warn_field, crit_field, label in (
            ("cpu_warn_pct", "cpu_crit_pct", "CPU"),
            ("mem_warn_pct", "mem_crit_pct", "内存"),
            ("temp_warn_c", "temp_crit_c", "温度"),
        ):
            warn, crit = _merged(self, attrs, warn_field, 0), _merged(self, attrs, crit_field, 0)
            if crit and warn and warn > crit:
                errors[warn_field] = f"{label}警告线不能高于严重线"

        # ---- 配置备份 / 策略同步(Device.clean() 的镜像) ----
        # 这两项**不看 collect_method**:采指标可以走 SNMP,但 SNMP 拿不到
        # 配置文本,也拿不到策略表。不在这里拦住的话开关能打开、任务每天
        # 跑一次、每次都失败,而人只有翻到「配置备份」页面才看得见
        model = _merged(self, attrs, "model", "")
        kind = _merged(self, attrs, "kind", "")
        has_ssh = bool(
            _merged(self, attrs, "ssh_username")
            and (_merged(self, attrs, "ssh_password") or _merged(self, attrs, "ssh_private_key"))
        )
        has_api = bool(_merged(self, attrs, "api_token") and vendor == Vendor.FORTINET)

        if _merged(self, attrs, "backup_enabled", False):
            if not (has_ssh or has_api):
                errors["backup_enabled"] = (
                    "配置备份需要 SSH 用户名 + 密码/私钥(FortiGate 也可只填 API Token)"
                    " —— SNMP 拿不到配置文本"
                )
            else:
                from netcheck.devices.profiles import get_profile

                if not get_profile(model, vendor).backup_cli and not has_api:
                    errors["backup_enabled"] = (
                        "这个型号的采集画像里没有定义备份命令,开了也备不了。"
                        "选一个在册型号,或在 devices/profiles.py 里补一条 backup_cli"
                    )

        if _merged(self, attrs, "policy_sync_enabled", False):
            if kind != DeviceKind.FIREWALL:
                errors["policy_sync_enabled"] = "策略同步只对防火墙有意义"
            elif vendor != Vendor.FORTINET:
                errors["policy_sync_enabled"] = (
                    "策略同步目前只实现了 FortiGate(FortiOS)。"
                    "加别的厂商要在 devices/policies.py 里补一个解析器"
                )
            elif not (has_api or has_ssh):
                errors["policy_sync_enabled"] = (
                    "策略同步需要 API Token(推荐,只有 API 有命中计数)或 SSH 凭据"
                )

        if errors:
            raise serializers.ValidationError(errors)
        return attrs


class DeviceInterfaceSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source="device.name", read_only=True)
    util_in_pct = serializers.FloatField(read_only=True)
    util_out_pct = serializers.FloatField(read_only=True)
    # **数据成色**:ifHC*(64 位)采不到时退回了 32 位计数器。
    # 48 口千兆交换机满速时 32 位的 ifInOctets 约 34 秒回绕一次,60 秒
    # 采集间隔算出来的速率纯粹是噪声 —— 页面上必须能看出这个数不可信,
    # 否则会有人拿它去排查一个不存在的流量问题(见 CLAUDE.md 第 6 条)
    counter_32bit = serializers.SerializerMethodField()
    # 管理上启用但链路 down —— 这是真正要看的那一类口
    link_problem = serializers.SerializerMethodField()

    class Meta:
        model = DeviceInterface
        fields = [
            "id", "device", "device_name", "if_index", "if_name", "if_alias", "if_type",
            "mac", "speed_bps", "admin_up", "oper_up", "last_change", "monitored",
            "in_bps", "out_bps", "in_err_delta", "out_err_delta",
            "util_in_pct", "util_out_pct", "counter_32bit", "link_problem", "updated_at",
        ]
        read_only_fields = [
            "if_index", "if_name", "if_alias", "if_type", "mac", "speed_bps",
            "admin_up", "oper_up", "last_change", "in_bps", "out_bps",
            "in_err_delta", "out_err_delta",
        ]

    def get_counter_32bit(self, obj) -> bool:
        return bool((obj.meta or {}).get("counter_32bit"))

    def get_link_problem(self, obj) -> bool:
        # admin down 是人为关的,不是故障 —— 不算问题
        return bool(obj.admin_up) and obj.oper_up is False


class DeviceSampleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceSample
        fields = [
            "id", "device", "ts", "reachable", "method", "latency_ms",
            "cpu_pct", "mem_pct", "temp_c", "uptime_s",
            "session_count", "session_rate", "ha_state", "vpn_tunnels_up",
            "if_total", "if_up", "psu_ok", "fan_ok", "extra", "error",
        ]


class InterfaceSampleSerializer(serializers.ModelSerializer):
    class Meta:
        model = InterfaceSample
        fields = [
            "id", "interface", "ts", "in_bps", "out_bps",
            "in_errors", "out_errors", "in_discards", "out_discards", "oper_up",
        ]


class DeviceNeighborSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source="device.name", read_only=True)
    matched_device_name = serializers.CharField(
        source="matched_device.name", read_only=True, default="")
    # 本地口没解析出 ifIndex 时前端要能看出来 —— 那条邻居不知道挂在哪个口,
    # 而"不知道"和"挂在 X 口"是两个结论
    local_resolved = serializers.SerializerMethodField()

    class Meta:
        model = DeviceNeighbor
        fields = [
            "id", "device", "device_name", "protocol",
            "local_if_index", "local_if_name", "local_resolved",
            "remote_device", "remote_port", "remote_platform",
            "remote_mgmt_ip", "remote_chassis_id",
            "matched_device", "matched_device_name",
            "first_seen", "last_seen", "changed_at",
        ]
        read_only_fields = fields

    def get_local_resolved(self, obj) -> bool:
        return obj.local_if_index is not None


# =========================================================================
# 服务器
# =========================================================================


class ServerSerializer(serializers.ModelSerializer):
    state_label = serializers.CharField(source="get_state_display", read_only=True)
    # 凭据只回"填过没有",不回内容 —— 和设备那边同一条规矩
    has_credential = serializers.SerializerMethodField()
    uses_key = serializers.SerializerMethodField()
    interface_count = serializers.SerializerMethodField()
    primary_interface = serializers.SerializerMethodField()
    open_event_count = serializers.SerializerMethodField()

    class Meta:
        model = Server
        fields = "__all__"
        # **关掉自动生成的 UniqueTogetherValidator。**
        # (host, ssh_port) 那条约束是"纯字段列表",所以 DRF 会自己给它生成
        # 一个校验器 —— 而它报的是 non_field_errors:"字段 host, ssh_port
        # 必须能构成唯一集合",既不指向输入框,也不说是**哪一台**已经占了
        # 这个地址。下面 validate() 里那份手写的会说"已经作为「xxx」加过了",
        # 那才是人看得懂的话。而且 run_validators() 跑在 validate() **之前**,
        # 不关掉的话手写那份永远轮不到。
        # 注意 name 的唯一性是**字段级**校验器(unique=True),不受这里影响。
        validators: list = []
        read_only_fields = [
            "state", "last_collected_at", "last_error", "consecutive_fail", "consecutive_ok",
            "hostname", "os_name", "kernel", "cpu_cores", "mem_total_bytes",
        ]
        extra_kwargs = {
            "ssh_password": {"write_only": True, "required": False, "allow_blank": True},
            "ssh_private_key": {"write_only": True, "required": False, "allow_blank": True},
            "ssh_key_passphrase": {"write_only": True, "required": False, "allow_blank": True},
        }

    def get_has_credential(self, obj) -> bool:
        return bool(obj.ssh_password or obj.ssh_private_key)

    def get_uses_key(self, obj) -> bool:
        return bool(obj.ssh_private_key)

    def get_interface_count(self, obj) -> int:
        return getattr(obj, "interface_count_ann", None) or obj.interfaces.count()

    def get_primary_interface(self, obj) -> str:
        iface = next((i for i in obj.interfaces.all() if i.is_primary), None)
        return iface.if_name if iface else ""

    def get_open_event_count(self, obj) -> int:
        return getattr(obj, "open_event_count_ann", None) or obj.events.filter(
            resolved_at__isnull=True
        ).count()

    def validate(self, attrs):
        """Server.clean() 的镜像 —— 两边必须一起改。"""

        errors = {}
        if not _merged(self, attrs, "ssh_password") and not _merged(self, attrs, "ssh_private_key"):
            errors["ssh_password"] = "SSH 采集需要密码或私钥"

        for warn_field, crit_field, label in (
            ("cpu_warn_pct", "cpu_crit_pct", "CPU"),
            ("mem_warn_pct", "mem_crit_pct", "内存"),
            ("disk_warn_pct", "disk_crit_pct", "磁盘"),
            ("load_warn", "load_crit", "负载"),
        ):
            warn = _merged(self, attrs, warn_field, 0)
            crit = _merged(self, attrs, crit_field, 0)
            if crit and warn and warn > crit:
                errors[warn_field] = f"{label}警告线不能高于严重线"

        # 端点重复。**必须手写** —— 和 ProbeTarget 那条同一个理由:
        # 撞了唯一约束会以 IntegrityError 冒成 500,页面上看到的是
        # "服务器错误"而不是"这台机器已经加过了"
        host = _merged(self, attrs, "host")
        port = _merged(self, attrs, "ssh_port", 22)
        if host:
            clash = Server.objects.filter(host=host, ssh_port=port)
            if self.instance is not None:
                clash = clash.exclude(pk=self.instance.pk)
            if existing := clash.first():
                errors["host"] = (
                    f"{host}:{port} 已经作为「{existing.name}」加过了。"
                    "同一台机器加两遍会被采两遍,图上是两条一样的线、事件也开两条"
                )

        if errors:
            raise serializers.ValidationError(errors)
        return attrs


class ServerSampleSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServerSample
        fields = [
            "id", "server", "ts", "reachable", "latency_ms",
            "cpu_pct", "cpu_iowait_pct", "mem_pct", "swap_pct", "disk_pct",
            "load1", "load5", "load15", "uptime_s", "process_count", "tcp_established",
            "net_in_bps", "net_out_bps", "extra", "error",
        ]


class ServerInterfaceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServerInterface
        fields = [
            "id", "server", "if_name", "is_primary", "is_virtual",
            "in_bps", "out_bps", "in_err_delta", "out_err_delta", "updated_at",
        ]
        read_only_fields = fields


# =========================================================================
# 配置备份
# =========================================================================


class DeviceBackupSerializer(serializers.ModelSerializer):
    """
    版本列表用。**不带 content** —— 一份配置几十 KB 到几 MB,
    列表一页二十行就是几十 MB 的响应。全文走单独的 detail / download 接口。
    """

    device_name = serializers.CharField(source="device.name", read_only=True)
    short_hash = serializers.CharField(read_only=True)

    class Meta:
        model = DeviceBackup
        fields = [
            "id", "device", "device_name", "ts", "last_seen_at", "seen_count",
            "method", "size_bytes", "line_count", "content_hash", "short_hash",
            "lines_added", "lines_removed", "is_first",
        ]
        read_only_fields = fields


class DeviceBackupDetailSerializer(DeviceBackupSerializer):
    """单个版本的全文。只在明确要看某一个版本时用。"""

    class Meta(DeviceBackupSerializer.Meta):
        fields = DeviceBackupSerializer.Meta.fields + ["content"]
        read_only_fields = fields


# =========================================================================
# 防火墙策略
# =========================================================================


class FirewallPolicySerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source="device.name", read_only=True)
    action_label = serializers.CharField(source="get_action_display", read_only=True)
    # 三态:True / False / None(不知道)。**前端要区分 None 和 False** ——
    # "从没命中过"能拿去删规则,"不知道有没有命中"不能
    never_hit = serializers.BooleanField(read_only=True, allow_null=True)
    # 规则审计:过宽 / 不记日志。只对"启用且放行"的规则判(见 models.py)
    permissive_level = serializers.CharField(read_only=True)
    logging_off = serializers.BooleanField(read_only=True)

    class Meta:
        model = FirewallPolicy
        fields = [
            "id", "device", "device_name", "vdom", "policy_id", "seq", "name",
            "src_intf", "dst_intf", "src_addr", "dst_addr", "service", "schedule",
            "action", "action_label", "enabled", "nat", "log_traffic", "comments", "uuid",
            "hit_count", "bytes_count", "packets", "sessions",
            "first_hit_at", "last_hit_at", "never_hit",
            "permissive_level", "logging_off",
            "synced_at", "method",
        ]
        read_only_fields = fields


class FirewallPolicyDetailSerializer(FirewallPolicySerializer):
    """带 raw。策略有上百个字段,页面上只展示十几个,剩下的从这里看。"""

    class Meta(FirewallPolicySerializer.Meta):
        fields = FirewallPolicySerializer.Meta.fields + ["raw"]
        read_only_fields = fields


# =========================================================================
# 事件
# =========================================================================


class EventSerializer(serializers.ModelSerializer):
    kind_label = serializers.CharField(source="get_kind_display", read_only=True)
    severity_label = serializers.CharField(source="get_severity_display", read_only=True)
    source_type_label = serializers.CharField(source="get_source_type_display", read_only=True)
    source_name = serializers.CharField(read_only=True)
    is_open = serializers.BooleanField(read_only=True)
    group_name = serializers.SerializerMethodField()
    # 未恢复的事件持续时长要实时算 —— duration_s 只在恢复时才回填
    live_duration_s = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = [
            "id", "source_type", "source_type_label", "source_name", "group_name",
            "target", "device", "interface", "server",
            "kind", "kind_label", "severity", "severity_label",
            "title", "message", "started_at", "resolved_at", "duration_s", "live_duration_s",
            "trigger_value", "threshold", "unit", "fail_count", "recovery_value",
            "notified_alert", "notified_recover",
            "acknowledged_at", "acknowledged_by", "note", "is_open",
        ]
        read_only_fields = [
            "source_type", "target", "device", "interface", "server", "kind", "severity",
            "title", "message", "started_at", "resolved_at", "duration_s",
            "trigger_value", "threshold", "unit", "fail_count", "recovery_value",
            "notified_alert", "notified_recover",
        ]

    def get_group_name(self, obj) -> str:
        if obj.target_id and obj.target and obj.target.group_id:
            return obj.target.group.name
        return ""

    def get_live_duration_s(self, obj) -> int:
        from django.utils import timezone

        if obj.duration_s is not None:
            return obj.duration_s
        return max(0, int((timezone.now() - obj.started_at).total_seconds()))


# =========================================================================
# 通知
# =========================================================================


class NotifierSerializer(serializers.ModelSerializer):
    kind_label = serializers.CharField(source="get_kind_display", read_only=True)
    has_token = serializers.SerializerMethodField()
    group_names = serializers.SerializerMethodField()

    class Meta:
        model = Notifier
        fields = "__all__"
        read_only_fields = ["last_sent_at", "last_error", "total_sent", "total_failed"]
        extra_kwargs = {
            "telegram_bot_token": {"write_only": True, "required": False, "allow_blank": True},
        }

    def get_has_token(self, obj) -> bool:
        return bool(obj.telegram_bot_token)

    def get_group_names(self, obj) -> list:
        return list(obj.groups.values_list("name", flat=True))

    def validate(self, attrs):
        """Notifier.clean() 的镜像。"""

        errors = {}
        kind = _merged(self, attrs, "kind")

        if kind == NotifierKind.TELEGRAM:
            if not _merged(self, attrs, "telegram_bot_token"):
                errors["telegram_bot_token"] = "Telegram 渠道必须填 Bot Token"
            if not _merged(self, attrs, "telegram_chat_id"):
                errors["telegram_chat_id"] = "Telegram 渠道必须填 Chat ID"
        elif kind == NotifierKind.WEBHOOK:
            url = _merged(self, attrs, "webhook_url", "")
            if not url:
                errors["webhook_url"] = "Webhook 渠道必须填地址"
            elif not str(url).startswith(("http://", "https://")):
                errors["webhook_url"] = "地址必须以 http:// 或 https:// 开头"
            headers = _merged(self, attrs, "webhook_headers", {})
            if headers and not isinstance(headers, dict):
                errors["webhook_headers"] = "自定义请求头必须是 JSON 对象"

        kinds = _merged(self, attrs, "kinds", [])
        if kinds and not isinstance(kinds, list):
            errors["kinds"] = "推送类型必须是数组"

        if errors:
            raise serializers.ValidationError(errors)
        return attrs


class NotifyLogSerializer(serializers.ModelSerializer):
    notifier_name = serializers.CharField(source="notifier.name", read_only=True)
    notifier_kind = serializers.CharField(source="notifier.kind", read_only=True)
    status_label = serializers.CharField(source="get_status_display", read_only=True)
    event_title = serializers.CharField(source="event.title", read_only=True, default="")

    class Meta:
        model = NotifyLog
        fields = [
            "id", "notifier", "notifier_name", "notifier_kind", "event", "event_title",
            "phase", "status", "status_label", "ts", "http_status", "duration_ms", "detail",
        ]
