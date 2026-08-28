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
    DeviceInterface,
    DeviceSample,
    Event,
    InterfaceSample,
    Notifier,
    NotifierKind,
    NotifyLog,
    ProbeGroup,
    ProbeRollup,
    ProbeSample,
    ProbeTarget,
    Protocol,
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

        if errors:
            raise serializers.ValidationError(errors)
        return attrs


class DeviceInterfaceSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source="device.name", read_only=True)
    util_in_pct = serializers.FloatField(read_only=True)
    util_out_pct = serializers.FloatField(read_only=True)

    class Meta:
        model = DeviceInterface
        fields = [
            "id", "device", "device_name", "if_index", "if_name", "if_alias", "if_type",
            "mac", "speed_bps", "admin_up", "oper_up", "last_change", "monitored",
            "in_bps", "out_bps", "in_err_delta", "out_err_delta",
            "util_in_pct", "util_out_pct", "updated_at",
        ]
        read_only_fields = [
            "if_index", "if_name", "if_alias", "if_type", "mac", "speed_bps",
            "admin_up", "oper_up", "last_change", "in_bps", "out_bps",
            "in_err_delta", "out_err_delta",
        ]


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
            "target", "device", "interface",
            "kind", "kind_label", "severity", "severity_label",
            "title", "message", "started_at", "resolved_at", "duration_s", "live_duration_s",
            "trigger_value", "threshold", "unit", "fail_count", "recovery_value",
            "notified_alert", "notified_recover",
            "acknowledged_at", "acknowledged_by", "note", "is_open",
        ]
        read_only_fields = [
            "source_type", "target", "device", "interface", "kind", "severity",
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
