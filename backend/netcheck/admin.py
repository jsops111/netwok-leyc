"""
Django admin —— 只做"出事时能直接翻库"的兜底,日常操作走前端配置中心。

凭据字段一律不在 admin 里显示 —— admin 没有前端那层 write_only 保护,
列出来就是明文。
"""

from django.contrib import admin

from netcheck.models import (
    Device,
    DeviceBackup,
    DeviceInterface,
    DeviceNeighbor,
    Event,
    FirewallPolicy,
    FirewallAddress,
    FirewallService,
    SdwanLink,
    FirewallVip,
    IdracHost,
    IdracSample,
    Notifier,
    NotifyLog,
    ProbeGroup,
    ProbeTarget,
    Server,
    ServerInterface,
)


@admin.register(ProbeGroup)
class ProbeGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "order", "enabled", "created_at")
    list_filter = ("enabled",)
    search_fields = ("name",)


@admin.register(ProbeTarget)
class ProbeTargetAdmin(admin.ModelAdmin):
    list_display = ("name", "group", "host", "protocol", "port", "interval_seconds",
                    "state", "last_rtt_ms", "enabled")
    list_filter = ("group", "protocol", "state", "enabled")
    search_fields = ("name", "host")
    readonly_fields = ("state", "last_checked_at", "last_rtt_ms", "last_loss_pct",
                       "last_jitter_ms", "last_error", "total_checks", "total_fail")


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "vendor", "model", "mgmt_ip", "collect_method",
                    "state", "os_version", "enabled")
    list_filter = ("kind", "vendor", "model", "collect_method", "state", "enabled")
    search_fields = ("name", "mgmt_ip", "serial")
    # 凭据字段不进 admin 表单
    exclude = ("snmp_community", "snmp_v3_auth_key", "snmp_v3_priv_key",
               "ssh_password", "ssh_private_key", "ssh_enable_password", "api_token")
    readonly_fields = ("state", "last_collected_at", "last_method_used", "last_error")


@admin.register(DeviceInterface)
class DeviceInterfaceAdmin(admin.ModelAdmin):
    list_display = ("device", "if_index", "if_name", "oper_up", "speed_bps",
                    "in_bps", "out_bps", "monitored")
    list_filter = ("device", "oper_up", "monitored")
    search_fields = ("if_name", "if_alias")


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ("started_at", "severity", "kind", "title", "resolved_at",
                    "duration_s", "notified_alert")
    list_filter = ("severity", "kind", "source_type")
    search_fields = ("title", "message")
    date_hierarchy = "started_at"


@admin.register(Notifier)
class NotifierAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "enabled", "min_severity", "total_sent",
                    "total_failed", "last_sent_at")
    list_filter = ("kind", "enabled")
    exclude = ("telegram_bot_token",)


@admin.register(NotifyLog)
class NotifyLogAdmin(admin.ModelAdmin):
    list_display = ("ts", "notifier", "phase", "status", "http_status", "duration_ms")
    list_filter = ("status", "phase", "notifier")
    date_hierarchy = "ts"


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = ("name", "host", "ssh_port", "state", "os_name",
                    "cpu_cores", "interval_seconds", "enabled")
    list_filter = ("state", "enabled", "site", "role")
    search_fields = ("name", "host", "hostname")
    # 凭据字段不进 admin 表单 —— admin 没有前端那层 write_only 保护
    exclude = ("ssh_password", "ssh_private_key", "ssh_key_passphrase")
    readonly_fields = ("state", "last_collected_at", "last_error", "hostname",
                       "os_name", "kernel", "cpu_cores", "mem_total_bytes")


@admin.register(ServerInterface)
class ServerInterfaceAdmin(admin.ModelAdmin):
    list_display = ("server", "if_name", "is_primary", "is_virtual", "in_bps", "out_bps")
    list_filter = ("server", "is_primary", "is_virtual")
    search_fields = ("if_name",)


@admin.register(DeviceBackup)
class DeviceBackupAdmin(admin.ModelAdmin):
    list_display = ("device", "ts", "last_seen_at", "seen_count", "method",
                    "line_count", "size_bytes", "short_hash")
    list_filter = ("device", "method", "is_first")
    date_hierarchy = "ts"
    # content 是几十 KB 到几 MB 的文本。admin 的列表页不该去读它,
    # 编辑页把它渲染成一个巨大的 textarea 也没有意义 —— 看全文用前端页面
    exclude = ("content",)
    readonly_fields = ("device", "ts", "last_seen_at", "seen_count", "method",
                       "size_bytes", "line_count", "content_hash",
                       "lines_added", "lines_removed", "is_first")


@admin.register(FirewallPolicy)
class FirewallPolicyAdmin(admin.ModelAdmin):
    list_display = ("device", "vdom", "policy_id", "seq", "name", "action",
                    "enabled", "nat", "hit_count", "synced_at")
    list_filter = ("device", "vdom", "action", "enabled", "method")
    search_fields = ("name", "comments")


@admin.register(FirewallVip)
class FirewallVipAdmin(admin.ModelAdmin):
    # endpoint_text 是模型属性,列表里显示它而不是分散的四列 ——
    # `1.2.3.4:443 → 10.0.0.5:8443` 一眼能读,而且端口为空时它说
    # 「所有端口」而不是留白
    list_display = ("device", "vdom", "name", "endpoint_text", "vip_type",
                    "port_forward", "synced_at")
    list_filter = ("device", "vdom", "vip_type", "port_forward", "method")
    search_fields = ("name", "comment", "ext_ip", "mapped_ip")


@admin.register(FirewallAddress)
class FirewallAddressAdmin(admin.ModelAdmin):
    list_display = ("device", "vdom", "name", "addr_type", "is_group", "display", "synced_at")
    list_filter = ("device", "vdom", "addr_type", "is_group", "method")
    search_fields = ("name", "value", "comment")


@admin.register(FirewallService)
class FirewallServiceAdmin(admin.ModelAdmin):
    list_display = ("device", "vdom", "name", "protocol", "is_group", "display", "synced_at")
    list_filter = ("device", "vdom", "is_group", "protocol", "method")
    search_fields = ("name", "value", "comment", "category")


@admin.register(SdwanLink)
class SdwanLinkAdmin(admin.ModelAdmin):
    list_display = ("device", "health_check", "member", "state", "latency_ms",
                    "jitter_ms", "loss_pct", "sla_text", "synced_at")
    list_filter = ("device", "vdom", "state", "method")
    search_fields = ("health_check", "member", "server")


@admin.register(IdracHost)
class IdracHostAdmin(admin.ModelAdmin):
    # **password 不出现在任何一栏** —— 和 SNMP community、TOTP 密钥同级,
    # 它是 EncryptedTextField,admin 里也不该显示
    list_display = ("name", "host", "model_name", "service_tag", "state",
                    "power_state", "last_collected_at", "enabled")
    list_filter = ("enabled", "state", "site", "manufacturer")
    search_fields = ("name", "host", "model_name", "service_tag", "system_hostname")
    exclude = ("password",)


@admin.register(IdracSample)
class IdracSampleAdmin(admin.ModelAdmin):
    list_display = ("idrac", "ts", "reachable", "health", "max_temp_c",
                    "power_watts", "disk_bad", "psu_bad")
    list_filter = ("idrac", "reachable", "health")
    date_hierarchy = "ts"


@admin.register(DeviceNeighbor)
class DeviceNeighborAdmin(admin.ModelAdmin):
    list_display = ("device", "local_if_name", "protocol", "remote_device",
                    "remote_port", "matched_device", "last_seen", "changed_at")
    list_filter = ("device", "protocol")
    search_fields = ("local_if_name", "remote_device", "remote_port", "remote_mgmt_ip")
