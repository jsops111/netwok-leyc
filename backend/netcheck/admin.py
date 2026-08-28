"""
Django admin —— 只做"出事时能直接翻库"的兜底,日常操作走前端配置中心。

凭据字段一律不在 admin 里显示 —— admin 没有前端那层 write_only 保护,
列出来就是明文。
"""

from django.contrib import admin

from netcheck.models import (
    Device,
    DeviceInterface,
    Event,
    Notifier,
    NotifyLog,
    ProbeGroup,
    ProbeTarget,
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
