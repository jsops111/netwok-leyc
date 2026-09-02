"""
列表过滤。

事件表的过滤条件是这里的重点 —— 事件记录页面要能回答"最近 24 小时哪条线路
断得最多"这类问题,所以时间范围、是否已恢复、级别、类型都要能筛。
"""

from __future__ import annotations

import django_filters as filters

from netcheck.models import (
    Device,
    DeviceBackup,
    DeviceInterface,
    Event,
    FirewallPolicy,
    Notifier,
    ProbeTarget,
    Server,
)


class ProbeTargetFilter(filters.FilterSet):
    group = filters.NumberFilter(field_name="group_id")
    keyword = filters.CharFilter(method="filter_keyword", label="名称或地址")

    class Meta:
        model = ProbeTarget
        fields = ["group", "protocol", "state", "enabled"]

    def filter_keyword(self, queryset, name, value):
        from django.db.models import Q

        return queryset.filter(Q(name__icontains=value) | Q(host__icontains=value))


class DeviceFilter(filters.FilterSet):
    keyword = filters.CharFilter(method="filter_keyword", label="名称或地址")

    class Meta:
        model = Device
        fields = ["kind", "vendor", "model", "collect_method", "state", "enabled", "site"]

    def filter_keyword(self, queryset, name, value):
        from django.db.models import Q

        return queryset.filter(
            Q(name__icontains=value) | Q(mgmt_ip__icontains=value) | Q(serial__icontains=value)
        )


class DeviceInterfaceFilter(filters.FilterSet):
    device = filters.NumberFilter(field_name="device_id")
    # 只看有流量的口 —— 48 口交换机上一半是空的,默认全列会把有用信息挤出去
    active = filters.BooleanFilter(method="filter_active", label="仅活动接口")

    class Meta:
        model = DeviceInterface
        fields = ["device", "oper_up", "admin_up", "monitored"]

    def filter_active(self, queryset, name, value):
        if value:
            return queryset.filter(oper_up=True)
        return queryset


class ServerFilter(filters.FilterSet):
    keyword = filters.CharFilter(method="filter_keyword", label="名称/地址/主机名")

    class Meta:
        model = Server
        fields = ["state", "enabled", "site", "role"]

    def filter_keyword(self, queryset, name, value):
        from django.db.models import Q

        return queryset.filter(
            Q(name__icontains=value) | Q(host__icontains=value) | Q(hostname__icontains=value)
        )


class DeviceBackupFilter(filters.FilterSet):
    device = filters.NumberFilter(field_name="device_id")
    # 只看"真的改过"的版本 —— 首个版本不算一次变更
    changed_only = filters.BooleanFilter(method="filter_changed", label="仅变更版本")

    class Meta:
        model = DeviceBackup
        fields = ["device", "method"]

    def filter_changed(self, queryset, name, value):
        if value:
            return queryset.filter(is_first=False)
        return queryset


class FirewallPolicyFilter(filters.FilterSet):
    device = filters.NumberFilter(field_name="device_id")
    keyword = filters.CharFilter(method="filter_keyword", label="名称/地址/服务/备注")
    # 「从没命中过的规则」—— 这个页面最有价值的一个筛选:它给出的是
    # 一份可以拿去清理的候选清单。**hit_count 为 null 的不算**
    # (那是"不知道",不是"没命中"),所以这里显式排除 null
    never_hit = filters.BooleanFilter(method="filter_never_hit", label="从未命中")
    has_hits = filters.BooleanFilter(method="filter_has_hits", label="有命中统计")

    class Meta:
        model = FirewallPolicy
        fields = ["device", "vdom", "action", "enabled", "nat", "method"]

    def filter_keyword(self, queryset, name, value):
        from django.db.models import Q

        # JSON 数组里的地址/服务用 icontains 搜文本形式 —— Postgres 会把
        # jsonb 转成文本再匹配。精确匹配要 jsonb 的 contains 查询,
        # 而这里要的是"输 10.0 能搜到 10.0.0.0/8"这种模糊查找
        return queryset.filter(
            Q(name__icontains=value)
            | Q(comments__icontains=value)
            | Q(src_addr__icontains=value)
            | Q(dst_addr__icontains=value)
            | Q(service__icontains=value)
            | Q(src_intf__icontains=value)
            | Q(dst_intf__icontains=value)
        )

    def filter_never_hit(self, queryset, name, value):
        if value is None:
            return queryset
        if value:
            return queryset.filter(hit_count=0)
        return queryset.filter(hit_count__gt=0)

    def filter_has_hits(self, queryset, name, value):
        if value is None:
            return queryset
        return queryset.filter(hit_count__isnull=not value)


class EventFilter(filters.FilterSet):
    started_after = filters.IsoDateTimeFilter(field_name="started_at", lookup_expr="gte")
    started_before = filters.IsoDateTimeFilter(field_name="started_at", lookup_expr="lte")
    # open=true 只看未恢复的,open=false 只看已恢复的
    open = filters.BooleanFilter(method="filter_open", label="仅未恢复")
    target = filters.NumberFilter(field_name="target_id")
    device = filters.NumberFilter(field_name="device_id")
    server = filters.NumberFilter(field_name="server_id")
    group = filters.NumberFilter(field_name="target__group_id", label="监控类")
    keyword = filters.CharFilter(method="filter_keyword", label="标题或详情")
    # 最近 N 小时 —— 页面上那几个快捷时间按钮走这个参数
    hours = filters.NumberFilter(method="filter_hours", label="最近 N 小时")

    class Meta:
        model = Event
        fields = ["source_type", "kind", "severity", "open", "target", "device", "server", "group"]

    def filter_open(self, queryset, name, value):
        if value is None:
            return queryset
        return queryset.filter(resolved_at__isnull=bool(value))

    def filter_keyword(self, queryset, name, value):
        from django.db.models import Q

        return queryset.filter(Q(title__icontains=value) | Q(message__icontains=value))

    def filter_hours(self, queryset, name, value):
        from datetime import timedelta

        from django.utils import timezone

        try:
            hours = float(value)
        except (TypeError, ValueError):
            return queryset
        return queryset.filter(started_at__gte=timezone.now() - timedelta(hours=hours))


class NotifierFilter(filters.FilterSet):
    class Meta:
        model = Notifier
        fields = ["kind", "enabled", "min_severity"]
