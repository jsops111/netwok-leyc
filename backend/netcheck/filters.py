"""
列表过滤。

事件表的过滤条件是这里的重点 —— 事件记录页面要能回答"最近 24 小时哪条线路
断得最多"这类问题,所以时间范围、是否已恢复、级别、类型都要能筛。
"""

from __future__ import annotations

import django_filters as filters

from netcheck.models import Device, DeviceInterface, Event, Notifier, ProbeTarget


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


class EventFilter(filters.FilterSet):
    started_after = filters.IsoDateTimeFilter(field_name="started_at", lookup_expr="gte")
    started_before = filters.IsoDateTimeFilter(field_name="started_at", lookup_expr="lte")
    # open=true 只看未恢复的,open=false 只看已恢复的
    open = filters.BooleanFilter(method="filter_open", label="仅未恢复")
    target = filters.NumberFilter(field_name="target_id")
    device = filters.NumberFilter(field_name="device_id")
    group = filters.NumberFilter(field_name="target__group_id", label="监控类")
    keyword = filters.CharFilter(method="filter_keyword", label="标题或详情")
    # 最近 N 小时 —— 页面上那几个快捷时间按钮走这个参数
    hours = filters.NumberFilter(method="filter_hours", label="最近 N 小时")

    class Meta:
        model = Event
        fields = ["source_type", "kind", "severity", "open", "target", "device", "group"]

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
