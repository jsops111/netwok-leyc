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
    DeviceNeighbor,
    Event,
    FirewallPolicy,
    FirewallAddress,
    FirewallVip,
    IdracHost,
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

    # 只看有问题的口:**admin up 但链路 down**,或者本周期新增了错包。
    # 这是巡检时唯一真正要看的那一列 —— 48 口交换机上一半是空的,
    # 而 admin down 是人为关的、不是故障
    problem = filters.BooleanFilter(method="filter_problem", label="仅异常接口")
    keyword = filters.CharFilter(method="filter_keyword", label="接口名或描述")

    def filter_active(self, queryset, name, value):
        if value:
            return queryset.filter(oper_up=True)
        return queryset

    def filter_problem(self, queryset, name, value):
        from django.db.models import Q

        if value is None:
            return queryset
        cond = (
            Q(admin_up=True, oper_up=False)
            | Q(in_err_delta__gt=0)
            | Q(out_err_delta__gt=0)
        )
        return queryset.filter(cond) if value else queryset.exclude(cond)

    def filter_keyword(self, queryset, name, value):
        from django.db.models import Q

        return queryset.filter(Q(if_name__icontains=value) | Q(if_alias__icontains=value))


class DeviceNeighborFilter(filters.FilterSet):
    device = filters.NumberFilter(field_name="device_id")
    keyword = filters.CharFilter(method="filter_keyword", label="本地口/对端/平台")
    # 只看「两端都在这个平台管着」的链路 —— 那些是能画成拓扑的
    managed_only = filters.BooleanFilter(
        field_name="matched_device", lookup_expr="isnull", exclude=True, label="仅受管链路")
    # 最近变过的 —— "谁动了线"
    changed = filters.BooleanFilter(
        field_name="changed_at", lookup_expr="isnull", exclude=True, label="曾发生变化")

    class Meta:
        model = DeviceNeighbor
        fields = ["device", "protocol"]

    def filter_keyword(self, queryset, name, value):
        from django.db.models import Q

        return queryset.filter(
            Q(local_if_name__icontains=value)
            | Q(remote_device__icontains=value)
            | Q(remote_port__icontains=value)
            | Q(remote_platform__icontains=value)
            | Q(remote_mgmt_ip__icontains=value)
        )


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
    # 审计筛选。**在 SQL 里重写一遍判定条件,不是拿属性去 filter** ——
    # permissive_level / logging_off 是 Python 属性,数据库不认识它们。
    # 两边的规则必须一致(和"模型 clean 要在序列化器里写第二遍"同一类问题),
    # 改 models.py 里那几个属性时**这里要一起改**
    permissive = filters.BooleanFilter(method="filter_permissive", label="过宽规则")
    no_log = filters.BooleanFilter(method="filter_no_log", label="放行但不记日志")

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

    def filter_permissive(self, queryset, name, value):
        """
        过宽 = 启用 + 放行 + 服务任意 + (源或目的任意)。

        JSON 数组里找 "all"/"any" 用 icontains 匹配文本形式 —— 精确匹配要
        jsonb 的 contains 查询,而 `["all"]` 和 `["ALL"]` 大小写不统一,
        icontains 反而更稳。代价是 `["all-servers"]` 这种名字会被误命中,
        所以带引号一起匹配:`"all"` 而不是 `all`
        """
        from django.db.models import Q

        if value is None:
            return queryset
        svc_any = Q(service__icontains='"all"') | Q(service__icontains='"any"') | Q(service=[])
        src_any = Q(src_addr__icontains='"all"') | Q(src_addr__icontains='"any"') | Q(src_addr=[])
        dst_any = Q(dst_addr__icontains='"all"') | Q(dst_addr__icontains='"any"') | Q(dst_addr=[])
        cond = Q(enabled=True, action="accept") & svc_any & (src_any | dst_any)
        return queryset.filter(cond) if value else queryset.exclude(cond)

    def filter_no_log(self, queryset, name, value):
        from django.db.models import Q

        if value is None:
            return queryset
        cond = Q(enabled=True, action="accept") & (
            Q(log_traffic="") | Q(log_traffic__iexact="disable") | Q(log_traffic__iexact="disabled")
        )
        return queryset.filter(cond) if value else queryset.exclude(cond)



class IdracHostFilter(filters.FilterSet):
    keyword = filters.CharFilter(method="filter_keyword", label="名称/地址/型号/服务编号")
    # 「有未恢复告警的」—— 大屏点进来时用。**在 SQL 里判**,
    # 不是拿序列化器上那个计数字段筛(那是 Python 侧算的)
    has_open_events = filters.BooleanFilter(method="filter_has_open_events", label="有未恢复告警")
    site = filters.CharFilter(field_name="site", lookup_expr="icontains")

    class Meta:
        model = IdracHost
        fields = ["enabled", "state", "site", "role", "server"]

    def filter_keyword(self, queryset, name, value):
        from django.db.models import Q

        return queryset.filter(
            Q(name__icontains=value)
            | Q(host__icontains=value)
            | Q(model_name__icontains=value)
            | Q(service_tag__icontains=value)
            | Q(system_hostname__icontains=value)
        )

    def filter_has_open_events(self, queryset, name, value):
        if value is None:
            return queryset
        return queryset.filter(events__resolved_at__isnull=True).distinct() if value \
            else queryset.exclude(events__resolved_at__isnull=True)


class FirewallAddressFilter(filters.FilterSet):
    device = filters.NumberFilter(field_name="device_id")
    keyword = filters.CharFilter(method="filter_keyword", label="名称/地址值/备注")
    # 「只看地址组」—— 别名查询里最常用的一个筛
    is_group = filters.BooleanFilter(field_name="is_group")

    class Meta:
        model = FirewallAddress
        fields = ["device", "vdom", "addr_type", "is_group", "method"]

    def filter_keyword(self, queryset, name, value):
        from django.db.models import Q

        return queryset.filter(
            Q(name__icontains=value)
            | Q(value__icontains=value)
            | Q(comment__icontains=value)
            # 组的成员名单也要能搜到 —— 「哪个组里有 web-svr」是个真问题
            | Q(members__icontains=value)
        )


class FirewallVipFilter(filters.FilterSet):
    device = filters.NumberFilter(field_name="device_id")
    keyword = filters.CharFilter(method="filter_keyword", label="名称/地址/备注")
    # 「整机映射」—— 外网地址的所有端口都通到内网那台机器上。这是这张表里
    # 唯一值得单独筛的风险,而它在列表里和一条只映射 443 的规则长得几乎一样。
    # **在 SQL 里重写 models.whole_host 那条判定**(数据库不认识 Python 属性),
    # 改模型上那个属性时这里要一起改 —— 和 filter_permissive 同一类问题
    whole_host = filters.BooleanFilter(method="filter_whole_host", label="整机映射")

    class Meta:
        model = FirewallVip
        fields = ["device", "vdom", "vip_type", "port_forward", "protocol", "method"]

    def filter_whole_host(self, queryset, name, value):
        """`whole_host` 就是 `port_forward` 取反(见 models.FirewallVip)。"""
        if value is None:
            return queryset
        return queryset.filter(port_forward=not value)

    def filter_keyword(self, queryset, name, value):
        from django.db.models import Q

        return queryset.filter(
            Q(name__icontains=value)
            | Q(comment__icontains=value)
            | Q(ext_ip__icontains=value)
            | Q(mapped_ip__icontains=value)
            | Q(ext_port__icontains=value)
            | Q(mapped_port__icontains=value)
            | Q(ext_intf__icontains=value)
        )


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
