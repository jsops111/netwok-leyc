"""
API 视图。

除了标准 CRUD,这里有三组"给大屏用"的聚合接口 —— 它们是这个文件的重点,
因为**大屏的性能全取决于这几个接口**:

    /api/dashboard/overview/    顶部那排统计(断线/丢包/延迟/抖动/异常 次数)
    /api/dashboard/charts/      按监控类分组的图表数据,一个监控类一块
    /api/dashboard/devices/     设备卡片(交换机/防火墙)

原则:**大屏的一次刷新只打这三个接口**,不是每条线路一个请求。
几十条线路 × 每 5 秒刷新,后者会把 gunicorn 打满。
"""

from __future__ import annotations

import logging
from datetime import timedelta

from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from core.pagination import SampleCursorPagination
from netcheck import scheduler
from netcheck.filters import (
    DeviceFilter,
    DeviceInterfaceFilter,
    EventFilter,
    NotifierFilter,
    ProbeTargetFilter,
)
from netcheck.models import (
    CollectMethod,
    Device,
    DeviceInterface,
    DeviceKind,
    DeviceModel,
    DeviceSample,
    Event,
    EventKind,
    InterfaceSample,
    LinkState,
    Notifier,
    NotifierKind,
    NotifyLog,
    ProbeGroup,
    ProbeRollup,
    ProbeSample,
    ProbeTarget,
    Protocol,
    RollupBucket,
    Severity,
    SnmpSecLevel,
    SnmpVersion,
    SourceType,
    Vendor,
)
from netcheck.serializers import (
    DeviceInterfaceSerializer,
    DeviceSampleSerializer,
    DeviceSerializer,
    EventSerializer,
    InterfaceSampleSerializer,
    NotifierSerializer,
    NotifyLogSerializer,
    ProbeGroupSerializer,
    ProbeRollupSerializer,
    ProbeSampleSerializer,
    ProbeTargetSerializer,
)

log = logging.getLogger("netcheck.api")

# 顶部统计的那五项。**顺序和 value 与前端 KIND_TILES 对齐**,
# 改这里要一起改 frontend/src/composables/useDashboard.ts
TOP_KINDS = [
    EventKind.DOWN,
    EventKind.LOSS,
    EventKind.LATENCY,
    EventKind.JITTER,
    EventKind.ANOMALY,
]


# =========================================================================
# CRUD
# =========================================================================


class ProbeGroupViewSet(viewsets.ModelViewSet):
    serializer_class = ProbeGroupSerializer
    filterset_fields = ["enabled"]
    search_fields = ["name", "description"]

    def get_queryset(self):
        return ProbeGroup.objects.annotate(target_count_ann=Count("targets"))


class ProbeTargetViewSet(viewsets.ModelViewSet):
    serializer_class = ProbeTargetSerializer
    filterset_class = ProbeTargetFilter
    search_fields = ["name", "host"]
    ordering_fields = ["name", "state", "last_rtt_ms", "last_checked_at", "order"]

    def get_queryset(self):
        return (
            ProbeTarget.objects.select_related("group")
            .annotate(
                open_event_count_ann=Count("events", filter=Q(events__resolved_at__isnull=True))
            )
        )

    def perform_create(self, serializer):
        target = serializer.save()
        # 立刻排期 —— 不等下一次 sync,新建的线路马上开始探测
        if target.enabled:
            scheduler.schedule_now("probe", target.pk)

    def perform_update(self, serializer):
        target = serializer.save()
        if target.enabled:
            # 改了频率要立刻重排,否则要等当前周期走完
            scheduler.schedule_now("probe", target.pk)
        else:
            scheduler.unschedule("probe", target.pk)
            self._close_open_events(target, "线路已停用")

    def perform_destroy(self, instance):
        scheduler.unschedule("probe", instance.pk)
        self._close_open_events(instance, "线路已删除")
        instance.delete()

    @staticmethod
    def _close_open_events(target, reason: str):
        from netcheck.events.engine import force_resolve

        for event in target.events.filter(resolved_at__isnull=True):
            force_resolve(event, reason)

    @action(detail=True, methods=["post"])
    def test(self, request, pk=None):
        """
        立刻测一次,结果直接返回,**不写库不开事件** ——
        这是配置页面上的"试一下",不是一次正式采样。
        """
        from netcheck.probes import runner

        target = self.get_object()
        try:
            result = runner.execute(target)
            state, problems = runner.evaluate(target, result)
        except Exception as exc:  # noqa: BLE001
            log.exception("线路 %s 测试失败", target.name)
            return Response(
                {"ok": False, "error": f"{type(exc).__name__}: {exc}"},
                status=status.HTTP_200_OK,
            )
        return Response({
            "ok": result.ok, "state": state,
            "rtt_ms": result.rtt_ms, "rtt_min_ms": result.rtt_min_ms, "rtt_max_ms": result.rtt_max_ms,
            "loss_pct": result.loss_pct, "jitter_ms": result.jitter_ms,
            "error_kind": result.error_kind, "error": result.error, "extra": result.extra,
            "problems": problems,
        })

    @action(detail=True, methods=["post"])
    def probe_now(self, request, pk=None):
        """排到下一拍立刻执行(走正式流程,写库、判事件)。"""
        target = self.get_object()
        if not target.enabled:
            return Response({"detail": "线路已停用"}, status=status.HTTP_400_BAD_REQUEST)
        scheduler.schedule_now("probe", target.pk)
        return Response({"detail": "已排入下一拍"})

    @action(detail=True, methods=["get"])
    def samples(self, request, pk=None):
        """
        原始样本(画大图用)。默认最近 30 分钟。

        跨度超过 6 小时会自动改用降采样表 —— 见 series 那个 action。
        直接拉几万个原始点前端画不动,而且大部分点在屏幕上会重叠到同一像素。
        """
        target = self.get_object()
        minutes = min(int(request.query_params.get("minutes", 30)), 720)
        since = timezone.now() - timedelta(minutes=minutes)
        queryset = target.samples.filter(ts__gte=since).order_by("ts")

        paginator = SampleCursorPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        return paginator.get_paginated_response(ProbeSampleSerializer(page, many=True).data)

    @action(detail=True, methods=["get"])
    def series(self, request, pk=None):
        """
        图表数据。**按时间跨度自动选粒度** —— 这是"大图能看长时间趋势"和
        "接口不超时"之间的那个开关:

            ≤ 2 小时    原始秒级点
            ≤ 2 天      1m 桶
            ≤ 14 天     5m 桶
            更长        1h 桶
        """
        target = self.get_object()
        hours = float(request.query_params.get("hours", 1))
        since = timezone.now() - timedelta(hours=hours)

        if hours <= 2:
            rows = list(
                target.samples.filter(ts__gte=since).order_by("ts")
                .values("ts", "rtt_ms", "loss_pct", "jitter_ms", "ok", "state")[:5000]
            )
            return Response({
                "granularity": "raw", "points": len(rows),
                "series": [
                    {
                        "ts": r["ts"], "rtt": r["rtt_ms"], "loss": r["loss_pct"],
                        "jitter": r["jitter_ms"], "ok": r["ok"], "state": r["state"],
                    }
                    for r in rows
                ],
            })

        bucket = RollupBucket.M1 if hours <= 48 else (
            RollupBucket.M5 if hours <= 336 else RollupBucket.H1
        )
        rows = list(
            target.rollups.filter(bucket=bucket, ts__gte=since).order_by("ts")
            .values("ts", "rtt_avg_ms", "rtt_max_ms", "rtt_p95_ms", "loss_avg_pct",
                    "loss_max_pct", "jitter_avg_ms", "samples", "ok_count", "fail_count")[:5000]
        )
        return Response({
            "granularity": bucket, "points": len(rows),
            "series": [
                {
                    "ts": r["ts"], "rtt": r["rtt_avg_ms"], "rtt_max": r["rtt_max_ms"],
                    "rtt_p95": r["rtt_p95_ms"], "loss": r["loss_avg_pct"],
                    "loss_max": r["loss_max_pct"], "jitter": r["jitter_avg_ms"],
                    "samples": r["samples"], "fail": r["fail_count"],
                    "availability": round(r["ok_count"] / r["samples"] * 100, 2) if r["samples"] else None,
                }
                for r in rows
            ],
        })


class DeviceViewSet(viewsets.ModelViewSet):
    serializer_class = DeviceSerializer
    filterset_class = DeviceFilter
    search_fields = ["name", "mgmt_ip", "serial", "os_version"]
    ordering_fields = ["name", "kind", "state", "last_collected_at", "order"]

    def get_queryset(self):
        return Device.objects.annotate(interface_count_ann=Count("interfaces"))

    def perform_create(self, serializer):
        device = serializer.save()
        if device.enabled:
            scheduler.schedule_now("device", device.pk)

    def perform_update(self, serializer):
        device = serializer.save()
        if device.enabled:
            scheduler.schedule_now("device", device.pk)
        else:
            scheduler.unschedule("device", device.pk)
            from netcheck.events.engine import force_resolve

            for event in device.events.filter(resolved_at__isnull=True):
                force_resolve(event, "设备已停用")

    def perform_destroy(self, instance):
        scheduler.unschedule("device", instance.pk)
        instance.delete()

    @action(detail=True, methods=["post"])
    def test(self, request, pk=None):
        """测连通性。可以指定 method 单独测某条通道(排查降级配置时有用)。"""
        from netcheck.devices import collector

        device = self.get_object()
        method = request.data.get("method") or ""
        if method and method not in CollectMethod.values:
            return Response({"detail": f"未知通道 {method}"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            ok, detail = collector.test_device_connection(device, method)
        except Exception as exc:  # noqa: BLE001
            log.exception("设备 %s 连通性测试异常", device.name)
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        return Response({"ok": ok, "detail": detail, "method": method or device.collect_method})

    @action(detail=True, methods=["post"])
    def collect_now(self, request, pk=None):
        device = self.get_object()
        if not device.enabled:
            return Response({"detail": "设备已停用"}, status=status.HTTP_400_BAD_REQUEST)
        scheduler.schedule_now("device", device.pk)
        return Response({"detail": "已排入下一拍"})

    @action(detail=True, methods=["get"])
    def series(self, request, pk=None):
        """设备指标时序。设备采集频率低(≥10s),原始点直接给,不做降采样。"""
        device = self.get_object()
        hours = min(float(request.query_params.get("hours", 6)), 168)
        since = timezone.now() - timedelta(hours=hours)
        rows = list(
            device.samples.filter(ts__gte=since).order_by("ts")
            .values("ts", "reachable", "cpu_pct", "mem_pct", "temp_c",
                    "session_count", "session_rate", "if_up", "latency_ms")[:5000]
        )
        return Response({"points": len(rows), "series": rows})

    @action(detail=True, methods=["get"])
    def interfaces(self, request, pk=None):
        device = self.get_object()
        queryset = device.interfaces.all()
        if request.query_params.get("active") == "true":
            queryset = queryset.filter(oper_up=True)
        return Response(DeviceInterfaceSerializer(queryset, many=True).data)

    @action(detail=False, methods=["get"])
    def profiles(self, request):
        """
        在册型号及其采集画像。配置页面用它告诉人「这款型号能采到什么」——
        比让人自己去猜 OID 支持情况现实得多。
        """
        from netcheck.devices.profiles import PROFILES

        return Response([
            {
                "key": p.key, "label": p.label, "vendor": p.vendor,
                "metrics": sorted(p.metrics.keys()),
                "optional": sorted(p.optional),
                "absent": sorted(p.absent),
                "cli_commands": p.cli,
                "notes": p.notes,
            }
            for p in PROFILES.values()
        ])


class DeviceInterfaceViewSet(viewsets.ReadOnlyModelViewSet):
    """接口是采集出来的,不给建改删 —— 只有 monitored 开关可以调(见下)。"""

    serializer_class = DeviceInterfaceSerializer
    filterset_class = DeviceInterfaceFilter
    search_fields = ["if_name", "if_alias"]
    ordering_fields = ["if_index", "in_bps", "out_bps"]

    def get_queryset(self):
        return DeviceInterface.objects.select_related("device")

    @action(detail=True, methods=["post"])
    def toggle_monitor(self, request, pk=None):
        iface = self.get_object()
        iface.monitored = not iface.monitored
        iface.save(update_fields=["monitored"])
        return Response({"id": iface.pk, "monitored": iface.monitored})

    @action(detail=True, methods=["get"])
    def series(self, request, pk=None):
        iface = self.get_object()
        hours = min(float(request.query_params.get("hours", 6)), 168)
        since = timezone.now() - timedelta(hours=hours)
        rows = list(
            iface.samples.filter(ts__gte=since).order_by("ts")
            .values("ts", "in_bps", "out_bps", "oper_up")[:5000]
        )
        return Response({"points": len(rows), "series": rows, "speed_bps": iface.speed_bps})


class EventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    事件只读 —— 它是采集产物。可写的只有"认领"和"备注"两个动作。
    """

    serializer_class = EventSerializer
    filterset_class = EventFilter
    search_fields = ["title", "message"]
    ordering_fields = ["started_at", "resolved_at", "severity", "duration_s"]

    def get_queryset(self):
        return Event.objects.select_related(
            "target", "target__group", "device", "interface", "interface__device"
        )

    @action(detail=True, methods=["post"])
    def acknowledge(self, request, pk=None):
        event = self.get_object()
        event.acknowledged_at = timezone.now()
        event.acknowledged_by = (
            request.data.get("by") or getattr(request.user, "username", "") or "匿名"
        )[:64]
        if note := request.data.get("note"):
            event.note = (event.note + "\n" if event.note else "") + str(note)[:2000]
        event.save(update_fields=["acknowledged_at", "acknowledged_by", "note"])
        return Response(EventSerializer(event).data)

    @action(detail=True, methods=["post"])
    def renotify(self, request, pk=None):
        """重新推一次。排查"告警没收到"时用。"""
        from netcheck.tasks import send_notification

        event = self.get_object()
        phase = "recover" if event.resolved_at else "alert"
        # 清掉标记,否则 send_notification 会当成重复推送直接跳过
        if phase == "alert":
            event.notified_alert = False
            event.save(update_fields=["notified_alert"])
        else:
            event.notified_recover = False
            event.save(update_fields=["notified_recover"])
        send_notification.delay(event.pk, phase)
        return Response({"detail": f"已排入推送队列({phase})"})

    @action(detail=False, methods=["get"])
    def report(self, request):
        """
        事件报告的汇总部分:按类型、按级别、按对象排行。

        页面上的事件表自己翻页,这个接口只给它上面那几块汇总数字 ——
        分开是因为汇总要扫全时间窗,而表格只要一页。
        """
        hours = float(request.query_params.get("hours", 24))
        since = timezone.now() - timedelta(hours=hours)
        queryset = Event.objects.filter(started_at__gte=since)

        by_kind = list(
            queryset.values("kind").annotate(count=Count("id")).order_by("-count")
        )
        by_severity = list(
            queryset.values("severity").annotate(count=Count("id")).order_by("-count")
        )
        # 出事最多的对象排行 —— "哪条线最不稳"是复盘时的第一个问题
        by_target = list(
            queryset.filter(target__isnull=False)
            .values("target_id", "target__name", "target__host")
            .annotate(count=Count("id"))
            .order_by("-count")[:10]
        )
        by_device = list(
            queryset.filter(device__isnull=False)
            .values("device_id", "device__name", "device__mgmt_ip")
            .annotate(count=Count("id"))
            .order_by("-count")[:10]
        )

        resolved = queryset.filter(resolved_at__isnull=False)
        durations = list(resolved.values_list("duration_s", flat=True))
        return Response({
            "window_hours": hours,
            "total": queryset.count(),
            "open": queryset.filter(resolved_at__isnull=True).count(),
            "resolved": resolved.count(),
            "by_kind": [
                {"kind": r["kind"],
                 "label": EventKind(r["kind"]).label if r["kind"] in EventKind.values else r["kind"],
                 "count": r["count"]}
                for r in by_kind
            ],
            "by_severity": by_severity,
            "top_targets": by_target,
            "top_devices": by_device,
            "duration": {
                "total_s": sum(durations),
                "avg_s": round(sum(durations) / len(durations)) if durations else 0,
                "max_s": max(durations) if durations else 0,
            },
        })


class NotifierViewSet(viewsets.ModelViewSet):
    serializer_class = NotifierSerializer
    filterset_class = NotifierFilter
    search_fields = ["name"]

    def get_queryset(self):
        return Notifier.objects.prefetch_related("groups")

    @action(detail=True, methods=["post"])
    def test(self, request, pk=None):
        """发一条测试消息。不受过滤条件和静默窗口约束。"""
        from netcheck.notify.dispatch import verify_notifier

        notifier = self.get_object()
        ok, detail = verify_notifier(notifier)
        return Response({"ok": ok, "detail": detail})


class NotifyLogViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = NotifyLogSerializer
    filterset_fields = ["notifier", "event", "phase", "status"]
    ordering_fields = ["ts"]

    def get_queryset(self):
        return NotifyLog.objects.select_related("notifier", "event")


# =========================================================================
# 大屏聚合接口
# =========================================================================


@api_view(["GET"])
def dashboard_overview(request):
    """
    顶部那排统计。

    需求原话是"检测线路断线、丢包、异常、延迟、抖动等次数都要在最上面显示",
    所以这里给的是**按时间窗统计的事件次数**,不是当前状态数 —— "现在断了
    几条"和"这一天断了几次"是两个不同的数字,后者才是那句话要的东西。
    两个都给:count 是次数,open 是当前还没恢复的。
    """

    hours = float(request.query_params.get("hours", 24))
    since = timezone.now() - timedelta(hours=hours)

    events = Event.objects.filter(started_at__gte=since)
    open_events = Event.objects.filter(resolved_at__isnull=True)

    kind_counts = dict(events.values_list("kind").annotate(c=Count("id")))
    open_kind_counts = dict(open_events.values_list("kind").annotate(c=Count("id")))

    tiles = []
    for kind in TOP_KINDS:
        tiles.append({
            "kind": kind,
            "label": EventKind(kind).label,
            "count": kind_counts.get(kind, 0),
            "open": open_kind_counts.get(kind, 0),
        })

    targets = ProbeTarget.objects.filter(enabled=True)
    state_counts = dict(targets.values_list("state").annotate(c=Count("id")))
    devices = Device.objects.filter(enabled=True)
    device_state_counts = dict(devices.values_list("state").annotate(c=Count("id")))

    # 全局可用率:所有线路累计成功次数 / 累计检测次数。
    # 用累计值而不是时间窗内重算 —— 后者要扫样本表,那是这个接口最贵的部分,
    # 而这个数字本身是给人看趋势的,不需要精确到窗口。
    from django.db.models import Sum

    totals = targets.aggregate(checks=Sum("total_checks"), fails=Sum("total_fail"))
    checks, fails = totals["checks"] or 0, totals["fails"] or 0

    return Response({
        "window_hours": hours,
        "generated_at": timezone.now(),
        "tiles": tiles,
        "events": {
            "total": events.count(),
            "open": open_events.count(),
            "critical_open": open_events.filter(severity=Severity.CRITICAL).count(),
            "device_total": events.filter(source_type__in=[SourceType.DEVICE, SourceType.INTERFACE]).count(),
        },
        "probes": {
            "total": targets.count(),
            "up": state_counts.get(LinkState.UP, 0),
            "degraded": state_counts.get(LinkState.DEGRADED, 0),
            "down": state_counts.get(LinkState.DOWN, 0),
            "unknown": state_counts.get(LinkState.UNKNOWN, 0),
            "availability": round((checks - fails) / checks * 100, 3) if checks else None,
            "total_checks": checks,
        },
        "devices": {
            "total": devices.count(),
            "up": device_state_counts.get(LinkState.UP, 0),
            "degraded": device_state_counts.get(LinkState.DEGRADED, 0),
            "down": device_state_counts.get(LinkState.DOWN, 0),
            "switches": devices.filter(kind=DeviceKind.SWITCH).count(),
            "firewalls": devices.filter(kind=DeviceKind.FIREWALL).count(),
        },
        # 调度健康度:overdue 长期不为 0 说明 worker 数量不够,
        # 而那时候图上的点会变稀 —— 有这个数字才不会去怀疑线路
        "scheduler": _safe_scheduler_stats(),
    })


def _safe_scheduler_stats():
    """Redis 挂了不能让整个大屏白屏 —— 调度状态是附加信息。"""
    try:
        return scheduler.stats()
    except Exception as exc:  # noqa: BLE001
        log.warning("读取调度状态失败: %s", exc)
        return {"error": str(exc)[:120]}


@api_view(["GET"])
def dashboard_charts(request):
    """
    「一个监控类一个大图」的数据源。

    一次返回所有启用的监控类,每类带上它下面每条线路的时序 —— 这样大屏
    刷新只打一个请求。粒度按跨度自动选,和单条线路的 series 一致。

    **线路数上限**:每个监控类最多返回 12 条线路的曲线(按 state 排序,
    有问题的优先)。一张图上二十条线人也读不出来,而数据量是线性增长的。
    """

    minutes = float(request.query_params.get("minutes", 30))
    max_lines = min(int(request.query_params.get("max_lines", 12)), 30)
    since = timezone.now() - timedelta(minutes=minutes)
    hours = minutes / 60

    # 粒度选择和 ProbeTargetViewSet.series 保持一致
    use_raw = hours <= 2
    bucket = RollupBucket.M1 if hours <= 48 else (RollupBucket.M5 if hours <= 336 else RollupBucket.H1)

    groups = ProbeGroup.objects.filter(enabled=True).order_by("order", "id")
    payload = []

    for group in groups:
        targets = list(
            group.targets.filter(enabled=True)
            # 有问题的排前面:down > degraded > unknown > up
            .annotate(open_events=Count("events", filter=Q(events__resolved_at__isnull=True)))
            .order_by("-open_events", "order", "id")[:max_lines]
        )
        if not targets:
            continue

        target_ids = [t.pk for t in targets]
        series_by_target: dict[int, list] = {tid: [] for tid in target_ids}

        if use_raw:
            rows = (
                ProbeSample.objects.filter(target_id__in=target_ids, ts__gte=since)
                .order_by("ts")
                .values("target_id", "ts", "rtt_ms", "loss_pct", "jitter_ms", "ok")
            )
            for row in rows.iterator(chunk_size=2000):
                series_by_target[row["target_id"]].append({
                    "ts": row["ts"], "rtt": row["rtt_ms"],
                    "loss": row["loss_pct"], "jitter": row["jitter_ms"], "ok": row["ok"],
                })
        else:
            rows = (
                ProbeRollup.objects.filter(target_id__in=target_ids, bucket=bucket, ts__gte=since)
                .order_by("ts")
                .values("target_id", "ts", "rtt_avg_ms", "rtt_max_ms", "loss_avg_pct",
                        "jitter_avg_ms", "samples", "ok_count")
            )
            for row in rows.iterator(chunk_size=2000):
                series_by_target[row["target_id"]].append({
                    "ts": row["ts"], "rtt": row["rtt_avg_ms"], "rtt_max": row["rtt_max_ms"],
                    "loss": row["loss_avg_pct"], "jitter": row["jitter_avg_ms"],
                    "ok": row["ok_count"] == row["samples"],
                })

        payload.append({
            "group": {
                "id": group.pk, "name": group.name,
                "color": group.color, "description": group.description,
            },
            "granularity": "raw" if use_raw else bucket,
            "lines": [
                {
                    "id": t.pk, "name": t.name, "host": t.host,
                    "protocol": t.protocol, "port": t.port,
                    "state": t.state, "interval": t.interval_seconds,
                    "last_rtt": t.last_rtt_ms, "last_loss": t.last_loss_pct,
                    "last_jitter": t.last_jitter_ms, "last_error": t.last_error,
                    "availability": t.availability,
                    "open_events": t.open_events,
                    "thresholds": {
                        "latency_warn": t.latency_warn_ms, "latency_crit": t.latency_crit_ms,
                        "loss_warn": t.loss_warn_pct, "loss_crit": t.loss_crit_pct,
                        "jitter_warn": t.jitter_warn_ms, "jitter_crit": t.jitter_crit_ms,
                    },
                    "series": series_by_target[t.pk],
                }
                for t in targets
            ],
            # 这一类的汇总,画在大图标题旁边
            "summary": {
                "total": len(targets),
                "down": sum(1 for t in targets if t.state == LinkState.DOWN),
                "degraded": sum(1 for t in targets if t.state == LinkState.DEGRADED),
                "truncated": group.targets.filter(enabled=True).count() > len(targets),
            },
        })

    return Response({
        "window_minutes": minutes,
        "generated_at": timezone.now(),
        "groups": payload,
    })


@api_view(["GET"])
def dashboard_devices(request):
    """设备卡片。交换机和防火墙分开返回 —— 它们关心的指标不一样。"""

    hours = float(request.query_params.get("hours", 3))
    since = timezone.now() - timedelta(hours=hours)
    devices = list(
        Device.objects.filter(enabled=True)
        .annotate(open_events=Count("events", filter=Q(events__resolved_at__isnull=True)))
        .order_by("order", "id")
    )
    device_ids = [d.pk for d in devices]

    # 一次把所有设备的时序捞出来,不是每台一个查询
    trends: dict[int, list] = {d.pk: [] for d in devices}
    rows = (
        DeviceSample.objects.filter(device_id__in=device_ids, ts__gte=since)
        .order_by("ts")
        .values("device_id", "ts", "cpu_pct", "mem_pct", "temp_c", "session_count", "reachable")
    )
    for row in rows.iterator(chunk_size=2000):
        trends[row["device_id"]].append({
            "ts": row["ts"], "cpu": row["cpu_pct"], "mem": row["mem_pct"],
            "temp": row["temp_c"], "sessions": row["session_count"], "up": row["reachable"],
        })

    # 接口 Top:按当前速率排,只取有流量的 —— 大屏上要看的是"哪个口在跑"
    top_interfaces: dict[int, list] = {d.pk: [] for d in devices}
    iface_rows = (
        DeviceInterface.objects.filter(device_id__in=device_ids, oper_up=True)
        .exclude(in_bps=None, out_bps=None)
        .order_by("device_id", "-in_bps")
        .values("device_id", "if_name", "if_alias", "in_bps", "out_bps", "speed_bps",
                "in_err_delta", "out_err_delta")
    )
    for row in iface_rows:
        bucket_list = top_interfaces[row["device_id"]]
        if len(bucket_list) < 6:
            speed = row["speed_bps"] or 0
            bucket_list.append({
                "name": row["if_name"], "alias": row["if_alias"],
                "in_bps": row["in_bps"], "out_bps": row["out_bps"], "speed_bps": speed,
                "util_in": round((row["in_bps"] or 0) / speed * 100, 1) if speed else None,
                "util_out": round((row["out_bps"] or 0) / speed * 100, 1) if speed else None,
                "errors": (row["in_err_delta"] or 0) + (row["out_err_delta"] or 0),
            })

    from netcheck.devices.profiles import get_profile

    def card(device):
        latest = trends[device.pk][-1] if trends[device.pk] else {}
        profile = get_profile(device.model, device.vendor)
        return {
            "id": device.pk, "name": device.name, "kind": device.kind,
            "vendor": device.vendor, "model": device.model,
            "model_label": device.get_model_display(),
            "mgmt_ip": device.mgmt_ip, "site": device.site,
            "os_version": device.os_version, "serial": device.serial,
            "state": device.state, "method": device.last_method_used or device.collect_method,
            "last_collected_at": device.last_collected_at,
            "last_error": device.last_error,
            "open_events": device.open_events,
            "cpu": latest.get("cpu"), "mem": latest.get("mem"), "temp": latest.get("temp"),
            "sessions": latest.get("sessions"),
            "thresholds": {
                "cpu_warn": device.cpu_warn_pct, "cpu_crit": device.cpu_crit_pct,
                "mem_warn": device.mem_warn_pct, "mem_crit": device.mem_crit_pct,
                "temp_warn": device.temp_warn_c, "temp_crit": device.temp_crit_c,
                "session_warn": device.session_warn,
            },
            # 前端据此把缺失指标显示成 "—" 而不是"采集失败"
            "absent_metrics": sorted(profile.absent),
            "optional_metrics": sorted(profile.optional),
            "trend": trends[device.pk],
            "interfaces": top_interfaces[device.pk],
        }

    return Response({
        "window_hours": hours,
        "generated_at": timezone.now(),
        "switches": [card(d) for d in devices if d.kind == DeviceKind.SWITCH],
        "firewalls": [card(d) for d in devices if d.kind == DeviceKind.FIREWALL],
        "others": [card(d) for d in devices if d.kind not in (DeviceKind.SWITCH, DeviceKind.FIREWALL)],
    })


@api_view(["GET"])
def meta_choices(request):
    """
    所有枚举。**前端不许硬编码中文枚举标签** —— 那是两边漂移的起点。
    """

    def pack(choices_cls):
        return [{"value": v, "label": l} for v, l in choices_cls.choices]

    return Response({
        "protocol": pack(Protocol),
        "link_state": pack(LinkState),
        "severity": pack(Severity),
        "event_kind": pack(EventKind),
        "source_type": pack(SourceType),
        "device_kind": pack(DeviceKind),
        "vendor": pack(Vendor),
        "device_model": pack(DeviceModel),
        "collect_method": pack(CollectMethod),
        "snmp_version": pack(SnmpVersion),
        "snmp_sec_level": pack(SnmpSecLevel),
        "notifier_kind": pack(NotifierKind),
        "rollup_bucket": pack(RollupBucket),
        "notify_status": pack(NotifyLog.Status),
        # 顶部统计的顺序,前端照这个渲染
        "top_kinds": [
            {"value": k, "label": EventKind(k).label} for k in TOP_KINDS
        ],
    })


@api_view(["GET"])
@permission_classes([AllowAny])
def health(request):
    """
    健康检查。**它要能在数据库正常但采集停了的时候报出来** ——
    "接口 200 但图不更新"是最难被发现的故障。

    **这是全站唯一始终放开的接口**,因为容器的 healthcheck 打的就是它
    (见 docker-compose.yml 的 backend.healthcheck),而 worker/beat 依赖
    backend 起来才启动。给它加权限的症状是"整个栈起不来",且看不出和权限有关。

    代价是未登录也能看到这里的内容,所以**明细分级**:未登录只给数量,
    线路名字和调度器内部状态要登录后才返回 —— 前者是网络拓扑,
    不该在登录页上就能读到。
    """

    now = timezone.now()
    enabled = ProbeTarget.objects.filter(enabled=True)
    stale = [
        {"id": t.pk, "name": t.name, "last": t.last_checked_at,
         "interval": t.interval_seconds}
        for t in enabled.exclude(last_checked_at=None)
        if (now - t.last_checked_at).total_seconds() > t.interval_seconds * 10
    ][:20]
    never_run = enabled.filter(last_checked_at=None).count()

    payload = {
        "status": "degraded" if (stale or never_run) else "ok",
        "time": now,
        "probes_enabled": enabled.count(),
        "probes_never_run": never_run,
        # 计数始终给 —— 顶栏那个指示灯在登录页上也要能亮
        "probes_stale_count": len(stale),
    }
    if request.user.is_authenticated:
        payload["probes_stale"] = stale
        payload["scheduler"] = _safe_scheduler_stats()
    return Response(payload)
