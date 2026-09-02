"""
API 视图。

除了标准 CRUD,这里有三组"给大屏用"的聚合接口 —— 它们是这个文件的重点,
因为**大屏的性能全取决于这几个接口**:

    /api/dashboard/overview/    顶部那排统计(断线/丢包/延迟/抖动/异常 次数)
    /api/dashboard/charts/      按监控类分组的图表数据,一个监控类一块
    /api/dashboard/devices/     设备卡片(交换机/防火墙)
    /api/dashboard/servers/     服务器卡片(基本信息 + 流量趋势)

原则:**大屏的一次刷新只打这三个接口**(服务器页面单独一个),
不是每条线路一个请求。几十条线路 × 每 5 秒刷新,后者会把 gunicorn 打满。
"""

from __future__ import annotations

import logging
import re
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
    DeviceBackupFilter,
    DeviceFilter,
    DeviceInterfaceFilter,
    EventFilter,
    FirewallPolicyFilter,
    NotifierFilter,
    ProbeTargetFilter,
    ServerFilter,
)
from netcheck.models import (
    BackupStatus,
    CollectMethod,
    Device,
    DeviceBackup,
    DeviceInterface,
    DeviceKind,
    DeviceModel,
    DeviceSample,
    Event,
    EventKind,
    FirewallPolicy,
    InterfaceSample,
    LinkState,
    Notifier,
    NotifierKind,
    NotifyLog,
    PolicyAction,
    ProbeGroup,
    ProbeRollup,
    ProbeSample,
    ProbeTarget,
    Protocol,
    RollupBucket,
    Server,
    ServerSample,
    Severity,
    SnmpSecLevel,
    SnmpVersion,
    SourceType,
    Vendor,
)
from netcheck.serializers import (
    DeviceBackupDetailSerializer,
    DeviceBackupSerializer,
    DeviceInterfaceSerializer,
    DeviceSampleSerializer,
    DeviceSerializer,
    EventSerializer,
    FirewallPolicyDetailSerializer,
    FirewallPolicySerializer,
    InterfaceSampleSerializer,
    NotifierSerializer,
    NotifyLogSerializer,
    ProbeGroupSerializer,
    ProbeRollupSerializer,
    ProbeSampleSerializer,
    ProbeTargetSerializer,
    ServerInterfaceSerializer,
    ServerSampleSerializer,
    ServerSerializer,
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
                # 前端据此决定「启用配置备份」这个开关要不要禁掉:
                # 画像里没有备份命令的型号,开了也备不了
                "backup_cli": p.backup_cli,
                "policy_cli": p.policy_cli,
                "supports_backup": bool(p.backup_cli),
                "supports_policy": bool(p.policy_cli),
                "notes": p.notes,
            }
            for p in PROFILES.values()
        ])

    # ---- 配置备份 ----

    @action(detail=True, methods=["post"])
    def test_backup(self, request, pk=None):
        """
        测备份通道:取一份配置回来看看,**但不存成版本**。

        存起来的话每点一次测试就多一个版本,而版本数有上限 ——
        连点五次就把真实的变更历史挤掉五个。
        """

        from netcheck.devices import backup as backup_mod

        device = self.get_object()
        try:
            ok, detail = backup_mod.test_backup(device)
        except Exception as exc:  # noqa: BLE001
            log.exception("设备 %s 备份通道测试异常", device.name)
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        return Response({"ok": ok, "detail": detail})

    @action(detail=True, methods=["post"])
    def backup_now(self, request, pk=None):
        """
        立刻备份一次(走正式流程:存版本、判变更、记事件)。

        排进到期表而不是同步执行:一份 running-config 走 SSH 要几十秒,
        而 HTTP 请求撑不了那么久 —— 同步做的话页面上会看到一个超时,
        而备份其实成功了。
        """

        device = self.get_object()
        if not device.enabled:
            return Response({"detail": "设备已停用"}, status=status.HTTP_400_BAD_REQUEST)
        if not device.backup_enabled:
            return Response(
                {"detail": "这台设备没有开启配置备份 —— 先在配置里打开"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        scheduler.schedule_now("backup", device.pk)
        return Response({"detail": "已排入备份队列,一份大配置可能要一两分钟"})

    @action(detail=True, methods=["get"])
    def backups(self, request, pk=None):
        """这台设备的版本列表(不带全文)。"""

        device = self.get_object()
        versions = device.backups.order_by("-ts")[:200]
        return Response({
            "device": device.name,
            "enabled": device.backup_enabled,
            "interval_hours": device.backup_interval_hours,
            "keep": device.backup_keep,
            "last_backup_at": device.last_backup_at,
            "last_backup_status": device.last_backup_status,
            "last_backup_error": device.last_backup_error,
            "versions": DeviceBackupSerializer(versions, many=True).data,
        })

    # ---- 防火墙策略 ----

    @action(detail=True, methods=["post"])
    def sync_policies_now(self, request, pk=None):
        device = self.get_object()
        if device.kind != DeviceKind.FIREWALL:
            return Response(
                {"detail": "策略同步只对防火墙有意义"}, status=status.HTTP_400_BAD_REQUEST
            )
        if not device.policy_sync_enabled:
            return Response(
                {"detail": "这台设备没有开启策略同步 —— 先在配置里打开"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        scheduler.schedule_now("policy", device.pk)
        return Response({"detail": "已排入同步队列"})


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


class ServerViewSet(viewsets.ModelViewSet):
    """
    服务器 CRUD + 测试 / 立即采集 / 时序 / 网卡。

    和 DeviceViewSet 的形状一样,区别是**没有通道概念** —— 服务器只走 SSH。
    """

    serializer_class = ServerSerializer
    filterset_class = ServerFilter
    search_fields = ["name", "host", "hostname", "os_name"]
    ordering_fields = ["name", "state", "last_collected_at", "order"]

    def get_queryset(self):
        # order_by 要**显式写**:annotate 之后 Meta.ordering 不一定还在,
        # 而分页接口拿到一个无序 queryset 会让第 2 页和第 1 页出现重复行
        # (DRF 会为此打 UnorderedObjectListWarning)
        return (
            Server.objects.prefetch_related("interfaces")
            .annotate(
                interface_count_ann=Count("interfaces", distinct=True),
                open_event_count_ann=Count(
                    "events", filter=Q(events__resolved_at__isnull=True), distinct=True
                ),
            )
            .order_by("order", "id")
        )

    def perform_create(self, serializer):
        server = serializer.save()
        if server.enabled:
            scheduler.schedule_now("server", server.pk)

    def perform_update(self, serializer):
        server = serializer.save()
        if server.enabled:
            scheduler.schedule_now("server", server.pk)
        else:
            scheduler.unschedule("server", server.pk)
            from netcheck.events.engine import force_resolve

            for event in server.events.filter(resolved_at__isnull=True):
                force_resolve(event, "服务器已停用")

    def perform_destroy(self, instance):
        scheduler.unschedule("server", instance.pk)
        instance.delete()

    @action(detail=True, methods=["post"])
    def test(self, request, pk=None):
        """连上去读一遍基本信息。**不写库、不开事件。**"""

        from netcheck.servers import collector

        server = self.get_object()
        try:
            ok, detail = collector.test_connection(server)
        except Exception as exc:  # noqa: BLE001
            log.exception("服务器 %s 测试异常", server.name)
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        return Response({"ok": ok, "detail": detail})

    @action(detail=True, methods=["post"])
    def collect_now(self, request, pk=None):
        server = self.get_object()
        if not server.enabled:
            return Response({"detail": "服务器已停用"}, status=status.HTTP_400_BAD_REQUEST)
        scheduler.schedule_now("server", server.pk)
        return Response({"detail": "已排入下一拍"})

    @action(detail=True, methods=["get"])
    def series(self, request, pk=None):
        """
        指标时序。**和设备一样不做降采样** —— 最快 15 秒一拍,
        一天最多 5760 行。所以能看的跨度受原始样本保留期约束(默认 48 小时),
        要看更久得先在「系统信息」里把保留期调大。
        """

        server = self.get_object()
        hours = min(float(request.query_params.get("hours", 6)), 720)
        since = timezone.now() - timedelta(hours=hours)
        rows = list(
            server.samples.filter(ts__gte=since).order_by("ts")
            .values("ts", "reachable", "cpu_pct", "cpu_iowait_pct", "mem_pct", "swap_pct",
                    "disk_pct", "load1", "load5", "load15",
                    "net_in_bps", "net_out_bps", "tcp_established", "process_count")[:5000]
        )
        return Response({
            "points": len(rows), "interval": server.interval_seconds, "series": rows,
        })

    @action(detail=True, methods=["get"])
    def interfaces(self, request, pk=None):
        server = self.get_object()
        queryset = server.interfaces.all()
        if request.query_params.get("physical") == "true":
            # 只看物理口。主网卡即使名字像虚拟口(br0 这种)也要留下 ——
            # 它是这台机器真正的对外出口
            queryset = queryset.filter(Q(is_virtual=False) | Q(is_primary=True))
        return Response(ServerInterfaceSerializer(queryset, many=True).data)

    @action(detail=True, methods=["get"])
    def detail_info(self, request, pk=None):
        """
        「基本信息」面板的数据源:最近一条样本里的挂载点明细、进程 Top、网卡。

        单独一个接口是因为这些东西**只看最新一条就够**,不需要时序 ——
        塞进 series 会让每个点都带上一份挂载点数组,响应大十几倍。
        """

        server = self.get_object()
        latest = server.samples.order_by("-ts").first()
        extra = (latest.extra if latest else {}) or {}
        return Response({
            "server": ServerSerializer(server).data,
            "ts": latest.ts if latest else None,
            "reachable": latest.reachable if latest else None,
            "uptime_s": latest.uptime_s if latest else None,
            "mounts": extra.get("mounts") or [],
            "top_processes": extra.get("top_processes") or [],
            "primary_interface": extra.get("primary_interface") or "",
            "interfaces": ServerInterfaceSerializer(server.interfaces.all(), many=True).data,
            "current": {
                "cpu": latest.cpu_pct if latest else None,
                "iowait": latest.cpu_iowait_pct if latest else None,
                "mem": latest.mem_pct if latest else None,
                "swap": latest.swap_pct if latest else None,
                "disk": latest.disk_pct if latest else None,
                "load1": latest.load1 if latest else None,
                "load5": latest.load5 if latest else None,
                "load15": latest.load15 if latest else None,
                "net_in_bps": latest.net_in_bps if latest else None,
                "net_out_bps": latest.net_out_bps if latest else None,
                "tcp_established": latest.tcp_established if latest else None,
                "process_count": latest.process_count if latest else None,
            },
            # 采集失败或指标算不出来的原因,页面上要能直接看到,
            # 不然"CPU 是 —"这件事只能靠猜
            "error": latest.error if latest else "",
            "cpu_pending": extra.get("cpu_pending", ""),
            "notes": [
                v for v in (extra.get("interface_error"), extra.get("stderr")) if v
            ],
        })


class DeviceBackupViewSet(viewsets.ReadOnlyModelViewSet):
    """
    配置版本只读 —— 它是备份产物。写入只有一条路:定时任务或「立即备份」。

    列表**不返回全文**(见 DeviceBackupSerializer),要全文用 retrieve、
    要文件用 download、要看改了什么用 diff。
    """

    filterset_class = DeviceBackupFilter
    ordering_fields = ["ts", "size_bytes", "line_count"]

    def get_queryset(self):
        return DeviceBackup.objects.select_related("device")

    def get_serializer_class(self):
        # 列表用不带 content 的,单条用带 content 的
        if self.action == "retrieve":
            return DeviceBackupDetailSerializer
        return DeviceBackupSerializer

    @action(detail=True, methods=["get"])
    def download(self, request, pk=None):
        """
        原样下载。**给的是原始文本,不是清洗后的** ——
        清洗只用于比对,下载下来的东西要能直接回灌到设备上。
        """

        from django.http import HttpResponse

        version = self.get_object()
        # 文件名里只留安全字符:设备名可能带中文、空格、斜杠,
        # 而带斜杠的 filename 在某些浏览器上会被当成路径
        safe_name = re.sub(r"[^\w.\-]", "_", version.device.name)[:48]
        filename = f"{safe_name}-{timezone.localtime(version.ts):%Y%m%d-%H%M%S}-{version.short_hash}.cfg"
        response = HttpResponse(version.content, content_type="text/plain; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    @action(detail=True, methods=["get"])
    def diff(self, request, pk=None):
        """
        和另一个版本的差异。`against` 留空则和**这台设备上更早的那一个版本**比。

        比对的是清洗后的文本(见 devices/backup.py 的 sanitize):
        比原始文本的话每次 diff 的头几行都是时间戳,人要在噪声里找真改动。
        """

        from netcheck.devices import backup as backup_mod

        version = self.get_object()
        against_id = request.query_params.get("against")
        if against_id:
            older = DeviceBackup.objects.filter(
                pk=against_id, device_id=version.device_id
            ).first()
            if older is None:
                return Response(
                    {"detail": "对比版本不存在,或不属于同一台设备"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            # "上一个版本"按 (ts, id) 比,不只按 ts:同一秒里有两个版本时,
            # 只比 ts 会一个都找不到(ts__lt 排除了同一秒的那个),
            # 于是页面上显示"这是最早的版本"——而它明明不是
            older = (
                DeviceBackup.objects.filter(device_id=version.device_id)
                .filter(Q(ts__lt=version.ts) | Q(ts=version.ts, pk__lt=version.pk))
                .order_by("-ts", "-pk").first()
            )
        if older is None:
            return Response({
                "detail": "这是最早的一个版本,没有可比的上一版",
                "lines": [], "from": None, "to": version.pk,
            })

        lines = backup_mod.unified_diff(older, version)
        return Response({
            "from": older.pk, "to": version.pk,
            "from_ts": older.ts, "to_ts": version.ts,
            "lines_added": version.lines_added, "lines_removed": version.lines_removed,
            "lines": lines,
        })


class FirewallPolicyViewSet(viewsets.ReadOnlyModelViewSet):
    """
    防火墙策略只读快照。写入只有一条路:同步任务。

    **默认按设备 + 策略顺序排**,不按命中数 —— 防火墙是先匹配先生效的,
    顺序本身是语义。要按命中数排就显式传 ordering=-hit_count。
    """

    filterset_class = FirewallPolicyFilter
    search_fields = ["name", "comments"]
    ordering_fields = ["seq", "policy_id", "hit_count", "bytes_count", "sessions", "last_hit_at"]

    def get_queryset(self):
        return FirewallPolicy.objects.select_related("device")

    def get_serializer_class(self):
        if self.action == "retrieve":
            return FirewallPolicyDetailSerializer
        return FirewallPolicySerializer

    @action(detail=False, methods=["get"])
    def summary(self, request):
        """
        策略页顶部那几块数字:按设备一行。

        `has_hit_stats` 是这里最重要的一个字段:**它决定"从未命中"那一列
        能不能被当成结论**。SSH 通道同步来的策略没有命中计数,
        那时候页面上必须说"这批数据没有命中统计",而不是显示一片 0。
        """

        devices = list(
            Device.objects.filter(kind=DeviceKind.FIREWALL, policy_sync_enabled=True)
            .order_by("order", "id")
        )
        # 一次聚合出所有设备的分布,不是每台一个查询
        rows = (
            FirewallPolicy.objects.filter(device__in=devices)
            .values("device_id", "action", "enabled")
            .annotate(count=Count("id"))
        )
        stats: dict[int, dict] = {}
        for row in rows:
            bucket = stats.setdefault(row["device_id"], {"total": 0, "accept": 0, "deny": 0, "disabled": 0})
            bucket["total"] += row["count"]
            if row["action"] == PolicyAction.ACCEPT:
                bucket["accept"] += row["count"]
            elif row["action"] == PolicyAction.DENY:
                bucket["deny"] += row["count"]
            if not row["enabled"]:
                bucket["disabled"] += row["count"]

        hit_rows = (
            FirewallPolicy.objects.filter(device__in=devices)
            .values("device_id")
            .annotate(
                with_stats=Count("id", filter=Q(hit_count__isnull=False)),
                never=Count("id", filter=Q(hit_count=0)),
            )
        )
        hits = {r["device_id"]: r for r in hit_rows}

        payload = []
        for device in devices:
            bucket = stats.get(device.pk, {"total": 0, "accept": 0, "deny": 0, "disabled": 0})
            hit = hits.get(device.pk, {"with_stats": 0, "never": 0})
            payload.append({
                "device_id": device.pk,
                "device_name": device.name,
                "mgmt_ip": device.mgmt_ip,
                "vdom": device.api_vdom or "root",
                "state": device.state,
                "synced_at": device.last_policy_sync_at,
                "error": device.last_policy_error,
                "interval_minutes": device.policy_sync_interval_minutes,
                **bucket,
                "has_hit_stats": hit["with_stats"] > 0,
                # 没有命中统计时**给 None 而不是 0** —— 0 会被读成
                # "所有规则都命中过",而真相是我们不知道
                "never_hit": hit["never"] if hit["with_stats"] else None,
            })
        return Response({"generated_at": timezone.now(), "devices": payload})


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
            "target", "target__group", "device", "interface", "interface__device", "server"
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
        by_server = list(
            queryset.filter(server__isnull=False)
            .values("server_id", "server__name", "server__host")
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
            "top_servers": by_server,
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
    servers = Server.objects.filter(enabled=True)
    server_state_counts = dict(servers.values_list("state").annotate(c=Count("id")))

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
            "server_total": events.filter(source_type=SourceType.SERVER).count(),
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
        "servers": {
            "total": servers.count(),
            "up": server_state_counts.get(LinkState.UP, 0),
            "degraded": server_state_counts.get(LinkState.DEGRADED, 0),
            "down": server_state_counts.get(LinkState.DOWN, 0),
            "unknown": server_state_counts.get(LinkState.UNKNOWN, 0),
        },
        # 备份的健康度放在顶部统计里:**一个悄悄坏掉的备份等于没有备份**,
        # 而这件事不会有任何症状 —— 只有主动把它显示出来才有人看见
        "backup": {
            "enabled": Device.objects.filter(enabled=True, backup_enabled=True).count(),
            "failed": Device.objects.filter(
                enabled=True, backup_enabled=True, last_backup_status=BackupStatus.FAILED
            ).count(),
            "never": Device.objects.filter(
                enabled=True, backup_enabled=True, last_backup_status=BackupStatus.NEVER
            ).count(),
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
def dashboard_servers(request):
    """
    服务器卡片:基本信息 + 流量/负载趋势,一次全给。

    和 dashboard_devices 同一条原则:**一次请求带回所有服务器的时序**,
    不是每台一个请求。几十台 × 每 30 秒会把 gunicorn 打满。

    趋势里带的是画图要的四条线(CPU / 内存 / 入向 / 出向),
    挂载点明细和进程 Top **不在这里** —— 它们只在展开某一台时才需要,
    每台每个点都带一份的话响应会大十几倍(走 /servers/{id}/detail_info/)。
    """

    hours = min(float(request.query_params.get("hours", 3)), 168)
    since = timezone.now() - timedelta(hours=hours)
    servers = list(
        Server.objects.filter(enabled=True)
        .prefetch_related("interfaces")
        .annotate(open_events=Count("events", filter=Q(events__resolved_at__isnull=True)))
        .order_by("order", "id")
    )
    server_ids = [srv.pk for srv in servers]

    trends: dict[int, list] = {srv.pk: [] for srv in servers}
    rows = (
        ServerSample.objects.filter(server_id__in=server_ids, ts__gte=since)
        .order_by("ts")
        .values("server_id", "ts", "cpu_pct", "mem_pct", "disk_pct", "load1",
                "net_in_bps", "net_out_bps", "reachable")
    )
    for row in rows.iterator(chunk_size=2000):
        trends[row["server_id"]].append({
            "ts": row["ts"], "cpu": row["cpu_pct"], "mem": row["mem_pct"],
            "disk": row["disk_pct"], "load1": row["load1"],
            "net_in": row["net_in_bps"], "net_out": row["net_out_bps"],
            "up": row["reachable"],
        })

    def card(server):
        latest = trends[server.pk][-1] if trends[server.pk] else {}
        primary = next((i for i in server.interfaces.all() if i.is_primary), None)
        return {
            "id": server.pk, "name": server.name, "host": server.host,
            "hostname": server.hostname, "site": server.site, "role": server.role,
            "os_name": server.os_name, "kernel": server.kernel,
            "cpu_cores": server.cpu_cores, "mem_total_bytes": server.mem_total_bytes,
            "state": server.state,
            "interval": server.interval_seconds,
            "last_collected_at": server.last_collected_at,
            "last_error": server.last_error,
            "open_events": server.open_events,
            "cpu": latest.get("cpu"), "mem": latest.get("mem"),
            "disk": latest.get("disk"), "load1": latest.get("load1"),
            "net_in_bps": latest.get("net_in"), "net_out_bps": latest.get("net_out"),
            "primary_interface": primary.if_name if primary else "",
            "thresholds": {
                "cpu_warn": server.cpu_warn_pct, "cpu_crit": server.cpu_crit_pct,
                "mem_warn": server.mem_warn_pct, "mem_crit": server.mem_crit_pct,
                "disk_warn": server.disk_warn_pct, "disk_crit": server.disk_crit_pct,
                "load_warn": server.load_warn, "load_crit": server.load_crit,
            },
            # 每核负载 —— 绝对值没有可比性,64 核的 load 8 很闲。
            # 前端不自己算是为了和阈值判定用同一个口径(见 servers/collector.py)
            "load_per_core": (
                round(latest["load1"] / server.cpu_cores, 2)
                if latest.get("load1") is not None and server.cpu_cores else None
            ),
            "trend": trends[server.pk],
        }

    cards = [card(srv) for srv in servers]
    return Response({
        "window_hours": hours,
        "generated_at": timezone.now(),
        "total": len(cards),
        "up": sum(1 for c in cards if c["state"] == LinkState.UP),
        "degraded": sum(1 for c in cards if c["state"] == LinkState.DEGRADED),
        "down": sum(1 for c in cards if c["state"] == LinkState.DOWN),
        "servers": cards,
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
        "backup_status": pack(BackupStatus),
        "policy_action": pack(PolicyAction),
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

    # 服务器采集也可能悄悄停掉,判定口径和线路一致(超过 10 个周期没数据)。
    # **这里只给计数,名字要登录后才给** —— 服务器名和主机名同样是拓扑信息,
    # 不该在登录页上就能读到
    servers_enabled = Server.objects.filter(enabled=True)
    servers_stale = [
        {"id": srv.pk, "name": srv.name, "last": srv.last_collected_at,
         "interval": srv.interval_seconds}
        for srv in servers_enabled.exclude(last_collected_at=None)
        if (now - srv.last_collected_at).total_seconds() > srv.interval_seconds * 10
    ][:20]

    payload = {
        "status": "degraded" if (stale or never_run or servers_stale) else "ok",
        "time": now,
        "probes_enabled": enabled.count(),
        "probes_never_run": never_run,
        # 计数始终给 —— 顶栏那个指示灯在登录页上也要能亮
        "probes_stale_count": len(stale),
        "servers_enabled": servers_enabled.count(),
        "servers_stale_count": len(servers_stale),
    }
    if request.user.is_authenticated:
        payload["probes_stale"] = stale
        payload["servers_stale"] = servers_stale
        payload["scheduler"] = _safe_scheduler_stats()
    return Response(payload)
