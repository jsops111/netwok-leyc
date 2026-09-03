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
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from core.pagination import SampleCursorPagination
from netcheck import scheduler
from netcheck import duplicate as duplicate_mod
from netcheck.devices import addresses as addresses_mod
from netcheck.filters import (
    DeviceBackupFilter,
    DeviceFilter,
    DeviceInterfaceFilter,
    DeviceNeighborFilter,
    EventFilter,
    FirewallPolicyFilter,
    FirewallAddressFilter,
    FirewallServiceFilter,
    FirewallVipFilter,
    IdracHostFilter,
    NotifierFilter,
    ProbeTargetFilter,
    ServerFilter,
)
from netcheck.models import (
    AddressType,
    BackupStatus,
    CollectMethod,
    Device,
    DeviceBackup,
    DeviceInterface,
    DeviceKind,
    DeviceModel,
    DeviceNeighbor,
    DeviceSample,
    Event,
    EventKind,
    FirewallPolicy,
    FirewallAddress,
    FirewallService,
    FirewallVip,
    HwState,
    IdracHost,
    IdracSample,
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
    ServerOS,
    ServerSample,
    Severity,
    SnmpSecLevel,
    SnmpVersion,
    SourceType,
    Vendor,
    VipType,
)
from netcheck.serializers import (
    DeviceBackupDetailSerializer,
    DeviceBackupSerializer,
    DeviceInterfaceSerializer,
    DeviceNeighborSerializer,
    DeviceSampleSerializer,
    DeviceSerializer,
    EventSerializer,
    FirewallPolicyDetailSerializer,
    FirewallPolicySerializer,
    FirewallAddressSerializer,
    FirewallServiceSerializer,
    FirewallVipSerializer,
    IdracHostSerializer,
    IdracSampleSerializer,
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


class DuplicateMixin:
    """
    给 ViewSet 加一个 `POST {id}/duplicate/`。

    **复制在后端做**,因为凭据是 `write_only`、前端拿不到 —— 前端拼出来的
    副本必然是一台没有密码的机器(见 `netcheck/duplicate.py` 的模块说明)。

    两种结果:

    - **201** —— 直接建好了。`ProbeGroup` / `Device` / `Notifier` 只有名字
      唯一,改个名就能存,所以点一下就完事。
    - **400 + `needs`** —— 有端点唯一约束的那三类(线路 / 服务器 / 带外),
      原样复制建不出来。这时回**必须改的那几个字段**,前端只弹那几个框,
      而不是让人对着一个四十项的完整表单从头改。

    `duplicate_needs` 就是那几个字段。**留空表示这一类可以直接建** ——
    不要为了"保险"给所有类型都填上,那样每次复制都要多点一次。
    """

    #: 端点唯一约束涉及的字段。空 = 直接建
    duplicate_needs: list[str] = []

    @action(detail=True, methods=["post"])
    def duplicate(self, request, pk=None):
        source = self.get_object()
        overrides = {
            k: v for k, v in (request.data or {}).items()
            if k in self.duplicate_needs
        }

        # 需要改地址但没给 —— **先问,不要试着存一次让它撞约束**:
        # 撞出来的 IntegrityError 会把整个事务标记成脏的,而且报错文本
        # 是数据库的约束名,指不到任何一个输入框
        missing = [f for f in self.duplicate_needs if not overrides.get(f)]
        if missing:
            return Response(
                {
                    "needs": self.duplicate_needs,
                    "missing": missing,
                    "detail": (
                        "这一类有端点唯一约束(同一个地址只能加一台,"
                        "否则同一台机器会被采两遍)—— 填一个新的再复制。"
                        "**凭据和其它配置都会一起复制过去**,不用重填。"
                    ),
                    "source": {
                        f: getattr(source, f, None) for f in self.duplicate_needs
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            copy = duplicate_mod.duplicate(source, overrides)
        except DjangoValidationError as exc:
            # 模型 clean() 的报错。**按字段回**,让前端标到输入框上
            return Response(
                exc.message_dict if hasattr(exc, "message_dict")
                else {"detail": "; ".join(exc.messages)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except IntegrityError as exc:
            return Response(
                {"detail": f"复制没能存下来(撞了唯一约束):{exc}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 新建的目标要立刻排进调度,否则要等下一次 sync_schedule 才开始采
        self._schedule_copy(copy)
        return Response(
            self.get_serializer(copy).data, status=status.HTTP_201_CREATED
        )

    def _schedule_copy(self, copy) -> None:
        """子类按需覆盖 —— 有的类型(监控类、通知渠道)不进调度。"""


class ProbeGroupViewSet(DuplicateMixin, viewsets.ModelViewSet):
    serializer_class = ProbeGroupSerializer
    filterset_fields = ["enabled"]
    search_fields = ["name", "description"]

    def get_queryset(self):
        return ProbeGroup.objects.annotate(target_count_ann=Count("targets"))


class ProbeTargetViewSet(DuplicateMixin, viewsets.ModelViewSet):

    # 唯一键是 (监控类, 地址, 协议, 端口)。**只问地址** —— 改端口或换监控类
    # 同样能解开约束,但人复制一条线路十有八九是要探另一台机器,
    # 问最常改的那一个就够,其余在「编辑」里改
    duplicate_needs = ["host"]

    def _schedule_copy(self, copy):
        if copy.enabled:
            scheduler.schedule_now("probe", copy.pk)
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


class DeviceViewSet(DuplicateMixin, viewsets.ModelViewSet):

    # **不问地址。**Device 没有端点唯一约束(多 VDOM 的 FortiGate 就是
    # 同一个管理地址配好几条),所以复制直接就能建出来。代价是不改地址
    # 的话同一台设备会被采两遍 —— 那句提醒放在前端的成功提示里,
    # 不是拦在这里:拦住会打断多 VDOM 这个合法用法
    duplicate_needs: list[str] = []

    def _schedule_copy(self, copy):
        if copy.enabled:
            scheduler.schedule_now("device", copy.pk)
    serializer_class = DeviceSerializer
    filterset_class = DeviceFilter
    search_fields = ["name", "mgmt_ip", "serial", "os_version"]
    ordering_fields = ["name", "kind", "state", "last_collected_at", "order"]

    def get_queryset(self):
        return Device.objects.annotate(interface_count_ann=Count("interfaces"))

    @action(detail=True, methods=["get"])
    def faceplate(self, request, pk=None):
        """
        端口面板图。**接口的数量和名字来自设备,几何来自型号画像。**

        每个口带的是**和 `/interfaces` 那一页完全同一份字段**(同一个
        序列化器)—— 点一个口弹出来的信息必须和那张表对得上,否则同一个口
        在两个地方显示不同的速率,而看不出哪个是对的。

        ⚠ **画错的面板比没有面板危险**:有人会照着它去机房拔线,而拔错的是
        别人的。所以返回里带着 `schematic` / `verified` / `note` ——
        页面上必须原样把那句话显示出来,让人自己决定信到什么程度。
        """

        from netcheck.devices import faceplate as faceplate_mod
        from netcheck.devices.profiles import get_profile

        device = self.get_object()
        interfaces = list(
            device.interfaces.all().order_by("if_index")
        )
        rows = DeviceInterfaceSerializer(interfaces, many=True).data
        profile = get_profile(device.model, device.vendor)
        layout = faceplate_mod.build([dict(r) for r in rows], profile)

        return Response({
            "device": {
                "id": device.pk, "name": device.name, "mgmt_ip": device.mgmt_ip,
                "model": device.model, "model_label": device.get_model_display(),
                "vendor": device.vendor, "kind": device.kind,
                "state": device.state,
                "last_collected_at": device.last_collected_at,
            },
            **layout,
            "counts": faceplate_mod.summarize(layout["banks"]),
        })

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

    # ---- 配置合规基线 ----

    @action(detail=False, methods=["get"])
    def compliance(self, request):
        """
        基线检查 —— 在**已经备份下来的配置**上跑,不需要新采集。

        比对告诉你"变了什么",基线告诉你"缺了什么"。后者更容易被忽略:
        telnet 一直开着、community 还是 public、日志没往外送 ——
        这些东西没有任何症状,直到出事或者审计。

        **没有规则的厂商 / 没有备份的设备明确回 `checked=false` 和原因**,
        不给一个 0 条问题的"全部通过"(见 compliance.py 的第 2 条自律)。
        """

        from netcheck.devices import compliance as comp

        device_id = request.query_params.get("device")
        devices = Device.objects.filter(enabled=True).order_by("order", "id")
        if device_id:
            devices = devices.filter(pk=device_id)

        results = [comp.check_device(d) for d in devices]
        checked = [r for r in results if r["checked"]]
        return Response({
            "generated_at": timezone.now(),
            "rule_total": len(comp.RULES),
            "supported_vendors": sorted(comp.SUPPORTED_VENDORS),
            "devices": results,
            "totals": {
                "devices": len(results),
                "checked": len(checked),
                "not_checked": len(results) - len(checked),
                "critical": sum(r["critical"] for r in checked),
                "warning": sum(r["warning"] for r in checked),
                "info": sum(r["info"] for r in checked),
                "clean": sum(1 for r in checked if not r["findings"]),
            },
        })

    # ---- MAC / IP 查找 ----

    @action(detail=False, methods=["post"])
    def lookup(self, request):
        """
        **「这个 MAC / 这个 IP 在哪台交换机的哪个口上」** —— 交换机排障
        问得最多的一句话。

        这是**同步现场查询**,不是查本地缓存:MAC 表大而易变,存下来的
        是一份过期的表,而排障时要的恰恰是"现在在哪儿"。所以要显式选设备,
        一台 1~5 秒。

        IP 是两段式:先在选中的设备里找 ARP 拿到 MAC(只有三层设备有),
        再拿 MAC 去找口。
        """

        from netcheck.devices import lookup as lookup_mod

        query = (request.data.get("query") or "").strip()
        ids = request.data.get("devices") or []
        if not isinstance(ids, list):
            return Response({"detail": "devices 要是一个 id 数组"},
                            status=status.HTTP_400_BAD_REQUEST)
        devices = list(Device.objects.filter(pk__in=ids, enabled=True))
        try:
            result = lookup_mod.lookup(query, devices)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exc:  # noqa: BLE001
            log.exception("MAC/IP 查找异常")
            return Response({"detail": f"{type(exc).__name__}: {exc}"},
                            status=status.HTTP_200_OK)
        return Response(result)

    # ---- 邻居 ----

    @action(detail=True, methods=["post"])
    def discover_neighbors(self, request, pk=None):
        """
        立刻采一次邻居。**同步执行** —— 两张表几十行,一两秒就回来,
        排障时等不了一个采集周期。
        """

        from netcheck.devices import neighbors as neighbor_mod

        device = self.get_object()
        if not device.collect_neighbors:
            return Response({"detail": "这台设备关掉了邻居采集"},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            result = neighbor_mod.collect_neighbors(device)
        except Exception as exc:  # noqa: BLE001
            log.exception("设备 %s 邻居采集异常", device.name)
            return Response({"ok": False, "detail": f"{type(exc).__name__}: {exc}"})
        detail = (
            f"学到 {result['total']} 条(LLDP {result['lldp']} / CDP {result['cdp']})"
            f",新增 {result['added']} / 消失 {result['removed']}"
        )
        if result["total"] == 0:
            detail += " —— 一条都没有:对端可能没开 LLDP/CDP,或者 community 的 view 没放开这两个 MIB"
        return Response({"ok": True, "detail": detail, **result})

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

    @action(detail=False, methods=["get"])
    def export(self, request):
        """
        接口清单导出 CSV。**巡检和交维时要的就是这张表。**

        「速率成色」那一列是这份表格里最容易被忽略但最要紧的:
        退回 32 位计数器算出来的速率不可信(48 口千兆满速时 32 位计数器
        约 34 秒回绕一次),导出的时候必须跟着走,否则表格出了这个系统
        就再也看不出哪几行的数字是噪声。
        """

        import csv
        import io as _io

        from django.http import HttpResponse

        queryset = self.filter_queryset(self.get_queryset()).order_by("device_id", "if_index")

        buf = _io.StringIO()
        buf.write("\ufeff")
        writer = csv.writer(buf)
        writer.writerow([
            "设备", "ifIndex", "接口名", "描述", "类型", "MAC", "协商速率",
            "管理状态", "运行状态", "入向", "出向", "入向利用率%", "出向利用率%",
            "入向错包增量", "出向错包增量", "速率成色", "纳入监控", "最后状态变化", "更新时间",
        ])
        def bps_text(v):
            if v is None:
                return "未知"
            for unit, div in (("Gbps", 1e9), ("Mbps", 1e6), ("Kbps", 1e3)):
                if v >= div:
                    return f"{v / div:.2f} {unit}"
            return f"{v:.0f} bps"

        count = 0
        for i in queryset.iterator(chunk_size=500):
            writer.writerow([
                i.device.name, i.if_index, i.if_name, i.if_alias, i.if_type, i.mac,
                bps_text(i.speed_bps) if i.speed_bps else "未知",
                "up" if i.admin_up else ("down" if i.admin_up is False else "未知"),
                "up" if i.oper_up else ("down" if i.oper_up is False else "未知"),
                bps_text(i.in_bps), bps_text(i.out_bps),
                "未知" if i.util_in_pct is None else i.util_in_pct,
                "未知" if i.util_out_pct is None else i.util_out_pct,
                "未知" if i.in_err_delta is None else i.in_err_delta,
                "未知" if i.out_err_delta is None else i.out_err_delta,
                "32 位计数器,速率不可信" if (i.meta or {}).get("counter_32bit") else "64 位",
                "是" if i.monitored else "否",
                timezone.localtime(i.last_change).strftime("%Y-%m-%d %H:%M:%S") if i.last_change else "",
                timezone.localtime(i.updated_at).strftime("%Y-%m-%d %H:%M:%S"),
            ])
            count += 1

        response = HttpResponse(buf.getvalue(), content_type="text/csv; charset=utf-8")
        stamp = timezone.localtime(timezone.now()).strftime("%Y%m%d-%H%M%S")
        response["Content-Disposition"] = f'attachment; filename="interfaces-{stamp}.csv"'
        log.info("导出接口清单 CSV:%d 行", count)
        return response

    @action(detail=False, methods=["get"])
    def summary(self, request):
        """
        接口页顶部那几块数字,按设备一行。

        `counter_32bit` 那一项单独给出来:它不是故障,但它决定**这台设备的
        速率数字能不能信**。不显式说出来的话没人会想到去怀疑一个看着正常的数。
        """

        devices = list(Device.objects.filter(enabled=True).order_by("order", "id"))
        rows = (
            DeviceInterface.objects.filter(device__in=devices)
            .values("device_id")
            .annotate(
                total=Count("id"),
                up=Count("id", filter=Q(oper_up=True)),
                problem=Count("id", filter=Q(admin_up=True, oper_up=False)),
                errors=Count("id", filter=Q(in_err_delta__gt=0) | Q(out_err_delta__gt=0)),
                unmonitored=Count("id", filter=Q(monitored=False)),
            )
        )
        stats = {r["device_id"]: r for r in rows}
        # counter_32bit 在 meta 里,SQL 里筛 JSON 不如直接数 —— 接口总数
        # 是几十到几百,一次取出来在 Python 里数完全够
        legacy: dict[int, int] = {}
        for iface in DeviceInterface.objects.filter(device__in=devices).only("device_id", "meta"):
            if (iface.meta or {}).get("counter_32bit"):
                legacy[iface.device_id] = legacy.get(iface.device_id, 0) + 1

        payload = []
        for device in devices:
            row = stats.get(device.pk, {})
            payload.append({
                "device_id": device.pk, "device_name": device.name,
                "mgmt_ip": device.mgmt_ip, "kind": device.kind, "state": device.state,
                "model_label": device.get_model_display(),
                "collect_interfaces": device.collect_interfaces,
                "last_collected_at": device.last_collected_at,
                "total": row.get("total", 0), "up": row.get("up", 0),
                "problem": row.get("problem", 0), "errors": row.get("errors", 0),
                "unmonitored": row.get("unmonitored", 0),
                "counter_32bit": legacy.get(device.pk, 0),
            })
        return Response({"generated_at": timezone.now(), "devices": payload})

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


class ServerViewSet(DuplicateMixin, viewsets.ModelViewSet):
    """
    服务器 CRUD + 测试 / 立即采集 / 时序 / 网卡。

    和 DeviceViewSet 的形状一样,区别是**没有通道概念** —— 服务器只走 SSH。
    """

    duplicate_needs = ["host"]

    def _schedule_copy(self, copy):
        if copy.enabled:
            scheduler.schedule_now("server", copy.pk)

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
            # ESXi 专有。虚拟机数**给不出来时是 null 不是 0** —— 0 台是
            # "这台宿主空着",null 是"没采到"(vim-cmd 权限不够最常见),
            # 混成 0 会让人以为一台跑着三十台虚拟机的宿主是空的
            "esxi": {
                "vm_registered": extra.get("vm_registered"),
                "vm_running": extra.get("vm_running"),
                "vm_names": extra.get("vm_names") or [],
                "hw_platform": extra.get("hw_platform") or "",
                "cpu_total_mhz": extra.get("cpu_total_mhz"),
                "cpu_used_mhz": extra.get("overall_cpu_mhz"),
                "cpu_threads": extra.get("cpu_threads"),
                "cpu_packages": extra.get("cpu_packages"),
                "maintenance_mode": extra.get("maintenance_mode"),
            } if server.os_type == ServerOS.ESXI else None,
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
                v for v in (
                    extra.get("interface_error"),
                    # "这台没有 loadavg" 要说出来 —— 否则负载那一栏一直是 —,
                    # 看着像采集坏了,而它是这个系统本来就不提供
                    extra.get("load_absent"),
                    extra.get("stderr"),
                ) if v
            ],
        })


class IdracHostViewSet(DuplicateMixin, viewsets.ModelViewSet):
    """
    带外主机(iDRAC)。可增删改 —— 它是配置,不是采集产物。

    `board` 那个 action 是**大屏的唯一数据源**:一次请求把所有机器 + 部件
    汇总 + 告警清单一起给出去。拆成"每台一个请求"会在几十台机器上把
    gunicorn 打满(和大屏那三个接口同一条规矩)。
    """

    duplicate_needs = ["host"]

    def _schedule_copy(self, copy):
        if copy.enabled:
            scheduler.schedule_now("idrac", copy.pk)

    serializer_class = IdracHostSerializer
    filterset_class = IdracHostFilter
    search_fields = ["name", "host", "model_name", "service_tag", "system_hostname"]
    ordering_fields = ["order", "name", "state", "last_collected_at"]

    def get_queryset(self):
        return IdracHost.objects.select_related("server").annotate(
            open_event_count_ann=Count(
                "events", filter=Q(events__resolved_at__isnull=True), distinct=True
            )
        )

    @action(detail=True, methods=["post"])
    def test(self, request, pk=None):
        """
        「测试」按钮。**同步跑,不排队** —— 人点了要立刻看到结果,
        而且它不写库,重跑一次没有副作用。
        """

        from netcheck.idrac import collector as idrac_collector

        host = self.get_object()
        ok, detail = idrac_collector.test_connection(host)
        return Response({"ok": ok, "detail": detail})

    @action(detail=True, methods=["post"])
    def collect_now(self, request, pk=None):
        """立刻采一次。排队跑 —— 一次带外采集要打五六个端点,不能占着请求。"""

        from netcheck.tasks import collect_idrac_task

        host = self.get_object()
        collect_idrac_task.delay(host.pk)
        return Response({"detail": f"{host.name} 的带外采集已排入队列"})

    @action(detail=True, methods=["get"])
    def series(self, request, pk=None):
        """
        趋势。**没有降采样表** —— 和 DeviceSample / ServerSample 同一个取舍:
        最快 60 秒一拍,一天一千多行,不值得为它建三张桶表。代价是能看的
        跨度就是原始样本保留期。
        """

        host = self.get_object()
        hours = min(int(request.query_params.get("hours", 24) or 24), 720)
        since = timezone.now() - timezone.timedelta(hours=hours)
        rows = host.samples.filter(ts__gte=since).order_by("ts")
        return Response({
            "host": host.name,
            "hours": hours,
            "points": IdracSampleSerializer(rows, many=True).data,
        })

    @action(detail=True, methods=["get"])
    def detail_info(self, request, pk=None):
        """
        单台的部件明细 —— 最新一条样本的 `extra`。

        单独一个接口的理由和 ServerViewSet.detail_info 一样:这些东西
        **只看最新一条就够**,塞进 series 会让每个点都带一份部件数组。
        """

        host = self.get_object()
        latest = host.samples.order_by("-ts").first()
        extra = (latest.extra if latest else {}) or {}
        return Response({
            "host": IdracHostSerializer(host).data,
            "ts": latest.ts if latest else None,
            "reachable": latest.reachable if latest else None,
            "health": latest.health if latest else None,
            "error": latest.error if latest else "",
            "disks": extra.get("disks") or [],
            "volumes": extra.get("volumes") or [],
            "memory": extra.get("memory") or [],
            "psus": extra.get("psus") or [],
            "fans": extra.get("fans") or [],
            "temps": extra.get("temps") or [],
            "sel": extra.get("sel"),
            # 为什么某一栏是空的。**这几条是这一页最该显示的东西** ——
            # 没有它们,"硬盘 0 块"看着像这台机器没有硬盘
            "notes": [v for v in (
                extra.get("memory_summary_only"),
            ) if v],
            "endpoint_errors": extra.get("endpoint_errors") or {},
            "current": {
                "power_watts": latest.power_watts if latest else None,
                "inlet_temp_c": latest.inlet_temp_c if latest else None,
                "max_temp_c": latest.max_temp_c if latest else None,
                "temp_delta_c": latest.temp_delta_c if latest else None,
                "hottest": extra.get("hottest") or "",
            },
        })

    @action(detail=False, methods=["get"])
    def board(self, request):
        """
        **大屏的唯一数据源。**一次请求给出:每台一行 + 全局汇总 + 告警清单。

        ## 为什么汇总里 `unknown` 单独一栏

        「读不到状态」和「是好的」是两个结论。合成一个的话,一台权限配错的
        iDRAC 会在大屏上显示成一片绿 —— 而那正是最需要有人去看一眼的时候。
        所以 `ok / warn / crit / unknown` 是四栏,大屏上是四种颜色。

        ## 为什么「从没采过」不算故障

        刚加进来还没轮到的机器 `last_collected_at` 是 null。把它算成"失联"
        会让新加的机器在大屏上先红一阵子,人会去查一个不存在的问题。
        它单独算一档(`pending`)。
        """

        hosts = list(
            IdracHost.objects.filter(enabled=True)
            .select_related("server")
            .order_by("order", "id")
        )
        # 每台取最新一条样本。**一次查完**,不要每台一次 —— 几十台就是几十次查询
        latest_by_host: dict = {}
        if hosts:
            for sample in IdracSample.objects.filter(
                idrac__in=hosts,
                ts__gte=timezone.now() - timezone.timedelta(days=2),
            ).order_by("idrac_id", "-ts"):
                latest_by_host.setdefault(sample.idrac_id, sample)

        open_events = list(
            Event.objects.filter(
                source_type=SourceType.IDRAC, resolved_at__isnull=True
            ).select_related("idrac").order_by("-severity", "-started_at")[:200]
        )
        events_by_host: dict = {}
        for event in open_events:
            events_by_host.setdefault(event.idrac_id, []).append(event)

        rows, totals = [], {
            "hosts": len(hosts), "ok": 0, "warn": 0, "crit": 0,
            "unknown": 0, "pending": 0, "down": 0,
            "disk_total": 0, "disk_bad": 0, "disk_unknown": 0, "ssd_worn": 0,
            # SMART 预警**单独一栏**:盘还在跑、Health 还是绿的,但它快坏了。
            # 并进 disk_bad 会让"要现在换"和"该排计划换"混成一个数
            "disk_smart": 0,
            "psu_total": 0, "psu_bad": 0, "psu_redundancy_lost": 0,
            # 告警条数(不是台数)。大屏的横幅和结论条要的是这两个
            "alert_crit": 0, "alert_warn": 0,
            "memory_total": 0, "memory_bad": 0,
            "fan_total": 0, "fan_bad": 0,
            "vdisk_total": 0, "vdisk_bad": 0,
            "power_watts": 0.0, "sel_recent_critical": 0,
        }
        temps: list[tuple[float, str]] = []
        # 四张大卡要画的**分布**(不是时间序列)。在后端算是因为逐块盘、
        # 逐个探头的明细只在 sample.extra 里,而大屏的 payload 不带那些 ——
        # 带上的话几十台机器一次刷新就是几 MB
        dist_temps: list[float] = []
        dist_deltas: list[int] = []
        dist_lives: list[float] = []
        dist_fans: list[int] = []

        for host in hosts:
            sample = latest_by_host.get(host.pk)
            events = events_by_host.get(host.pk, [])
            extra = (sample.extra if sample else {}) or {}

            # 档位。**顺序有意**:没采过 → 失联 → 有严重事件 → 有警告事件 →
            # 部件状态读不到 → 正常。把"没采过"放最前是因为它不是故障
            if sample is None:
                level = "pending"
            elif not sample.reachable:
                level = "down"
            elif any(e.severity == Severity.CRITICAL for e in events):
                level = "crit"
            elif events:
                level = "warn"
            elif sample.health == HwState.UNKNOWN:
                level = "unknown"
            else:
                level = "ok"
            # 每台**只落一档**。down 不并进 crit —— 大屏上"带外连不上 3 台"和
            # "硬件有严重告警 3 台"要人做的事完全不同:前者去查网络/凭据,
            # 后者去机房换件。合成一栏会让人先跑错方向
            totals[level] = totals.get(level, 0) + 1

            for event in events:
                if event.severity == Severity.CRITICAL:
                    totals["alert_crit"] += 1
                else:
                    totals["alert_warn"] += 1

            if sample is not None and sample.reachable:
                for key in ("disk_total", "disk_bad", "disk_unknown", "psu_total", "psu_bad",
                            "memory_total", "memory_bad", "fan_total", "fan_bad",
                            "vdisk_total", "vdisk_bad"):
                    totals[key] += getattr(sample, key) or 0
                if sample.power_watts:
                    totals["power_watts"] += sample.power_watts
                if sample.max_temp_c is not None:
                    temps.append((sample.max_temp_c, host.name))
                    dist_temps.append(sample.max_temp_c)
                if sample.temp_delta_c is not None:
                    dist_deltas.append(int(round(sample.temp_delta_c)))
                if sample.fan_max_rpm:
                    dist_fans.append(sample.fan_max_rpm)

                sel = extra.get("sel") or {}
                totals["sel_recent_critical"] += sel.get("recent_critical") or 0

                disks = extra.get("disks") or []
                totals["disk_smart"] += sum(1 for d in disks if d.get("smart_alert"))
                totals["ssd_worn"] += sum(
                    1 for d in disks
                    if d.get("life_pct") is not None
                    and d["life_pct"] <= host.ssd_life_warn_pct
                )
                # **只有 SSD 进这条分布。**机械盘的 life_pct 是 None
                # (它没有这个概念),混进来的话曲线会被一堆 0 压平
                dist_lives.extend(
                    d["life_pct"] for d in disks if d.get("life_pct") is not None
                )

                # 冗余丢失:有一路电源没有输入电压。**机器照跑,操作系统里
                # 一点症状都没有** —— 这正是带外该报而带内报不了的那一类
                psus = extra.get("psus") or []
                if any(
                    p.get("input_voltage") is not None and p["input_voltage"] < 50
                    for p in psus
                ) or any(p.get("health") in ("warning", "critical") for p in psus):
                    totals["psu_redundancy_lost"] += 1

            rows.append({
                "id": host.pk, "name": host.name, "host": host.host,
                "site": host.site, "role": host.role,
                "model": host.model_name, "service_tag": host.service_tag,
                "power_state": host.power_state,
                "server_id": host.server_id, "server_name": host.server.name if host.server else "",
                "level": level,
                "state": host.state,
                "health": sample.health if sample else None,
                "reachable": sample.reachable if sample else None,
                "ts": sample.ts if sample else None,
                "last_error": host.last_error,
                "interval": host.interval_seconds,
                "metrics": {
                    "power_watts": sample.power_watts if sample else None,
                    "inlet_temp_c": sample.inlet_temp_c if sample else None,
                    "max_temp_c": sample.max_temp_c if sample else None,
                    "temp_delta_c": sample.temp_delta_c if sample else None,
                    "fan_max_rpm": sample.fan_max_rpm if sample else None,
                },
                "parts": {
                    # **每一项都是 (总数, 异常, 未知)** —— 未知不并进任何一边
                    "disk": [sample.disk_total, sample.disk_bad, sample.disk_unknown]
                            if sample else [None, None, None],
                    "psu": [sample.psu_total, sample.psu_bad, None] if sample else [None, None, None],
                    "memory": [sample.memory_total, sample.memory_bad, None]
                              if sample else [None, None, None],
                    "fan": [sample.fan_total, sample.fan_bad, None] if sample else [None, None, None],
                    "vdisk": [sample.vdisk_total, sample.vdisk_bad, None]
                             if sample else [None, None, None],
                },
                "hottest": extra.get("hottest") or "",
                "sel_recent": (extra.get("sel") or {}).get("recent_critical"),
                "alerts": [
                    {"kind": e.kind, "kind_label": e.get_kind_display(),
                     "severity": e.severity, "message": e.message,
                     "started_at": e.started_at}
                    for e in events
                ],
            })

        totals["power_watts"] = round(totals["power_watts"], 1) or None
        totals["temp_max"] = max(temps)[0] if temps else None
        # 最热那台**点名** —— 只给一个数字的话人还得自己去表里找
        totals["temp_max_host"] = max(temps)[1] if temps else None
        totals["temp_avg"] = round(sum(t[0] for t in temps) / len(temps), 1) if temps else None

        # 全局档位:有严重就是严重,有警告就是警告 —— **unknown 不算正常**,
        # 但也不算故障,它是"这块屏上有一部分是瞎的"
        if totals["crit"] or totals["down"]:
            verdict = "crit"
        elif totals["warn"]:
            verdict = "warn"
        elif totals["unknown"]:
            verdict = "unknown"
        else:
            verdict = "ok"

        return Response({
            "generated_at": timezone.now(),
            "verdict": verdict,
            "totals": totals,
            # 四张大卡画的是**分布**,不是趋势 —— 前端那条曲线的 X 轴是
            # "N 台按高低排好序",所以排序在这里做完
            "distributions": {
                "temps": sorted(dist_temps, reverse=True),
                "deltas": sorted(dist_deltas, reverse=True),
                # 寿命是**越低越糟**,所以升序 —— 最该看的那块排在最前
                "lives": sorted(dist_lives),
                "fans": sorted(dist_fans, reverse=True),
            },
            "hosts": rows,
            # 全部未恢复告警,按级别排 —— 大屏右侧那一栏
            "alerts": [
                {"host_id": e.idrac_id,
                 "host": e.idrac.name if e.idrac else "?",
                 "kind": e.kind, "kind_label": e.get_kind_display(),
                 "severity": e.severity, "message": e.message,
                 "started_at": e.started_at}
                for e in open_events
            ],
        })


class FirewallAddressViewSet(viewsets.ReadOnlyModelViewSet):
    """
    防火墙**地址对象 / 地址组**只读快照。和策略同一次同步拿回来。

    这一页回答的是策略表回答不了的另一半:策略里的源/目的地址是一串
    **名字**(`内网服务器组`),**它到底是哪几个网段完全不在策略表里**。
    """

    serializer_class = FirewallAddressSerializer
    filterset_class = FirewallAddressFilter
    search_fields = ["name", "value", "comment"]
    ordering_fields = ["name", "addr_type", "is_group", "value", "synced_at"]

    def get_queryset(self):
        return FirewallAddress.objects.select_related("device")

    @action(detail=False, methods=["get"])
    def resolve(self, request):
        """
        **别名查询。**`?device=1&name=内网服务器组` → 它到底是什么。

        地址组会**递归展开**(组能套组),返回一棵树 + 一张拍平的叶子表。
        人问"这个别名是哪些地址",要的就是那张拍平的表。

        三件在返回里说清楚的事:

        - **查不到 ≠ 不存在。**FortiOS 的 `show` 只打印偏离默认值的项,
          出厂自带的对象(`all` / `none`)根本不出现 —— 走 SSH 通道同步的
          设备上查它们必然查不到。所以 `kind` 是 `unknown` 而不是报错,
          页面上说的是"没同步到这个对象"。
        - **`all` 是「任意」,不是「查不到」**(内置名,含义确定)。
          把它显示成"没同步到"会让人以为数据缺了一块,而实际上那条策略
          是对所有地址开放的 —— 那恰恰是最该看见的。
        - **环要标出来。**组 A 包含组 B、组 B 包含组 A 这种配置 FortiOS
          不拦,而递归展开会转到超时。这里掐掉那一支并标 `cycle`。
        """

        device_id = request.query_params.get("device")
        name = (request.query_params.get("name") or "").strip()
        if not device_id or not name:
            return Response(
                {"detail": "要同时给 device 和 name"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        rows = list(FirewallAddress.objects.filter(device_id=device_id))
        index = addresses_mod.build_index(rows)
        tree = addresses_mod.resolve(name, index)

        policies = list(
            FirewallPolicy.objects.filter(device_id=device_id).only(
                "id", "policy_id", "seq", "name", "src_addr", "dst_addr",
                "enabled", "action",
            )
        )
        return Response({
            "device": int(device_id),
            "query": name,
            # 这批数据是哪条通道来的 —— API 能拿到内置对象,SSH 拿不到。
            # 同一个别名在两条通道下查出来的结果不一样,这一点要能看见
            "method": rows[0].method if rows else "",
            "synced_at": rows[0].synced_at if rows else None,
            "total_objects": len(rows),
            "result": tree,
            "used_by": addresses_mod.used_by_policies(name, policies),
        })

    @action(detail=False, methods=["get"])
    def summary(self, request):
        """按设备一行:同步了多少对象、多少组、走的哪条通道。"""

        devices = list(
            Device.objects.filter(
                kind=DeviceKind.FIREWALL, enabled=True, policy_sync_enabled=True
            ).order_by("order", "id")
        )
        counts: dict = {}
        for row in FirewallAddress.objects.filter(device__in=devices).only(
            "device_id", "is_group", "method", "synced_at"
        ):
            slot = counts.setdefault(row.device_id, {
                "total": 0, "groups": 0, "method": row.method, "synced_at": row.synced_at,
            })
            slot["total"] += 1
            if row.is_group:
                slot["groups"] += 1

        return Response({"devices": [
            {
                "device_id": d.pk, "device_name": d.name, "mgmt_ip": d.mgmt_ip,
                "vdom": d.api_vdom or "root", "state": d.state,
                **counts.get(d.pk, {"total": 0, "groups": 0, "method": "", "synced_at": None}),
                # **0 个对象不等于"这台没有地址对象"** —— SSH 的 show 可能
                # 没跑成、API 可能权限不够。页面上说的是"没同步到"
                "note": (
                    "" if counts.get(d.pk)
                    else "没有同步到地址对象 —— 不等于这台没有配"
                ),
            }
            for d in devices
        ]})


class FirewallServiceViewSet(viewsets.ReadOnlyModelViewSet):
    """
    防火墙**服务对象 / 服务组**只读快照。和策略同一次同步拿回来。

    这是「这条策略放开了什么」的第三维:地址回答"谁到谁",这里回答
    "哪个端口"。策略里写的是 `HTTPS` 这样的名字,**它到底是哪几个端口
    完全不在策略表里**。
    """

    serializer_class = FirewallServiceSerializer
    filterset_class = FirewallServiceFilter
    search_fields = ["name", "value", "comment", "category"]
    ordering_fields = ["name", "protocol", "is_group", "value", "synced_at"]

    def get_queryset(self):
        return FirewallService.objects.select_related("device")

    @action(detail=False, methods=["get"])
    def resolve(self, request):
        """
        **服务名查询。**`?device=1&name=业务服务组` → 它到底是哪几个端口。

        和地址那边共用同一个展开器(`devices/addresses.resolve()`)——
        两者在 `name / is_group / value / members` 上是同构的。
        **不同的只有内置名那一套**:`ALL` 在服务里是"所有协议所有端口",
        在地址里是 `0.0.0.0/0`。

        ⚠ **走 SSH 通道时查预定义服务必然查不到。**FortiOS 自带几百个
        (HTTP / HTTPS / SSH / DNS …),而 `show firewall service custom`
        只打印**被改过的**那些 —— 而策略里引用得最多的恰恰是它们。
        返回里带着 `method`,页面上要把这一点说出来:那是"没同步到",
        **不是"这个服务不存在"**。
        """

        device_id = request.query_params.get("device")
        name = (request.query_params.get("name") or "").strip()
        if not device_id or not name:
            return Response(
                {"detail": "要同时给 device 和 name"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        rows = list(FirewallService.objects.filter(device_id=device_id))
        index = addresses_mod.build_index([
            {"name": r.name, "is_group": r.is_group, "addr_type": r.protocol,
             "value": r.value, "members": r.members, "comment": r.comment}
            for r in rows
        ])
        tree = addresses_mod.resolve(name, index, builtin=addresses_mod.SERVICE_BUILTIN)

        policies = list(
            FirewallPolicy.objects.filter(device_id=device_id).only(
                "id", "policy_id", "seq", "name", "service", "enabled", "action",
            )
        )
        return Response({
            "device": int(device_id),
            "query": name,
            "method": rows[0].method if rows else "",
            "synced_at": rows[0].synced_at if rows else None,
            "total_objects": len(rows),
            "result": tree,
            "used_by": addresses_mod.used_by_policies(name, policies, kind="service"),
        })


class FirewallVipViewSet(viewsets.ReadOnlyModelViewSet):
    """
    防火墙**映射**(FortiOS 的 firewall vip)只读快照。写入只有一条路:
    和策略同一次的同步任务。

    这张表回答的是策略表回答不了的那个问题:**外面的 1.2.3.4:443 到底进到
    内网哪台机器的哪个端口**。策略的目的地址里只有一个 VIP 的名字。
    """

    serializer_class = FirewallVipSerializer
    filterset_class = FirewallVipFilter
    search_fields = ["name", "comment", "ext_ip", "mapped_ip"]
    ordering_fields = ["seq", "name", "ext_ip", "synced_at"]

    def get_queryset(self):
        return FirewallVip.objects.select_related("device")

    def _usage_index(self, queryset):
        """
        (设备, vdom, 映射名) → 引用它的策略列表。

        **一条没有任何策略引用的映射是不生效的** —— 和"从未命中"同一类
        结论,能直接拿去清理。所以这个索引值得为它多查一次策略表。

        名字**精确比较**:`web-vip-old` 和 `web-vip` 是两条不同的规则。
        """
        device_ids = set(queryset.values_list("device_id", flat=True))
        if not device_ids:
            return {}
        index: dict = {}
        policies = FirewallPolicy.objects.filter(device_id__in=device_ids).only(
            "id", "device_id", "vdom", "policy_id", "seq", "name",
            "dst_addr", "enabled", "action",
        )
        for p in policies:
            for name in (p.dst_addr or []):
                key = (p.device_id, p.vdom, str(name))
                index.setdefault(key, []).append({
                    "id": p.pk, "policy_id": p.policy_id, "seq": p.seq,
                    "name": p.name, "enabled": p.enabled, "action": p.action,
                })
        return index

    def get_serializer_context(self):
        context = super().get_serializer_context()
        if self.action in ("list", "retrieve"):
            context["vip_usage"] = self._usage_index(
                self.filter_queryset(self.get_queryset())
            )
        return context

    @action(detail=False, methods=["get"])
    def summary(self, request):
        """
        映射概览。三个数字,每个都直接对应一个动作:

          - **整机映射**:外网地址的所有端口都通到内网那台机器 —— 该收窄成端口映射
          - **没有策略引用**:配了但不生效 —— 可以清理
          - **没有同步到映射**:这批数据里一条映射都没有。**这不等于
            "这台防火墙没有映射"** —— SSH 通道的 `show firewall vip` 可能
            没跑成、API 通道可能权限不够。两者在页面上的说法完全不同:
            前者是结论,后者是状态(和「这批数据没有命中统计」同一条)
        """

        queryset = self.filter_queryset(self.get_queryset())
        vips = list(queryset)
        usage = self._usage_index(queryset)

        unused = [
            v for v in vips
            if not usage.get((v.device_id, v.vdom, v.name))
        ]
        whole_host = [v for v in vips if v.whole_host]

        def brief(v):
            return {
                "id": v.pk, "device_id": v.device_id, "device_name": v.device.name,
                "vdom": v.vdom, "name": v.name, "endpoint_text": v.endpoint_text,
                "vip_type": v.vip_type, "whole_host": v.whole_host,
                "comment": v.comment,
            }

        # 这批数据覆盖了哪些防火墙 —— 用来分辨"没有映射"和"没同步到映射"
        device_ids = {v.device_id for v in vips}
        firewalls = Device.objects.filter(
            kind=DeviceKind.FIREWALL, enabled=True, policy_sync_enabled=True
        ).values_list("id", "name")
        missing = [name for did, name in firewalls if did not in device_ids]

        return Response({
            "generated_at": timezone.now(),
            "total": len(vips),
            "whole_host": {
                "count": len(whole_host),
                "hint": "外网地址的**所有端口**都通到内网那台机器上,暴露面比端口映射大得多",
                "items": [brief(v) for v in whole_host[:100]],
            },
            "unused": {
                "count": len(unused),
                "hint": "没有任何策略的目的地址引用它 —— 配了但不生效,可以清理",
                "items": [brief(v) for v in unused[:100]],
            },
            # **不说"这几台没有映射"**,只说没同步到 —— 我们分不出是真没有
            # 还是没拉到,而说成前者会让人以为已经确认过了
            "devices_without_vips": missing,
        })


class DeviceNeighborViewSet(viewsets.ReadOnlyModelViewSet):
    """
    邻居关系只读 —— 它是采集产物(LLDP / CDP)。

    `topology` 那个 action 给的是**两端都在这个平台管着**的链路,
    那些才画得成拓扑图;一端是打印机或者别人的设备时,只能列在明细里。
    """

    serializer_class = DeviceNeighborSerializer
    filterset_class = DeviceNeighborFilter
    search_fields = ["remote_device", "remote_port", "local_if_name"]
    ordering_fields = ["local_if_index", "last_seen", "changed_at"]

    def get_queryset(self):
        return DeviceNeighbor.objects.select_related("device", "matched_device")

    @action(detail=False, methods=["get"])
    def summary(self, request):
        """按设备一行:学到多少邻居、其中多少是受管设备、最近有没有变过。"""

        devices = list(
            Device.objects.filter(enabled=True, collect_neighbors=True).order_by("order", "id")
        )
        rows = (
            DeviceNeighbor.objects.filter(device__in=devices)
            .values("device_id")
            .annotate(
                total=Count("id"),
                lldp=Count("id", filter=Q(protocol="lldp")),
                cdp=Count("id", filter=Q(protocol="cdp")),
                managed=Count("id", filter=Q(matched_device__isnull=False)),
                changed=Count("id", filter=Q(changed_at__isnull=False)),
                unresolved=Count("id", filter=Q(local_if_index__isnull=True)),
            )
        )
        stats = {r["device_id"]: r for r in rows}
        payload = []
        for device in devices:
            row = stats.get(device.pk, {})
            payload.append({
                "device_id": device.pk, "device_name": device.name,
                "mgmt_ip": device.mgmt_ip, "kind": device.kind, "state": device.state,
                "model_label": device.get_model_display(),
                "last_collected_at": device.last_collected_at,
                "method": device.last_method_used or device.collect_method,
                "total": row.get("total", 0),
                "lldp": row.get("lldp", 0), "cdp": row.get("cdp", 0),
                "managed": row.get("managed", 0),
                "changed": row.get("changed", 0),
                # 本地口没解析出 ifIndex 的条数 —— 那些邻居不知道挂在哪个口
                "unresolved": row.get("unresolved", 0),
                # 邻居只有 SNMP 通道采得到,走 API/SSH 的设备永远是 0 ——
                # 明确说出来,否则"0 个邻居"会被读成"这个口没接线"
                "snmp_channel": (device.last_method_used or device.collect_method) == CollectMethod.SNMP,
            })
        return Response({"generated_at": timezone.now(), "devices": payload})

    @action(detail=False, methods=["get"])
    def topology(self, request):
        """
        受管链路 —— 两端都是这个平台在管的设备。

        **同一条物理链路会被两端各上报一次**(A 的 Gi1/0/1 看到 B,
        B 的 Gi1/0/48 看到 A),这里合并成一条:按 (设备 id 小的在前) 归一化,
        并标注这条链路是不是**双向都确认**的。

        单向确认的链路要单独标出来:它可能是对端没开 LLDP,
        也可能是我们把邻居挂到了错误的口上 —— 后者是要去查的。
        """

        links: dict[tuple, dict] = {}
        queryset = (
            DeviceNeighbor.objects.filter(matched_device__isnull=False)
            .select_related("device", "matched_device")
        )
        for n in queryset:
            a_id, b_id = n.device_id, n.matched_device_id
            # 归一化方向:小 id 在前,这样两端上报的同一条链路落到同一个 key
            if a_id <= b_id:
                key = (a_id, n.local_if_name, b_id, n.remote_port, n.protocol)
                entry = links.setdefault(key, {
                    "a_device_id": a_id, "a_device": n.device.name, "a_port": n.local_if_name,
                    "b_device_id": b_id, "b_device": n.matched_device.name, "b_port": n.remote_port,
                    "protocol": n.protocol, "confirmed_by": [],
                    "last_seen": n.last_seen, "changed_at": n.changed_at,
                })
            else:
                key = (b_id, n.remote_port, a_id, n.local_if_name, n.protocol)
                entry = links.setdefault(key, {
                    "a_device_id": b_id, "a_device": n.matched_device.name, "a_port": n.remote_port,
                    "b_device_id": a_id, "b_device": n.device.name, "b_port": n.local_if_name,
                    "protocol": n.protocol, "confirmed_by": [],
                    "last_seen": n.last_seen, "changed_at": n.changed_at,
                })
            entry["confirmed_by"].append(n.device.name)
            if n.changed_at and (entry["changed_at"] is None or n.changed_at > entry["changed_at"]):
                entry["changed_at"] = n.changed_at

        out = []
        for entry in links.values():
            entry["bidirectional"] = len(set(entry["confirmed_by"])) >= 2
            out.append(entry)
        out.sort(key=lambda e: (e["a_device"], e["a_port"]))

        one_way = sum(1 for e in out if not e["bidirectional"])
        return Response({
            "generated_at": timezone.now(),
            "links": out,
            "total": len(out),
            "bidirectional": len(out) - one_way,
            "one_way": one_way,
            "one_way_hint": (
                "单向确认的链路:可能是对端没开 LLDP/CDP,也可能是邻居被挂到了"
                "错误的本地口上 —— 后者要去查(对照接口的实际连线)"
            ) if one_way else "",
        })

    @action(detail=False, methods=["get"])
    def export(self, request):
        """邻居清单导出 —— 交维和画拓扑图时要的就是这张表。"""

        import csv
        import io as _io

        from django.http import HttpResponse

        queryset = self.filter_queryset(self.get_queryset()).order_by(
            "device_id", "local_if_index", "protocol")
        buf = _io.StringIO()
        buf.write("\ufeff")
        writer = csv.writer(buf)
        writer.writerow([
            "本端设备", "本端接口", "ifIndex", "发现协议", "对端设备", "对端接口",
            "对端平台", "对端管理地址", "对端 chassis id", "对端是否纳管",
            "首次发现", "最后确认", "最后变化",
        ])
        for n in queryset.iterator(chunk_size=500):
            writer.writerow([
                n.device.name, n.local_if_name,
                # 解析不出 ifIndex 时写「未解析」而不是空 —— 空会被读成 0
                n.local_if_index if n.local_if_index is not None else "未解析",
                n.protocol.upper(), n.remote_device, n.remote_port,
                n.remote_platform, n.remote_mgmt_ip, n.remote_chassis_id,
                n.matched_device.name if n.matched_device_id else "否",
                timezone.localtime(n.first_seen).strftime("%Y-%m-%d %H:%M:%S"),
                timezone.localtime(n.last_seen).strftime("%Y-%m-%d %H:%M:%S"),
                timezone.localtime(n.changed_at).strftime("%Y-%m-%d %H:%M:%S") if n.changed_at else "",
            ])
        response = HttpResponse(buf.getvalue(), content_type="text/csv; charset=utf-8")
        stamp = timezone.localtime(timezone.now()).strftime("%Y%m%d-%H%M%S")
        response["Content-Disposition"] = f'attachment; filename="neighbors-{stamp}.csv"'
        return response


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

    def get_serializer_context(self):
        """
        把映射表按 (设备, vdom, 名字) 建索引塞进 context。

        **在这里做而不是在序列化器里**:序列化器一次只看得到一行,逐行去查
        映射就是每页 20 次查询,而这一页是要翻的。一台防火墙的映射通常几十到
        几百条,整张表一次查回来比什么都便宜。

        `device` 过滤存在时只取那台的 —— 页面上绝大多数请求都带着设备。
        """
        context = super().get_serializer_context()
        if self.action not in ("list", "retrieve"):
            return context

        vips = FirewallVip.objects.all()
        if device_id := self.request.query_params.get("device"):
            vips = vips.filter(device_id=device_id)
        context["vip_index"] = {
            (v.device_id, v.vdom, v.name): {
                "id": v.pk, "name": v.name, "endpoint_text": v.endpoint_text,
                "ext_ip": v.ext_ip, "ext_port_text": v.ext_port_text,
                "mapped_ip": v.mapped_ip, "mapped_port_text": v.mapped_port_text,
                "protocol": v.protocol, "vip_type": v.vip_type,
                "whole_host": v.whole_host,
            }
            for v in vips.only(
                "id", "device_id", "vdom", "name", "ext_ip", "ext_port",
                "mapped_ip", "mapped_port", "protocol", "port_forward", "vip_type",
            )
        }
        return context

    @action(detail=False, methods=["get"])
    def audit(self, request):
        """
        规则审计 —— 防火墙评审时真正要回答的四个问题。

            1. 有没有 any-any-any 的放行规则(等于这对接口之间没有防火墙)
            2. 有没有放行但不记日志的规则(出事之后查不出来源)
            3. 有没有从来没命中过的规则(可以清理的候选)
            4. 有没有**永远匹配不到**的规则(被前面的规则挡住了)

        前三项每条规则自己就能判(模型上的属性),第四项**必须看顺序** ——
        防火墙是先匹配先生效的,所以要拿整张有序的表来算,这也是它只能在
        这个接口里做、不能做成表格里一列的原因。

        影子规则这里只判**最保守、绝不会误报的那一种**:某条 enabled 的
        规则在它的接口对上是 any-any-any,那么同一接口对上排在它后面的规则
        全都到不了。更一般的影子判定要做地址段和端口区间的包含运算
        (10.0.0.0/8 盖住 10.1.2.0/24、服务组展开成端口区间),
        那需要把地址对象和服务对象也同步过来 —— **没做,不猜**。
        宁可漏报也不误报:告诉工程师"这条规则没用"而它其实在用,
        比不告诉他糟得多。
        """

        device_id = request.query_params.get("device")
        queryset = self.filter_queryset(self.get_queryset())
        if device_id:
            queryset = queryset.filter(device_id=device_id)
        # 顺序是语义,按设备 + vdom + seq 取全量(几百条,一次查完)
        policies = list(queryset.order_by("device_id", "vdom", "seq", "policy_id"))

        def brief(p):
            return {
                "id": p.pk, "device_id": p.device_id, "device_name": p.device.name,
                "vdom": p.vdom, "policy_id": p.policy_id, "seq": p.seq,
                "name": p.name, "action": p.action, "enabled": p.enabled,
                "src_addr": p.src_addr, "dst_addr": p.dst_addr, "service": p.service,
                "hit_count": p.hit_count, "comments": p.comments,
            }

        wide_open, no_log, never_hit, shadowed = [], [], [], []

        # ---- 前三项:逐条判 ----
        for p in policies:
            if p.permissive_level == "critical":
                wide_open.append({**brief(p), "level": "critical"})
            elif p.permissive_level == "warning":
                wide_open.append({**brief(p), "level": "warning"})
            if p.logging_off:
                no_log.append(brief(p))
            if p.never_hit:
                never_hit.append(brief(p))

        # ---- 第四项:按 (设备, vdom, 接口对) 分组,找 catch-all 之后的规则 ----
        catch_all: dict = {}
        for p in policies:
            key = (p.device_id, p.vdom, p.intf_pair)
            blocker = catch_all.get(key)
            if blocker is not None:
                shadowed.append({
                    **brief(p),
                    "shadowed_by": {"id": blocker.pk, "policy_id": blocker.policy_id,
                                    "seq": blocker.seq, "name": blocker.name,
                                    "action": blocker.action},
                    "reason": (
                        f"同一接口对上,顺序在它前面的 #{blocker.seq + 1}"
                        f"(策略 {blocker.policy_id})是 any-any-any 的"
                        f"{'放行' if blocker.action == PolicyAction.ACCEPT else '拒绝'}规则,"
                        "这条永远匹配不到"
                    ),
                })
                continue
            # 任何动作的 any-any-any 都会挡住后面(拒绝的兜底规则同样如此,
            # 而兜底规则本来就该放在最后 —— 它后面还有规则就是配错了)
            if (p.enabled and p._is_any(p.src_addr) and p._is_any(p.dst_addr)
                    and p._is_any(p.service)):
                catch_all[key] = p

        # 没有命中统计时,"从未命中"这一项没有意义 —— 明确说出来,
        # 而不是给一个空列表让人以为"没有这种规则"
        has_hit_stats = any(p.hit_count is not None for p in policies)

        return Response({
            "generated_at": timezone.now(),
            "total": len(policies),
            "has_hit_stats": has_hit_stats,
            "findings": [
                {"key": "wide_open", "label": "过宽的放行规则",
                 "hint": "源/目的/服务都是任意的 accept —— 等于这对接口之间没有防火墙",
                 "count": len(wide_open), "items": wide_open[:100]},
                {"key": "shadowed", "label": "永远匹配不到的规则",
                 "hint": "同一接口对上被前面的 any-any-any 规则挡住了。防火墙先匹配先生效",
                 "count": len(shadowed), "items": shadowed[:100]},
                {"key": "no_log", "label": "放行但不记日志",
                 "hint": "出事之后查不出来源。放行规则恰恰是最需要留痕的一类",
                 "count": len(no_log), "items": no_log[:100]},
                {"key": "never_hit", "label": "从未命中过的规则",
                 "hint": ("可以清理的候选" if has_hit_stats
                          else "**这批数据没有命中统计**(SSH 通道),这一项无法判断"),
                 "count": len(never_hit) if has_hit_stats else None,
                 "items": never_hit[:100]},
            ],
        })

    @action(detail=False, methods=["get"])
    def export(self, request):
        """
        导出 CSV。防火墙评审要把规则表交给安全/审计的人,而他们用 Excel。

        两个细节:
        - **带 UTF-8 BOM**,不然 Excel 打开中文是乱码(这是国内环境的常态)
        - 命中数为空时导出「未知」而不是空单元格或 0 ——
          交出去的表格同样不能让人把"不知道"读成"没命中"
        """

        import csv
        import io as _io

        from django.http import HttpResponse

        queryset = self.filter_queryset(self.get_queryset()).order_by(
            "device_id", "vdom", "seq", "policy_id")

        buf = _io.StringIO()
        buf.write("\ufeff")            # BOM
        writer = csv.writer(buf)
        writer.writerow([
            "设备", "VDOM", "顺序", "策略ID", "名称", "源接口", "源地址",
            "目的接口", "目的地址", "服务", "生效时间", "动作", "NAT", "状态",
            "日志", "命中次数", "字节数", "最后命中", "风险", "备注", "同步通道", "同步时间",
        ])
        count = 0
        for p in queryset.iterator(chunk_size=500):
            risks = []
            if p.permissive_level == "critical":
                risks.append("过宽(any-any-any 放行)")
            elif p.permissive_level == "warning":
                risks.append("偏宽(服务任意)")
            if p.logging_off:
                risks.append("不记日志")
            if p.never_hit:
                risks.append("从未命中")
            writer.writerow([
                p.device.name, p.vdom, p.seq + 1, p.policy_id, p.name,
                " ".join(p.src_intf or []), " ".join(p.src_addr or []),
                " ".join(p.dst_intf or []), " ".join(p.dst_addr or []),
                " ".join(p.service or []), p.schedule,
                p.get_action_display(), "是" if p.nat else "否",
                "启用" if p.enabled else "已停用",
                p.log_traffic or "不记录",
                "未知" if p.hit_count is None else p.hit_count,
                "未知" if p.bytes_count is None else p.bytes_count,
                timezone.localtime(p.last_hit_at).strftime("%Y-%m-%d %H:%M:%S") if p.last_hit_at else "",
                " / ".join(risks),
                p.comments, p.method.upper(),
                timezone.localtime(p.synced_at).strftime("%Y-%m-%d %H:%M:%S") if p.synced_at else "",
            ])
            count += 1

        response = HttpResponse(buf.getvalue(), content_type="text/csv; charset=utf-8")
        stamp = timezone.localtime(timezone.now()).strftime("%Y%m%d-%H%M%S")
        response["Content-Disposition"] = f'attachment; filename="firewall-policies-{stamp}.csv"'
        log.info("导出防火墙策略 CSV:%d 条", count)
        return response

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

        # 审计计数。**判定条件在 SQL 里重写了一遍**(模型属性数据库不认识),
        # 和 filters.FirewallPolicyFilter 里那两个方法必须保持一致
        svc_any = Q(service__icontains='"all"') | Q(service__icontains='"any"') | Q(service=[])
        src_any = Q(src_addr__icontains='"all"') | Q(src_addr__icontains='"any"') | Q(src_addr=[])
        dst_any = Q(dst_addr__icontains='"all"') | Q(dst_addr__icontains='"any"') | Q(dst_addr=[])
        accept_on = Q(enabled=True, action=PolicyAction.ACCEPT)
        audit_rows = (
            FirewallPolicy.objects.filter(device__in=devices)
            .values("device_id")
            .annotate(
                wide=Count("id", filter=accept_on & svc_any & src_any & dst_any),
                nolog=Count("id", filter=accept_on & (
                    Q(log_traffic="") | Q(log_traffic__iexact="disable")
                    | Q(log_traffic__iexact="disabled"))),
            )
        )
        audits = {r["device_id"]: r for r in audit_rows}

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
                # 审计:这两项不依赖命中统计,SSH 通道也能判
                "wide_open": audits.get(device.pk, {}).get("wide", 0),
                "no_log": audits.get(device.pk, {}).get("nolog", 0),
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


class NotifierViewSet(DuplicateMixin, viewsets.ModelViewSet):
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
                    # 优先级(order)。**数字小的排在前面** —— 列表、大屏、
                    # 下拉都按它排(模型的 ordering = ["order", "id"])。
                    # 大屏上要能看见它,否则"为什么这条线在最上面"没法回答
                    "order": t.order,
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
            "order": device.order,
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
            "order": server.order,
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
        "server_os": pack(ServerOS),
        "hw_state": pack(HwState),
        "notifier_kind": pack(NotifierKind),
        "rollup_bucket": pack(RollupBucket),
        "notify_status": pack(NotifyLog.Status),
        "backup_status": pack(BackupStatus),
        "policy_action": pack(PolicyAction),
        "vip_type": pack(VipType),
        "address_type": pack(AddressType),
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
