"""
事件引擎:把「这一拍观测到的问题清单」变成「事件表里的开/关」。

拨测和设备采集共用这一套,靠 EventSource 描述来源。

三条规则是这里的全部要点:

1. **连续 N 次才开,连续 M 次才关。**单次失败就报警会被瞬时丢包刷爆;
   反过来单次成功就宣告恢复,抖动线路会开关几百次。阈值来自来源自身的
   fail_threshold / recover_threshold。

2. **连续次数存 Redis,不存库。**它是每秒都在变的计数器,写库等于给每条
   线路每秒加一次 UPDATE。丢了的代价仅仅是"这次告警晚几拍",可以接受。

3. **同一来源同一类型同时只有一条未恢复事件。**由 Event 那条部分唯一索引
   在库层面兜底,这里的逻辑只是不去制造重复。级别变严重时**升级现有事件**
   而不是新开一条 —— 一次故障就该是一行,否则事件表没法读。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.utils import timezone

from netcheck.models import Device, DeviceInterface, Event, EventKind, ProbeTarget, Severity, SourceType

log = logging.getLogger("netcheck.events")

# 连续计数在 Redis 里的存活时间。比最长采集间隔宽裕得多,但也不能是永久:
# 线路被停用之后那份计数应该自己过期,不然重新启用时带着旧状态。
_STREAK_TTL = 7 * 24 * 3600

_SEVERITY_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}


@dataclass
class EventSource:
    """事件的来源。三个外键只有一个非空,和 Event 表一致。"""

    source_type: str
    name: str
    fail_threshold: int = 3
    recover_threshold: int = 3
    target: ProbeTarget | None = None
    device: Device | None = None
    interface: DeviceInterface | None = None
    # 附加到事件标题上的限定词,如接口名
    qualifier: str = ""

    @classmethod
    def from_target(cls, t: ProbeTarget) -> "EventSource":
        return cls(
            source_type=SourceType.PROBE, name=f"{t.name}({t.host})", target=t,
            fail_threshold=t.fail_threshold, recover_threshold=t.recover_threshold,
        )

    @classmethod
    def from_device(cls, d: Device) -> "EventSource":
        return cls(
            source_type=SourceType.DEVICE, name=f"{d.name}({d.mgmt_ip})", device=d,
            fail_threshold=d.fail_threshold, recover_threshold=d.recover_threshold,
        )

    @classmethod
    def from_interface(cls, i: DeviceInterface, device: Device) -> "EventSource":
        # device 也一起填上:这样"这台设备相关的所有事件"一次能查出来,
        # 包含它的接口事件。唯一约束是四元组,填了不会影响去重。
        return cls(
            source_type=SourceType.INTERFACE, name=f"{device.name} / {i.if_name}",
            interface=i, device=device,
            fail_threshold=device.fail_threshold, recover_threshold=device.recover_threshold,
            qualifier=i.if_name,
        )

    @property
    def cache_key(self) -> str:
        obj_id = (
            self.target_id if self.target else (self.device_id if self.device else self.interface_id)
        )
        return f"streak:{self.source_type}:{obj_id}"

    @property
    def target_id(self):
        return self.target.pk if self.target else None

    @property
    def device_id(self):
        return self.device.pk if self.device else None

    @property
    def interface_id(self):
        return self.interface.pk if self.interface else None

    def event_filter(self) -> dict:
        return {
            "source_type": self.source_type,
            "target_id": self.target_id,
            "device_id": self.device_id,
            "interface_id": self.interface_id,
        }


@dataclass
class EventOutcome:
    """这一拍事件表发生的变化,交给调用方决定要不要推送。"""

    opened: list[Event] = field(default_factory=list)
    resolved: list[Event] = field(default_factory=list)
    escalated: list[Event] = field(default_factory=list)


def process(source: EventSource, problems: list[dict]) -> EventOutcome:
    """
    problems 是 evaluate() 给出的当前问题清单,形如
        [{"kind","severity","value","threshold","unit","message"}, ...]
    空列表表示这一拍全好。
    """

    outcome = EventOutcome()
    now = timezone.now()
    active = {p["kind"]: p for p in problems}

    open_events = {
        e.kind: e
        for e in Event.objects.filter(resolved_at__isnull=True, **source.event_filter())
    }

    key = source.cache_key
    streaks: dict = cache.get(key) or {}

    for kind in set(active) | set(open_events):
        st = streaks.setdefault(kind, {"fail": 0, "ok": 0})
        problem = active.get(kind)
        existing = open_events.get(kind)

        if problem is not None:
            st["fail"] += 1
            st["ok"] = 0
            if existing is not None:
                if _update_open_event(existing, problem, now):
                    outcome.escalated.append(existing)
            elif st["fail"] >= source.fail_threshold:
                created = _open_event(source, kind, problem, now, st["fail"])
                if created is not None:
                    outcome.opened.append(created)
        else:
            st["ok"] += 1
            st["fail"] = 0
            if existing is not None and st["ok"] >= source.recover_threshold:
                _resolve_event(existing, now)
                outcome.resolved.append(existing)
                # 恢复之后计数归零,否则下次故障要"多攒几拍"才开
                streaks.pop(kind, None)

    cache.set(key, streaks, _STREAK_TTL)
    return outcome


def _open_event(source: EventSource, kind: str, problem: dict, now, fail_count: int) -> Event | None:
    label = EventKind(kind).label if kind in EventKind.values else kind
    title = f"{source.name} {label}"
    try:
        with transaction.atomic():
            return Event.objects.create(
                **source.event_filter(),
                kind=kind,
                severity=problem.get("severity", Severity.WARNING),
                title=title[:200],
                message=problem.get("message", ""),
                started_at=now,
                trigger_value=problem.get("value"),
                threshold=problem.get("threshold"),
                unit=problem.get("unit", ""),
                fail_count=fail_count,
            )
    except IntegrityError:
        # 撞上了那条部分唯一索引 —— 说明另一个 worker 刚刚开了同一条事件。
        # 这是并发下的正常结果,不是错误:那条事件已经存在,这里什么都不用做。
        log.debug("事件已由并发的采集开出: %s %s", source.name, kind)
        return None


def _update_open_event(event: Event, problem: dict, now) -> bool:
    """
    刷新一条未恢复事件。返回是否发生了**级别升级** —— 升级要重新推送一次,
    因为"警告变严重"是值班的人需要知道的新信息。
    """

    fields = ["fail_count", "message"]
    event.fail_count += 1
    event.message = problem.get("message", event.message)

    new_sev = problem.get("severity", event.severity)
    escalated = _SEVERITY_RANK.get(new_sev, 0) > _SEVERITY_RANK.get(event.severity, 0)
    if escalated:
        event.severity = new_sev
        event.threshold = problem.get("threshold", event.threshold)
        # 重新推一次:把 notified_alert 放回 False,由通知任务再发一遍
        event.notified_alert = False
        fields += ["severity", "threshold", "notified_alert"]

    # 触发值取"最差的那个",不是最新的 —— 事后看事件要知道最坏到了什么程度
    value = problem.get("value")
    if value is not None and (event.trigger_value is None or value > event.trigger_value):
        event.trigger_value = value
        fields.append("trigger_value")

    event.save(update_fields=fields)
    return escalated


def _resolve_event(event: Event, now) -> None:
    event.resolved_at = now
    event.duration_s = max(0, int((now - event.started_at).total_seconds()))
    event.save(update_fields=["resolved_at", "duration_s"])


def force_resolve(event: Event, reason: str) -> None:
    """
    外部原因关闭事件(线路被停用/删除、设备下线)。

    和自然恢复分开是有意的:这不是"故障好了",而是"不再观测了"。
    备注里写明原因,否则事后看到一条 duration 很短的恢复会误判成误报。
    """

    now = timezone.now()
    event.resolved_at = now
    event.duration_s = max(0, int((now - event.started_at).total_seconds()))
    event.note = (event.note + "\n" if event.note else "") + f"[系统关闭] {reason}"
    # 不推恢复通知 —— 没人在等一条"因为你把它删了所以它好了"的消息
    event.notified_recover = True
    event.save(update_fields=["resolved_at", "duration_s", "note", "notified_recover"])
