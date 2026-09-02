"""
推送的公共部分:消息渲染、过滤、静默窗口。

**过滤在推送侧做,不在事件生成侧** —— 事件该记的照记,只是不一定推。
这样调完过滤条件回头看事件表,历史是完整的。
"""

from __future__ import annotations

from dataclasses import dataclass

from django.utils import timezone

from netcheck.models import Event, EventKind, Notifier, Severity, SourceType

_SEVERITY_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}

# 中文字段名固定在这里,Telegram 和 Webhook 两条通道用同一套措辞
_SEV_ICON = {Severity.INFO: "ℹ️", Severity.WARNING: "⚠️", Severity.CRITICAL: "🔴"}


@dataclass
class Message:
    """一条待发消息。text 给 Telegram,payload 给 Webhook,两者内容等价。"""

    title: str
    text: str
    payload: dict


def human_duration(seconds: int | None) -> str:
    if seconds is None:
        return "-"
    if seconds < 60:
        return f"{seconds}秒"
    if seconds < 3600:
        return f"{seconds // 60}分{seconds % 60}秒"
    hours, rest = divmod(seconds, 3600)
    if hours < 24:
        return f"{hours}小时{rest // 60}分"
    days, rest_h = divmod(hours, 24)
    return f"{days}天{rest_h}小时"


def should_send(notifier: Notifier, event: Event, phase: str) -> tuple[bool, str]:
    """
    要不要发。返回 (是否发送, 跳过原因)。

    静默窗口挡的是 flapping 造成的轰炸:同一条事件的同一个阶段在
    cooldown_seconds 内不重复发。**不同事件之间互不影响** —— 一次真实的
    大面积故障应该每条线路都告警,那不是轰炸。
    """

    if not notifier.enabled:
        return False, "渠道已停用"
    if phase == "alert" and not notifier.on_alert:
        return False, "该渠道未开启告警推送"
    if phase == "recover" and not notifier.on_recover:
        return False, "该渠道未开启恢复推送"

    if _SEVERITY_RANK.get(event.severity, 0) < _SEVERITY_RANK.get(notifier.min_severity, 0):
        return False, f"级别 {event.severity} 低于渠道下限 {notifier.min_severity}"

    kinds = notifier.kinds or []
    if kinds and event.kind not in kinds:
        return False, f"类型 {event.kind} 不在该渠道的推送范围"

    # 监控类过滤只对线路事件生效 —— 设备和服务器不属于任何监控类,
    # 拿"没选中"去挡它们的事件会让设备/服务器告警在配了分组的渠道上静默消失
    if event.source_type == SourceType.PROBE and event.target_id:
        allowed = list(notifier.groups.values_list("id", flat=True))
        if allowed and event.target.group_id not in allowed:
            return False, "该线路的监控类不在推送范围"

    if notifier.cooldown_seconds > 0:
        from netcheck.models import NotifyLog

        since = timezone.now() - timezone.timedelta(seconds=notifier.cooldown_seconds)
        duplicated = NotifyLog.objects.filter(
            notifier=notifier, event=event, phase=phase,
            status=NotifyLog.Status.SUCCESS, ts__gte=since,
        ).exists()
        if duplicated:
            return False, f"{notifier.cooldown_seconds}s 静默窗口内已发过同一条"

    return True, ""


def render(event: Event, phase: str) -> Message:
    """
    把事件渲染成消息。告警和恢复用同一个函数 —— 两条消息里的字段必须一致,
    否则收到恢复消息的人对不上是哪条告警。
    """

    kind_label = EventKind(event.kind).label if event.kind in EventKind.values else event.kind
    is_recover = phase == "recover"
    status_label = "已恢复" if is_recover else "告警"
    icon = "✅" if is_recover else _SEV_ICON.get(event.severity, "⚠️")
    source = event.source_name

    value_text = "-"
    if event.trigger_value is not None:
        value_text = f"{event.trigger_value:g}{event.unit}"
        if event.threshold is not None:
            value_text += f"(阈值 {event.threshold:g}{event.unit})"

    lines = [
        f"{icon} 【{status_label}】{kind_label}",
        "",
        f"对象:{source}",
        f"级别:{event.get_severity_display()}",
        f"详情:{event.message or '-'}",
        f"实测:{value_text}",
        f"发生:{timezone.localtime(event.started_at):%Y-%m-%d %H:%M:%S}",
    ]
    if is_recover and event.resolved_at:
        lines += [
            f"恢复:{timezone.localtime(event.resolved_at):%Y-%m-%d %H:%M:%S}",
            f"持续:{human_duration(event.duration_s)}",
            f"期间失败:{event.fail_count} 次",
        ]
    text = "\n".join(lines)

    payload = {
        "event_id": event.pk,
        "status": "resolved" if is_recover else "firing",
        "phase": phase,
        "severity": event.severity,
        "severity_label": event.get_severity_display(),
        "kind": event.kind,
        "kind_label": kind_label,
        "source_type": event.source_type,
        "source": source,
        "title": event.title,
        "message": event.message,
        "value": event.trigger_value,
        "threshold": event.threshold,
        "unit": event.unit,
        "fail_count": event.fail_count,
        "started_at": timezone.localtime(event.started_at).isoformat(),
        "resolved_at": timezone.localtime(event.resolved_at).isoformat() if event.resolved_at else None,
        "duration_s": event.duration_s,
        "duration": human_duration(event.duration_s),
    }
    return Message(title=f"[{status_label}] {event.title}", text=text, payload=payload)
