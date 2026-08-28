"""
推送派发:一个事件 → 所有匹配的渠道。

**每个渠道独立 try,一个渠道挂掉不影响其它渠道** —— 这是这个文件存在的
主要理由。Telegram 在内网经常连不上,不能因为它把 Webhook 也拖住。
"""

from __future__ import annotations

import logging
import time

from django.utils import timezone

from netcheck.models import Event, Notifier, NotifierKind, NotifyLog

from . import telegram, webhook
from .base import render, should_send

log = logging.getLogger("netcheck.notify")


def notify_event(event: Event, phase: str) -> dict:
    """
    phase: "alert" | "recover"。返回统计,给 Celery 任务日志用。

    发完之后回写 event.notified_alert / notified_recover —— 这两个标记
    保证重试的任务不会重复发同一条(静默窗口是第二道防线)。
    """

    message = render(event, phase)
    stats = {"sent": 0, "failed": 0, "skipped": 0}

    notifiers = Notifier.objects.filter(enabled=True).prefetch_related("groups")
    for notifier in notifiers:
        allowed, reason = should_send(notifier, event, phase)
        if not allowed:
            stats["skipped"] += 1
            NotifyLog.objects.create(
                notifier=notifier, event=event, phase=phase,
                status=NotifyLog.Status.SKIPPED, detail=reason,
            )
            continue

        started = time.perf_counter()
        try:
            if notifier.kind == NotifierKind.TELEGRAM:
                ok, code, detail = telegram.send(notifier, message)
            elif notifier.kind == NotifierKind.WEBHOOK:
                ok, code, detail = webhook.send(notifier, message)
            else:
                ok, code, detail = False, None, f"未实现的渠道类型 {notifier.kind}"
        except Exception as exc:  # noqa: BLE001 —— 一个渠道的意外不能中断其它渠道
            log.exception("渠道 %s 推送异常", notifier.name)
            ok, code, detail = False, None, f"{type(exc).__name__}: {exc}"

        duration_ms = int((time.perf_counter() - started) * 1000)
        NotifyLog.objects.create(
            notifier=notifier, event=event, phase=phase,
            status=NotifyLog.Status.SUCCESS if ok else NotifyLog.Status.FAILED,
            http_status=code, duration_ms=duration_ms, detail=detail[:2000],
        )

        fields = ["last_error"]
        if ok:
            stats["sent"] += 1
            notifier.total_sent += 1
            notifier.last_sent_at = timezone.now()
            notifier.last_error = ""
            fields += ["total_sent", "last_sent_at"]
        else:
            stats["failed"] += 1
            notifier.total_failed += 1
            notifier.last_error = detail[:255]
            fields += ["total_failed"]
        notifier.save(update_fields=fields)

    # 只要有一个渠道成功就算推过了。全失败则保持 False,让重试任务再试 ——
    # 但**跳过不算失败**:所有渠道都因为过滤跳过时,标记为已推,否则
    # 这条事件会被重试任务永久重捞。
    if stats["sent"] or (stats["failed"] == 0 and stats["skipped"] > 0):
        if phase == "alert":
            event.notified_alert = True
            event.save(update_fields=["notified_alert"])
        else:
            event.notified_recover = True
            event.save(update_fields=["notified_recover"])

    return stats


def verify_notifier(notifier: Notifier) -> tuple[bool, str]:
    """配置中心的「测试」按钮。测试不受过滤和静默窗口影响,点了就发。"""

    started = time.perf_counter()
    try:
        if notifier.kind == NotifierKind.TELEGRAM:
            ok, detail = telegram.verify(notifier)
        elif notifier.kind == NotifierKind.WEBHOOK:
            ok, detail = webhook.verify(notifier)
        else:
            ok, detail = False, f"未实现的渠道类型 {notifier.kind}"
    except Exception as exc:  # noqa: BLE001
        ok, detail = False, f"{type(exc).__name__}: {exc}"

    NotifyLog.objects.create(
        notifier=notifier, event=None, phase="test",
        status=NotifyLog.Status.SUCCESS if ok else NotifyLog.Status.FAILED,
        duration_ms=int((time.perf_counter() - started) * 1000), detail=detail[:2000],
    )
    notifier.last_error = "" if ok else detail[:255]
    notifier.save(update_fields=["last_error"])
    return ok, detail
