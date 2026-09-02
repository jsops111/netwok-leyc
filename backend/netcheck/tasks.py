"""
Celery 任务。

分四类:
    派发      dispatch_due_* —— beat 每拍调用,共五类:
              线路 / 设备 / 服务器 / 配置备份 / 防火墙策略
    执行      run_probe / collect_device_task / collect_server_task /
              backup_device_task / sync_policies_task —— 一个目标一个任务
    聚合清理  rollup_1m / rollup_5m_1h / purge_raw_samples
    通知      send_notification / retry_pending_notifications

**执行任务必须是"单目标"的**:一个任务里循环采所有线路的话,一条慢线路
会拖住后面所有线路,而且失败重试会把已经成功的重跑一遍。

**备份和策略同步不调 event_engine.process()。**process() 的语义是"这一拍
观测到的全部问题",没出现在 problems 里的未恢复事件会被它当成已恢复 ——
拿一个只含 backup_failed 的 problems 去调用,这台设备上正开着的
cpu_high / device_down 会被一起关掉。它们用 record_point_event()
记瞬时事件,见 events/engine.py 里那段说明。
"""

from __future__ import annotations

import logging
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.utils import timezone

from netcheck import scheduler
from netcheck.events import engine as event_engine
from netcheck.models import (
    BackupStatus,
    Device,
    DeviceKind,
    Event,
    EventKind,
    LinkState,
    ProbeRollup,
    ProbeSample,
    ProbeTarget,
    RollupBucket,
    Server,
    Severity,
)
from netcheck.probes import runner

log = logging.getLogger("netcheck.tasks")


# =========================================================================
# 派发
# =========================================================================


@shared_task(name="netcheck.dispatch_due_probes")
def dispatch_due_probes() -> dict:
    enabled_ids = list(ProbeTarget.objects.filter(enabled=True).values_list("id", flat=True))
    sync = scheduler.sync_schedule("probe", enabled_ids)

    due = scheduler.take_due("probe", limit=1000)
    dispatched = 0
    for target_id in due:
        if scheduler.mark_inflight("probe", target_id):
            run_probe.delay(target_id)
            dispatched += 1
        # 派不出去(上一拍还在跑)也要重排,否则这条线路会从 ZSET 里消失
        # ——take_due 已经把它推后 5 秒,这里按真实频率覆盖
    return {"due": len(due), "dispatched": dispatched, **sync}


@shared_task(name="netcheck.dispatch_due_devices")
def dispatch_due_devices() -> dict:
    enabled_ids = list(Device.objects.filter(enabled=True).values_list("id", flat=True))
    sync = scheduler.sync_schedule("device", enabled_ids)

    due = scheduler.take_due("device", limit=200)
    dispatched = 0
    for device_id in due:
        if scheduler.mark_inflight("device", device_id, ttl_seconds=600):
            collect_device_task.delay(device_id)
            dispatched += 1
    return {"due": len(due), "dispatched": dispatched, **sync}


@shared_task(name="netcheck.dispatch_due_servers")
def dispatch_due_servers() -> dict:
    enabled_ids = list(Server.objects.filter(enabled=True).values_list("id", flat=True))
    sync = scheduler.sync_schedule("server", enabled_ids)

    due = scheduler.take_due("server", limit=200)
    dispatched = 0
    for server_id in due:
        # 服务器采集是一次完整的 SSH 握手,慢的机器上要好几秒。
        # inflight 的 ttl 给到 10 分钟 —— 比最坏情况宽裕得多,
        # 而给短了会在上一拍还没结束时又派一次,同一台机器被并发登录
        if scheduler.mark_inflight("server", server_id, ttl_seconds=600):
            collect_server_task.delay(server_id)
            dispatched += 1
    return {"due": len(due), "dispatched": dispatched, **sync}


@shared_task(name="netcheck.dispatch_due_backups")
def dispatch_due_backups() -> dict:
    """
    配置备份的派发。**只看 backup_enabled,不看 collect_method** ——
    一台走 SNMP 采指标的交换机照样可以备份配置(备份走 SSH)。
    """

    enabled_ids = list(
        Device.objects.filter(enabled=True, backup_enabled=True).values_list("id", flat=True)
    )
    sync = scheduler.sync_schedule("backup", enabled_ids)

    due = scheduler.take_due("backup", limit=100)
    dispatched = 0
    for device_id in due:
        # 一份 running-config 走 SSH 读完可能几十秒,大配置更久 ——
        # ttl 给 30 分钟。给短了会让同一台设备被两个 worker 同时备份,
        # 而那会在同一秒产生两个"新版本"(第二个的 diff 是空的)
        if scheduler.mark_inflight("backup", device_id, ttl_seconds=1800):
            backup_device_task.delay(device_id)
            dispatched += 1
    return {"due": len(due), "dispatched": dispatched, **sync}


@shared_task(name="netcheck.dispatch_due_policies")
def dispatch_due_policies() -> dict:
    enabled_ids = list(
        Device.objects.filter(
            enabled=True, policy_sync_enabled=True, kind=DeviceKind.FIREWALL
        ).values_list("id", flat=True)
    )
    sync = scheduler.sync_schedule("policy", enabled_ids)

    due = scheduler.take_due("policy", limit=100)
    dispatched = 0
    for device_id in due:
        if scheduler.mark_inflight("policy", device_id, ttl_seconds=900):
            sync_policies_task.delay(device_id)
            dispatched += 1
    return {"due": len(due), "dispatched": dispatched, **sync}


# =========================================================================
# 执行
# =========================================================================


@shared_task(name="netcheck.run_probe", bind=True, max_retries=0)
def run_probe(self, target_id: int) -> dict:
    """
    拨测一条线路。

    max_retries=0 是有意的:拨测失败**本身就是要记录的结果**,不是需要重试的
    错误。重试会污染数据 —— 一次超时重试三次成功,记下来的是"通",而真实
    情况是这条线路当时不稳。
    """

    try:
        target = ProbeTarget.objects.select_related("group").get(pk=target_id, enabled=True)
    except ProbeTarget.DoesNotExist:
        scheduler.unschedule("probe", target_id)
        return {"skipped": "线路不存在或已停用"}

    try:
        result = runner.execute(target)
        state, problems = runner.evaluate(target, result)
        now = timezone.now()

        ProbeSample.objects.create(
            target=target, ts=now, ok=result.ok,
            rtt_ms=result.rtt_ms, rtt_min_ms=result.rtt_min_ms, rtt_max_ms=result.rtt_max_ms,
            loss_pct=result.loss_pct, jitter_ms=result.jitter_ms, state=state,
            error_kind=result.error_kind[:32], error=result.error[:255],
        )

        target.state = state
        target.last_checked_at = now
        target.last_rtt_ms = result.rtt_ms
        target.last_loss_pct = result.loss_pct
        target.last_jitter_ms = result.jitter_ms
        target.last_error = result.error[:255]
        target.total_checks += 1
        if state == LinkState.DOWN or not result.ok:
            target.total_fail += 1
            target.consecutive_fail += 1
            target.consecutive_ok = 0
        else:
            target.consecutive_ok += 1
            target.consecutive_fail = 0
        target.save(update_fields=[
            "state", "last_checked_at", "last_rtt_ms", "last_loss_pct", "last_jitter_ms",
            "last_error", "total_checks", "total_fail", "consecutive_fail", "consecutive_ok",
        ])

        outcome = event_engine.process(event_engine.EventSource.from_target(target), problems)
        for event in outcome.opened + outcome.escalated:
            send_notification.delay(event.pk, "alert")
        for event in outcome.resolved:
            send_notification.delay(event.pk, "recover")

        return {
            "target": target.name, "state": state, "rtt": result.rtt_ms,
            "loss": result.loss_pct, "opened": len(outcome.opened), "resolved": len(outcome.resolved),
        }
    finally:
        # 无论成败都要解锁并重排,否则这条线路就此停摆
        scheduler.clear_inflight("probe", target_id)
        scheduler.reschedule("probe", target_id, target.interval_seconds)


@shared_task(name="netcheck.collect_device", bind=True, max_retries=0)
def collect_device_task(self, device_id: int) -> dict:
    from netcheck.devices import collector

    try:
        device = Device.objects.get(pk=device_id, enabled=True)
    except Device.DoesNotExist:
        scheduler.unschedule("device", device_id)
        return {"skipped": "设备不存在或已停用"}

    try:
        sample = collector.collect_device(device)
        return {
            "device": device.name, "reachable": sample.reachable,
            "method": sample.method, "cpu": sample.cpu_pct, "mem": sample.mem_pct,
        }
    finally:
        scheduler.clear_inflight("device", device_id)
        scheduler.reschedule("device", device_id, device.interval_seconds)


@shared_task(name="netcheck.collect_server", bind=True, max_retries=0)
def collect_server_task(self, server_id: int) -> dict:
    """
    采一台服务器。

    `max_retries=0` 和拨测同一个理由:**采集失败本身就是要记录的结果**。
    重试会污染数据 —— 一次 SSH 超时重试三次成功,记下来的是"可达",
    而真实情况是这台机器当时登不上去。
    """

    from netcheck.servers import collector

    try:
        server = Server.objects.get(pk=server_id, enabled=True)
    except Server.DoesNotExist:
        scheduler.unschedule("server", server_id)
        return {"skipped": "服务器不存在或已停用"}

    try:
        sample = collector.collect_server(server)
        return {
            "server": server.name, "reachable": sample.reachable,
            "cpu": sample.cpu_pct, "mem": sample.mem_pct, "disk": sample.disk_pct,
            "load1": sample.load1,
        }
    finally:
        # 少一个这条服务器就此停摆 —— 和 run_probe 的 finally 同一条规矩
        scheduler.clear_inflight("server", server_id)
        scheduler.reschedule("server", server_id, server.interval_seconds)


# =========================================================================
# 配置备份 / 策略同步
# =========================================================================

# 备份失败后多久重试。**不用整个备份间隔**:间隔通常是 24 小时,
# 一次网络抖动就意味着这台设备一天没有备份 —— 那正是备份最不该有的性质。
# 也不做 Celery 的 retry:那条链路在 worker 重启后就断了,而"下次什么时候
# 再试"这件事本来就该由到期表来管。
_BACKUP_RETRY_SECONDS = 1800
# 同一台设备的备份失败事件的去重窗口。一台配置错误的设备会每 30 分钟失败
# 一次,不去重就是一天 48 条一模一样的事件
_BACKUP_EVENT_DEDUPE = 6 * 3600


@shared_task(name="netcheck.backup_device", bind=True, max_retries=0)
def backup_device_task(self, device_id: int) -> dict:
    """
    备份一台设备的配置。

    成功后**只有配置真的变了**才记一条 config_changed 事件(info 级) ——
    每天一条"配置没变"的事件毫无信息量,而事件表是要被人读的。
    失败记 backup_failed(warning 级,默认会被推送):
    一个悄悄坏掉的备份等于没有备份,而这件事只有告警能让人知道。
    """

    from netcheck.devices import backup as backup_mod
    from netcheck.events import engine as engine_mod

    try:
        device = Device.objects.get(pk=device_id, enabled=True, backup_enabled=True)
    except Device.DoesNotExist:
        scheduler.unschedule("backup", device_id)
        return {"skipped": "设备不存在、已停用或未开启备份"}

    now = timezone.now()
    next_interval = device.backup_interval_hours * 3600
    try:
        result = backup_mod.backup_device(device)

        device.last_backup_at = now
        device.last_backup_status = BackupStatus.OK
        device.last_backup_error = ""
        device.save(update_fields=["last_backup_at", "last_backup_status", "last_backup_error"])

        if result["changed"] and not result.get("is_first"):
            event = engine_mod.record_point_event(
                engine_mod.EventSource.from_device(device),
                EventKind.CONFIG_CHANGED,
                # info 级:配置变更是**记录**,不是故障。默认渠道的最低级别是
                # warning,所以它不会被推送出去 —— 想收推送就把渠道的
                # 「最低级别」调到 info
                Severity.INFO,
                title=f"{device.name} 配置发生变更",
                message=(
                    f"新增 {result.get('lines_added')} 行 / 删除 {result.get('lines_removed')} 行"
                    f"(通道 {result['method'].upper()},版本 {result['hash'][:12]})"
                ),
            )
            if event is not None:
                send_notification.delay(event.pk, "alert")

        return {"device": device.name, **result}

    except Exception as exc:  # noqa: BLE001 —— 备份失败要记录,不能让任务炸掉
        error = str(exc) if isinstance(exc, backup_mod.BackupError) else f"{type(exc).__name__}: {exc}"
        if not isinstance(exc, backup_mod.BackupError):
            log.exception("设备 %s 备份异常", device.name)
        else:
            log.warning("设备 %s 备份失败: %s", device.name, error)

        device.last_backup_status = BackupStatus.FAILED
        device.last_backup_error = error[:255]
        device.save(update_fields=["last_backup_status", "last_backup_error"])

        event = engine_mod.record_point_event(
            engine_mod.EventSource.from_device(device),
            EventKind.BACKUP_FAILED, Severity.WARNING,
            title=f"{device.name} 配置备份失败",
            message=error[:500],
            dedupe_seconds=_BACKUP_EVENT_DEDUPE,
        )
        if event is not None:
            send_notification.delay(event.pk, "alert")

        # 失败就换成短间隔重试,不等下一个整周期
        next_interval = min(next_interval, _BACKUP_RETRY_SECONDS)
        return {"device": device.name, "error": error}
    finally:
        scheduler.clear_inflight("backup", device_id)
        scheduler.reschedule("backup", device_id, next_interval)


@shared_task(name="netcheck.sync_policies", bind=True, max_retries=0)
def sync_policies_task(self, device_id: int) -> dict:
    """
    同步一台防火墙的策略快照。

    失败**不记事件**:策略同步失败不是网络故障,而设备连不上这件事
    device_down 已经报过了 —— 再记一条只是把同一件事说两遍。
    失败原因写在 Device.last_policy_error 上,页面顶部会显示。
    """

    from netcheck.devices import policies

    try:
        device = Device.objects.get(pk=device_id, enabled=True, policy_sync_enabled=True)
    except Device.DoesNotExist:
        scheduler.unschedule("policy", device_id)
        return {"skipped": "设备不存在、已停用或未开启策略同步"}

    interval = device.policy_sync_interval_minutes * 60
    try:
        result = policies.sync_policies(device)
        return {"device": device.name, **result}
    except Exception as exc:  # noqa: BLE001
        error = str(exc) if isinstance(exc, policies.PolicyError) else f"{type(exc).__name__}: {exc}"
        if not isinstance(exc, policies.PolicyError):
            log.exception("设备 %s 策略同步异常", device.name)
        else:
            log.info("设备 %s 策略同步失败: %s", device.name, error)
        # **不清空已有快照。**同步失败时页面上要还能看上一次的规则
        # (标明"数据截止于什么时候")—— 防火墙连不上恰恰是最需要查规则的时候
        device.last_policy_error = error[:255]
        device.save(update_fields=["last_policy_error"])
        return {"device": device.name, "error": error}
    finally:
        scheduler.clear_inflight("policy", device_id)
        scheduler.reschedule("policy", device_id, interval)


# =========================================================================
# 通知
# =========================================================================


@shared_task(name="netcheck.send_notification", bind=True, max_retries=3, default_retry_delay=60)
def send_notification(self, event_id: int, phase: str) -> dict:
    from netcheck.notify import dispatch

    try:
        event = Event.objects.select_related("target", "device", "interface__device").get(pk=event_id)
    except Event.DoesNotExist:
        return {"skipped": "事件已删除"}

    # 已推过就不重复推。escalate 时 notified_alert 被置回 False,所以升级
    # 能再推一次 —— 这个开关就是幂等的边界。
    if phase == "alert" and event.notified_alert:
        return {"skipped": "该事件的告警已推送过"}
    if phase == "recover" and event.notified_recover:
        return {"skipped": "该事件的恢复已推送过"}

    stats = dispatch.notify_event(event, phase)
    # 全部渠道都失败才重试 —— 部分成功重试会给成功的渠道再发一遍
    if stats["failed"] and not stats["sent"] and self.request.retries < self.max_retries:
        raise self.retry(countdown=60 * (self.request.retries + 1))
    return stats


@shared_task(name="netcheck.retry_pending_notifications")
def retry_pending_notifications() -> dict:
    """
    捞回没推出去的事件。

    Celery 的重试链断掉(worker 重启、重试次数用尽)时,事件会永远停在
    notified=False。这个任务是最后一道网 —— 只捞最近 6 小时的,
    更早的没推出去也没意义了,那时候值班的人早就从别的渠道知道了。
    """

    since = timezone.now() - timedelta(hours=6)
    pending_alerts = Event.objects.filter(started_at__gte=since, notified_alert=False)
    pending_recovers = Event.objects.filter(
        resolved_at__isnull=False, resolved_at__gte=since, notified_recover=False
    )
    count = 0
    for event in pending_alerts[:200]:
        send_notification.delay(event.pk, "alert")
        count += 1
    for event in pending_recovers[:200]:
        send_notification.delay(event.pk, "recover")
        count += 1
    return {"requeued": count}


# =========================================================================
# 聚合与清理
# =========================================================================


def _percentile(values: list[float], pct: float) -> float | None:
    """
    最近邻插值的百分位。不引 numpy —— 一个桶里最多几百个点,
    为这点计算量加一个几十兆的依赖不值得。
    """
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 3)
    idx = min(len(ordered) - 1, max(0, round(pct / 100 * (len(ordered) - 1))))
    return round(ordered[idx], 3)


@shared_task(name="netcheck.rollup_1m")
def rollup_1m() -> dict:
    """
    把上一分钟的原始样本压成 1m 桶。

    只处理**已经结束的**分钟(上一分钟),不碰当前分钟 —— 当前分钟还在写入,
    聚合出来的桶是不完整的,而 upsert 会让它看起来像完整的。
    """

    now = timezone.now().replace(second=0, microsecond=0)
    bucket_start = now - timedelta(minutes=1)
    bucket_end = now

    written = 0
    target_ids = ProbeSample.objects.filter(
        ts__gte=bucket_start, ts__lt=bucket_end
    ).values_list("target_id", flat=True).distinct()

    for target_id in target_ids:
        samples = list(
            ProbeSample.objects.filter(target_id=target_id, ts__gte=bucket_start, ts__lt=bucket_end)
            .values_list("ok", "rtt_ms", "loss_pct", "jitter_ms")
        )
        if not samples:
            continue

        rtts = [s[1] for s in samples if s[1] is not None]
        jitters = [s[3] for s in samples if s[3] is not None]
        losses = [s[2] or 0 for s in samples]
        ok_count = sum(1 for s in samples if s[0])

        ProbeRollup.objects.update_or_create(
            target_id=target_id, bucket=RollupBucket.M1, ts=bucket_start,
            defaults={
                "samples": len(samples), "ok_count": ok_count,
                "fail_count": len(samples) - ok_count,
                "rtt_avg_ms": round(sum(rtts) / len(rtts), 3) if rtts else None,
                "rtt_min_ms": round(min(rtts), 3) if rtts else None,
                "rtt_max_ms": round(max(rtts), 3) if rtts else None,
                "rtt_p95_ms": _percentile(rtts, 95),
                "loss_avg_pct": round(sum(losses) / len(losses), 3),
                "loss_max_pct": round(max(losses), 3),
                "jitter_avg_ms": round(sum(jitters) / len(jitters), 3) if jitters else None,
                "jitter_max_ms": round(max(jitters), 3) if jitters else None,
            },
        )
        written += 1
    return {"bucket": bucket_start.isoformat(), "targets": written}


def _coarsen(source_bucket: str, dest_bucket: str, span: timedelta, aligned_start) -> int:
    """
    由细桶聚合成粗桶。

    **P95 是从细桶的 P95 里取最大值,不是重算。**严格的 P95 需要原始点,
    而原始点可能已经清理掉了。取细桶 P95 的最大值是保守的近似 ——
    它只会偏高不会偏低,对"最慢的时候有多慢"这个问题来说是安全的方向。
    """

    written = 0
    rows = ProbeRollup.objects.filter(
        bucket=source_bucket, ts__gte=aligned_start, ts__lt=aligned_start + span
    ).values_list("target_id", flat=True).distinct()

    for target_id in rows:
        fine = list(
            ProbeRollup.objects.filter(
                target_id=target_id, bucket=source_bucket,
                ts__gte=aligned_start, ts__lt=aligned_start + span,
            ).values(
                "samples", "ok_count", "fail_count", "rtt_avg_ms", "rtt_min_ms",
                "rtt_max_ms", "rtt_p95_ms", "loss_avg_pct", "loss_max_pct",
                "jitter_avg_ms", "jitter_max_ms",
            )
        )
        if not fine:
            continue

        total_samples = sum(f["samples"] for f in fine) or 1
        # 平均值按样本数加权 —— 直接对细桶的平均值再平均,会让一个只有
        # 两个样本的桶和一个有六十个样本的桶等权,那是错的
        def weighted(key):
            pairs = [(f[key], f["samples"]) for f in fine if f[key] is not None]
            if not pairs:
                return None
            return round(sum(v * w for v, w in pairs) / sum(w for _, w in pairs), 3)

        def pick(key, fn):
            values = [f[key] for f in fine if f[key] is not None]
            return round(fn(values), 3) if values else None

        ProbeRollup.objects.update_or_create(
            target_id=target_id, bucket=dest_bucket, ts=aligned_start,
            defaults={
                "samples": total_samples,
                "ok_count": sum(f["ok_count"] for f in fine),
                "fail_count": sum(f["fail_count"] for f in fine),
                "rtt_avg_ms": weighted("rtt_avg_ms"),
                "rtt_min_ms": pick("rtt_min_ms", min),
                "rtt_max_ms": pick("rtt_max_ms", max),
                "rtt_p95_ms": pick("rtt_p95_ms", max),
                "loss_avg_pct": weighted("loss_avg_pct") or 0,
                "loss_max_pct": pick("loss_max_pct", max) or 0,
                "jitter_avg_ms": weighted("jitter_avg_ms"),
                "jitter_max_ms": pick("jitter_max_ms", max),
            },
        )
        written += 1
    return written


@shared_task(name="netcheck.rollup_5m_1h")
def rollup_5m_1h() -> dict:
    """5m 桶每 5 分钟一次;1h 桶只在整点后的那一拍做。"""

    now = timezone.now().replace(second=0, microsecond=0)
    five = now - timedelta(minutes=now.minute % 5 or 5)
    five = five.replace(minute=five.minute - five.minute % 5)
    written_5m = _coarsen(RollupBucket.M1, RollupBucket.M5, timedelta(minutes=5), five)

    written_1h = 0
    # 整点后的第一拍(0~4 分)才聚合上一小时
    if now.minute < 5:
        hour_start = (now - timedelta(hours=1)).replace(minute=0)
        written_1h = _coarsen(RollupBucket.M5, RollupBucket.H1, timedelta(hours=1), hour_start)

    return {"5m": written_5m, "1h": written_1h}


@shared_task(name="netcheck.purge_raw_samples")
def purge_raw_samples() -> dict:
    """
    删过期原始样本。

    **分批删**:一条 1 秒频率的线路两天就是十七万行,一次 DELETE 会长时间
    持锁,而这张表同时在被高频写入。每批一万行,删到没有为止。
    接口样本和设备样本按同一保留期处理;NotifyLog 留久一点(30 天),
    它是审计材料而不是时序数据。
    """

    from netcheck.models import (
        DeviceSample,
        Event,
        InterfaceSample,
        NotifyLog,
        RetentionPolicy,
        ServerSample,
    )

    # 保留期以**库里的策略**为准,不是环境变量 —— 环境变量只在首次建行时当默认值。
    # 磁盘快满时改保留期这件事发生在半夜,那时候人只能开个页面(见 models.py)
    policy = RetentionPolicy.load()
    cutoff = timezone.now() - timedelta(hours=policy.raw_hours)
    deleted = {}

    for model, label in (
        (ProbeSample, "probe_samples"),
        (InterfaceSample, "interface_samples"),
        (DeviceSample, "device_samples"),
        # 服务器样本和设备样本同一个保留期。**它没有降采样表** ——
        # 60 秒一拍的话一台机器一天 1440 行,和秒级拨测不是一个量级,
        # 不值得为它建四张桶表。代价是能看的历史跨度就是 raw_hours,
        # 要看更久的服务器趋势得先把原始保留期调大(见「系统信息」页)
        (ServerSample, "server_samples"),
    ):
        total = 0
        while True:
            ids = list(model.objects.filter(ts__lt=cutoff).values_list("pk", flat=True)[:10000])
            if not ids:
                break
            count, _ = model.objects.filter(pk__in=ids).delete()
            total += count
            if len(ids) < 10000:
                break
        deleted[label] = total

    now = timezone.now()
    deleted["notify_logs"] = NotifyLog.objects.filter(
        ts__lt=now - timedelta(days=policy.notify_log_days)
    ).delete()[0]

    # 登录审计留得比时序数据久得多(默认 180 天)—— 它回答的是"上个季度
    # 是谁登过这台机器",而那种问题从来不在事发当周问出口
    from accounts.models import LoginAudit

    deleted["login_audit"] = LoginAudit.objects.filter(
        created_at__lt=now - timedelta(days=policy.login_audit_days)
    ).delete()[0]

    # 降采样桶。**1h 桶默认永久**(policy 里 0 = 永久)—— 一条线路一年才 8760 行,
    # 不值得清理,而它是唯一能回答"去年这条线怎么样"的东西
    for bucket, days in (
        (RollupBucket.M1, policy.rollup_1m_days),
        (RollupBucket.M5, policy.rollup_5m_days),
        (RollupBucket.H1, policy.rollup_1h_days),
    ):
        if not days:                      # 0 = 永久
            continue
        deleted[f"rollup_{bucket}"] = ProbeRollup.objects.filter(
            bucket=bucket, ts__lt=now - timedelta(days=days)
        ).delete()[0]

    # 事件默认永久(0)。它是故障复盘的材料,一条事件几百字节,
    # 不是磁盘的矛盾所在 —— 真要删也**只删已恢复的**,未恢复的事件还在用
    if policy.event_days:
        deleted["events"] = Event.objects.filter(
            resolved_at__isnull=False,
            resolved_at__lt=now - timedelta(days=policy.event_days),
        ).delete()[0]

    return {"cutoff": cutoff.isoformat(), "policy_raw_hours": policy.raw_hours, **deleted}


@shared_task(name="netcheck.reap_stale_events")
def reap_stale_events() -> dict:
    """
    复核挂着的事件。

    两种情况事件会永远开着而没人关它:
      1. 线路/设备被停用了 —— 不再采集,自然不会有"连续正常"来触发恢复
      2. 采集本身停了(worker 挂了、线路被删)

    对 1 直接强制关闭并注明原因。对 2 只记日志不动 —— 采集停了不代表
    线路好了,那种情况下自动"恢复"是危险的误报。
    """

    closed = 0
    stale_open = 0
    now = timezone.now()

    for event in Event.objects.filter(resolved_at__isnull=True).select_related(
        "target", "device", "server"
    ):
        source_disabled = False
        if event.target_id and event.target and not event.target.enabled:
            source_disabled = True
            reason = "线路已停用"
        elif event.device_id and event.device and not event.device.enabled:
            source_disabled = True
            reason = "设备已停用"
        elif event.server_id and event.server and not event.server.enabled:
            source_disabled = True
            reason = "服务器已停用"

        if source_disabled:
            event_engine.force_resolve(event, reason)
            closed += 1
            continue

        # 采集是否还在跑:最后采集时间距今超过 10 个周期就算停了
        source = event.target or event.device or event.server
        if source is None:
            continue
        last = getattr(source, "last_checked_at", None) or getattr(source, "last_collected_at", None)
        if last and (now - last).total_seconds() > source.interval_seconds * 10:
            stale_open += 1

    if stale_open:
        log.warning("有 %d 条未恢复事件的来源已长时间没有采集数据,检查 worker 是否在运行", stale_open)
    return {"force_closed": closed, "stale_sources": stale_open}
