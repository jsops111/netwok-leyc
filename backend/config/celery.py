"""
Celery 入口。

拨测的调度不走 beat 的 crontab —— 每条线路频率不同(可低到 1 秒),
beat 只负责每 NETCHECK_TICK_SECONDS 秒敲一次 `netcheck.tick`,
由派发器查 Redis 里的到期表决定这一拍要打哪些目标。见 netcheck/scheduler.py。
"""

from __future__ import annotations

import os

from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("netcheck")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


@app.on_after_finalize.connect
def setup_periodic_tasks(sender, **kwargs):
    from django.conf import settings

    tick = max(1, int(settings.NETCHECK_TICK_SECONDS))

    # 拨测派发器:每 tick 秒一次
    sender.add_periodic_task(
        float(tick), dispatch_due.s(), name="拨测派发(每 %ds)" % tick, expires=tick
    )
    # 设备采集派发器:设备采集最快也是 10s 级,单独一拍省得和拨测抢 worker
    sender.add_periodic_task(
        10.0, dispatch_devices.s(), name="设备采集派发(每 10s)", expires=10
    )
    # 服务器采集派发器:最快 15s 一拍(每次一个完整 SSH 握手),
    # 10 秒敲一次派发足够,和设备同一档
    sender.add_periodic_task(
        10.0, dispatch_servers.s(), name="服务器采集派发(每 10s)", expires=10
    )
    # 带外(iDRAC)派发器。最快 60 秒一拍 —— **BMC 是一颗很弱的处理器**,
    # 打太勤会把它自己拖慢,严重时管理界面登不进去,而那正是出事时要用的
    # 东西。所以派发器 30 秒敲一次就够(真正的间隔由每台自己的到期时间定)
    sender.add_periodic_task(
        30.0, dispatch_idrac.s(), name="带外采集派发(每 30s)", expires=28
    )
    # 配置备份派发器。备份间隔是**小时级**,所以派发器一分钟敲一次就够 ——
    # 敲得更勤只是多几次 Redis 查询,而"最多迟一分钟"对一天一次的备份
    # 完全无感。expires=55 保证 worker 堵住时这一拍会被丢掉而不是堆积
    sender.add_periodic_task(
        60.0, dispatch_backups.s(), name="配置备份派发(每 60s)", expires=55
    )
    # 防火墙策略同步派发器。同上,策略同步间隔最短 5 分钟
    sender.add_periodic_task(
        60.0, dispatch_policies.s(), name="防火墙策略同步派发(每 60s)", expires=55
    )
    # 分钟级降采样:每分钟把上一分钟的原始点压成 1m 桶
    sender.add_periodic_task(
        crontab(minute="*"), rollup_minute.s(), name="1m 降采样", expires=55
    )
    # 5m / 1h 桶由 1m 桶再聚合,错开整分钟触发避免和上面撞车
    sender.add_periodic_task(
        crontab(minute="*/5"), rollup_coarse.s(), name="5m/1h 降采样", expires=280
    )
    # 过期原始样本清理
    sender.add_periodic_task(
        crontab(minute="17"), purge_raw.s(), name="清理过期原始样本"
    )
    # 卡住的事件复核:探测停了或线路被删,事件不能永远挂着
    sender.add_periodic_task(
        crontab(minute="*/5"), reap_events.s(), name="事件超时复核"
    )


# 这些 shim 只为让 add_periodic_task 拿到签名;真正实现在 netcheck.tasks,
# 在这里 import 会在 Django app 就绪前触发模型加载,所以延迟到调用时。
@app.task(name="netcheck.dispatch_due")
def dispatch_due():
    from netcheck.tasks import dispatch_due_probes

    return dispatch_due_probes()


@app.task(name="netcheck.dispatch_devices")
def dispatch_devices():
    from netcheck.tasks import dispatch_due_devices

    return dispatch_due_devices()


@app.task(name="netcheck.dispatch_servers")
def dispatch_servers():
    from netcheck.tasks import dispatch_due_servers

    return dispatch_due_servers()


@app.task(name="netcheck.dispatch_idrac")
def dispatch_idrac():
    from netcheck.tasks import dispatch_due_idrac

    return dispatch_due_idrac()


@app.task(name="netcheck.dispatch_backups")
def dispatch_backups():
    from netcheck.tasks import dispatch_due_backups

    return dispatch_due_backups()


@app.task(name="netcheck.dispatch_policies")
def dispatch_policies():
    from netcheck.tasks import dispatch_due_policies

    return dispatch_due_policies()


@app.task(name="netcheck.rollup_minute")
def rollup_minute():
    from netcheck.tasks import rollup_1m

    return rollup_1m()


@app.task(name="netcheck.rollup_coarse")
def rollup_coarse():
    from netcheck.tasks import rollup_5m_1h

    return rollup_5m_1h()


@app.task(name="netcheck.purge_raw")
def purge_raw():
    from netcheck.tasks import purge_raw_samples

    return purge_raw_samples()


@app.task(name="netcheck.reap_events")
def reap_events():
    from netcheck.tasks import reap_stale_events

    return reap_stale_events()
