"""
秒级拨测的派发器。

为什么不用 Celery beat 的 crontab:每条线路频率不同,最快 1 秒,而 crontab
最细只到分钟。django-celery-beat 的 IntervalSchedule 能到秒,但那是**每条
线路一个 beat 条目**,几十条线路就是几十个独立定时器,beat 自己会成为瓶颈,
而且改一条线路的频率要动 beat 的库表。

这里的做法:beat 只做一件事 —— 每 TICK_SECONDS 秒敲一次 tick。
tick 查 Redis 里的"下次该跑的时间"表,把到期的目标派发给 worker。

Redis 用 ZSET:member 是目标 id,score 是下次该跑的 unix 时间戳。
取到期项就是一次 ZRANGEBYSCORE —— 无论多少条线路都是一次查询。

调度六类东西(见 _ZSETS):拨测线路、网络设备、服务器、配置备份、策略同步、带外(iDRAC)。
后两类的周期是小时/分钟级,但机制完全一样 —— 每台设备自己的间隔用
crontab 表达不出来,而"每台一个 beat 条目"正是这个文件一开始要避免的东西。

**不追赶。**如果 worker 堵了三十秒,到期的目标只跑一次,不会为了补上
错过的三十拍连发三十次 —— 那只会把 worker 彻底打死,而且补出来的数据点
时间戳全是"现在",在图上是一根垂直线,没有意义。
"""

from __future__ import annotations

import logging
import time

import redis
from django.conf import settings

log = logging.getLogger("netcheck.scheduler")

# 每一类被调度的东西一张到期表。**加一类要在这里补一行** ——
# 拿不认识的 kind 去查会抛 KeyError,那比静默共用一张表好:
# 共用的话两类的 id 会互相覆盖(线路 3 和服务器 3 是同一个 member)。
_ZSETS = {
    "probe": "netcheck:sched:probe",
    "device": "netcheck:sched:device",
    "server": "netcheck:sched:server",
    # 配置备份和策略同步也走同一套到期表。它们的周期是**小时/分钟级**,
    # 和采集不是一个量级,但机制完全一样:一张 ZSET + 一次 ZRANGEBYSCORE。
    # 单独做一套定时器(或者塞进 beat 的 crontab)只会多一处要维护的东西,
    # 而且 crontab 表达不出"每台设备自己的间隔"
    "backup": "netcheck:sched:backup",
    "policy": "netcheck:sched:policy",
    # 带外(iDRAC)。周期是分钟级,和备份/策略同步一样 —— **不是**因为它
    # 不重要,而是因为 BMC 是一颗很弱的处理器,打太勤会把它自己拖慢
    "idrac": "netcheck:sched:idrac",
}

# 正在执行的目标,防止上一拍还没跑完就又派一次(慢线路 + 高频率的组合)。
# 值是开始时间,用来清理僵尸锁。
_HASH_INFLIGHT = "netcheck:sched:inflight"


def _client() -> redis.Redis:
    # decode_responses=True:ZSET 的 member 是目标 id,当字符串处理最省事
    return redis.Redis(
        host=settings.REDIS_HOST, port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD or None,
        db=settings.NETCHECK_CACHE_DB, decode_responses=True,
    )


def _zset(kind: str) -> str:
    try:
        return _ZSETS[kind]
    except KeyError:
        raise ValueError(
            f"未知的调度类别 {kind!r},可用:{sorted(_ZSETS)}。"
            "加一类要在 scheduler._ZSETS 里补一行"
        ) from None


def take_due(kind: str, limit: int = 500) -> list[int]:
    """
    取出所有到期的目标 id,并**立刻**把它们的下次时间推后一个占位量。

    推后是为了避免同一个目标在这一拍被两个 tick 同时取走(tick 之间会重叠:
    上一个 tick 还在派发,下一个已经醒了)。真正的下次时间由 reschedule()
    在任务派发时按目标自己的频率写回。占位量取 5 秒 —— 派发本身远快于此。
    """

    client = _client()
    now = time.time()
    key = _zset(kind)

    due = client.zrangebyscore(key, "-inf", now, start=0, num=limit)
    if not due:
        return []

    pipe = client.pipeline()
    for member in due:
        pipe.zadd(key, {member: now + 5})
    pipe.execute()

    return [int(m) for m in due if m.isdigit()]


def reschedule(kind: str, obj_id: int, interval_seconds: int) -> None:
    """
    写回下次执行时间。

    基准是**现在**而不是"上次应该执行的时间" —— 后者在积压时会导致一连串
    立即到期的任务(和"不追赶"那条原则冲突)。代价是长期看频率会略有漂移
    (每拍多出派发耗时),对监控来说完全可以接受。
    """

    interval = max(1, int(interval_seconds))
    _client().zadd(_zset(kind), {str(obj_id): time.time() + interval})


def schedule_now(kind: str, obj_id: int) -> None:
    """让目标在下一拍立即执行 —— 新建/启用/改了频率时用。"""

    _client().zadd(_zset(kind), {str(obj_id): time.time()})


def unschedule(kind: str, obj_id: int) -> None:
    client = _client()
    client.zrem(_zset(kind), str(obj_id))
    client.hdel(_HASH_INFLIGHT, f"{kind}:{obj_id}")


def sync_schedule(kind: str, enabled_ids: list[int]) -> dict:
    """
    把 ZSET 和数据库对齐:补上没排期的,删掉已停用/已删除的。

    tick 每次都会调它 —— 这是"改了配置立刻生效"和"重启 Redis 也能自愈"的
    保证。**不要改成只在启动时同步**:那样在页面上新建一条线路要等到下次
    重启才开始探测。
    """

    client = _client()
    key = _zset(kind)
    current = set(client.zrange(key, 0, -1))
    wanted = {str(i) for i in enabled_ids}

    added = wanted - current
    removed = current - wanted

    if added:
        now = time.time()
        # 新目标错开首次执行时间,别让十条线路在同一毫秒一起打出去
        client.zadd(key, {member: now + (idx % 10) * 0.1 for idx, member in enumerate(added)})
    if removed:
        client.zrem(key, *removed)
        client.hdel(_HASH_INFLIGHT, *[f"{kind}:{m}" for m in removed])

    return {"added": len(added), "removed": len(removed), "total": len(wanted)}


def mark_inflight(kind: str, obj_id: int, ttl_seconds: int = 300) -> bool:
    """
    标记开始执行。返回 False 表示上一次还在跑,这一拍应该跳过。

    僵尸锁清理:超过 ttl 的锁直接抢占 —— worker 被 kill 掉时锁不会自己消失,
    没有这一步那条线路会永久停止探测。
    """

    client = _client()
    field = f"{kind}:{obj_id}"
    started = client.hget(_HASH_INFLIGHT, field)
    now = time.time()

    if started is not None:
        try:
            if now - float(started) < ttl_seconds:
                return False
        except ValueError:
            pass  # 值坏了,当成没锁

    client.hset(_HASH_INFLIGHT, field, now)
    return True


def clear_inflight(kind: str, obj_id: int) -> None:
    _client().hdel(_HASH_INFLIGHT, f"{kind}:{obj_id}")


def stats() -> dict:
    """给大屏的"调度健康度"用:排了多少、有多少已经迟到。"""

    client = _client()
    now = time.time()
    out = {}
    for kind, key in _ZSETS.items():
        # 迟到的判定按类别分开:拨测迟到 3 秒就该说话(它可能是每秒一拍),
        # 而备份是小时级的,迟到 3 秒毫无意义 —— 用同一个阈值会让
        # 「调度健康度」上永远挂着几条备份"迟到",把真正的告警淹掉
        grace = 3 if kind in ("probe", "device", "server") else 300
        out[kind] = {
            "scheduled": client.zcard(key),
            "overdue": client.zcount(key, "-inf", now - grace),
        }
    out["inflight"] = client.hlen(_HASH_INFLIGHT)
    return out
