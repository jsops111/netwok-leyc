# CLAUDE.md

给要改这个项目的人(和模型)看的。`README.md` 讲平台做什么,这里只讲**改代码要知道的事**。
先读 README。

## 技术栈

- **后端**: Django 6.0 + DRF 3.17、`django-filter`、`django-cors-headers`、`whitenoise`
- **DB**: PostgreSQL 17 / `psycopg` 3。用了**部分唯一索引**和**表达式约束**
  (`Coalesce`),是刻意的 Postgres-only,别"移植性修复"成 Python 层校验
- **异步**: Celery 5.6 + Redis 8
- **采集**: `pysnmp` 7(asyncio)、`paramiko` 5、`requests`、`dnspython`
- **加密**: `cryptography` Fernet,包在 `core.crypto.EncryptedTextField` 里
- **前端**: Vue 3 + Vite 6 + TypeScript + Naive UI + ECharts(按需引入)

**故意没有的**:pytest、ruff/black/mypy、drf-spectacular、django-celery-beat。
加任何一个都是有意的决定 —— 说出来,不要当成漏了补上。

`backend/pyproject.toml` 是手维护的。**`uv pip install` 了什么就在同一次改动里
补进去**,否则下一个重建 venv 的人拿到一个坏环境。加新 Django app 还要在
`[tool.setuptools.packages.find]` 的 include 里补一行(不补的话新环境报
`ModuleNotFoundError`,而错误信息指不到这个文件)。

---

## 这个项目最容易出错的六件事

### 1. 模型的跨字段校验必须在序列化器里写第二遍

**DRF 从不调用 `full_clean()`。**只写 `Model.clean()` 的话,API 写入那条规则
等于死代码 —— 而页面上所有写入都走 API。

`ProbeTarget.clean()` / `Device.clean()` / `Notifier.clean()` 各有一份镜像在
`serializers.py` 的 `validate()` 里。**两边要一起改。**

序列化器版必须用 `_merged()` 合并 `self.instance` 的现值:
PATCH 只带部分字段,不合并的话 `PATCH {"protocol":"tcp"}` 就能造出一条没有端口的
TCP 线路。

**数据库约束也要镜像。**`ProbeTarget` 那条端点唯一约束里带了 `Coalesce` 表达式,
DRF 只会为"纯字段列表"的 `UniqueConstraint` 自动生成校验器,认不出表达式约束。
不手写的话重复端点会以 `IntegrityError` 冒成 **500**,页面上看到的是"服务器错误"
而不是"这个端点已经有了"。这一条是实测踩出来的。

### 2. NULL 会让唯一约束静默失效

`fields=["host", "protocol", "port"]` 这种写法对 ICMP 线路**完全不生效** ——
ICMP 没有端口,`port` 恒为 NULL,而 PostgreSQL 里 `NULL != NULL`。
约束在那儿,一行都挡不住(实测重复插了 90 行才发现)。

所以是:

```python
models.UniqueConstraint(
    "group", "host", "protocol", Coalesce("port", Value(0)),
    name="uniq_probe_endpoint_in_group",
)
```

**任何可空字段进唯一约束都要先 `Coalesce`。**

### 3. 失败时 rtt 必须是 None,不能是 0

写 0 会把平均延迟拉低,图上看着比实际情况好。同理 `loss_pct` 不通时是 `100.0`。

前端同一条规矩:`useFormat.ts` 里 null 一律渲染成 `—`(`DASH`),
**不渲染 0**。而且要区分三种"没有数字":

| 情况 | 显示 | 来源 |
|---|---|---|
| 该型号没有这个指标 | 「该型号不提供此指标」 | 画像的 `absent` |
| 固件没上报 | 「固件未上报」 | 画像的 `optional` |
| 采集失败 | 红色错误信息 | `error` 字段 |

把它们混成一个 0 或一个 `—`,会让人去查一个不存在的问题(C9200L 的温度就是这种)。

### 4. 秒级调度不用 beat 的 crontab

每条线路频率不同、最快 1 秒,而 crontab 最细到分钟;
django-celery-beat 的 IntervalSchedule 是**每条线路一个 beat 条目**,
几十条线就是几十个定时器,改频率还要动 beat 的库表。

这里的做法(`netcheck/scheduler.py`):beat 只做一件事 —— 每
`NETCHECK_TICK_SECONDS` 秒敲一次 tick;tick 查 Redis ZSET 里的到期表
(member=目标 id,score=下次执行时间戳),一次 `ZRANGEBYSCORE` 取出所有到期的。
无论多少线路都是一次查询。

三条不能改的规则:

- **不追赶。**worker 堵了 30 秒,到期目标只跑一次,不补跑错过的 30 拍 ——
  补出来的点时间戳全是"现在",在图上是一根垂直线,没有意义,而且会把 worker 打死。
- **`take_due()` 取出后立刻把 score 推后 5 秒**,防止相邻两个 tick 重叠时
  同一个目标被取走两次。真正的下次时间由任务 `finally` 里的 `reschedule()` 写回。
- **`sync_schedule()` 每拍都调。**这是"改了配置立刻生效"和"Redis 重启后自愈"
  的保证。改成只在启动时同步,页面上新建的线路要等下次重启才开始探测。

`run_probe` 的 `finally` 里必须同时 `clear_inflight()` 和 `reschedule()` ——
少一个那条线路就此停摆。

### 5. 拨测任务 `max_retries=0`

**拨测失败本身就是要记录的结果,不是需要重试的错误。**
重试会污染数据:一次超时重试三次成功,记下来的是"通",而真实情况是这条线路当时不稳。

对比:`send_notification` 是要重试的(`max_retries=3`),但只在**所有渠道都失败**时重试 ——
部分成功再重试会给已成功的渠道重复发一遍。

### 6. 计数器回绕必须丢弃,不能取绝对值

SNMP 拿到的是单调递增的字节计数器,速率靠差值算。
`current < previous` 说明计数器回绕或设备重启,这时唯一正确的做法是**返回 None**
(`devices/collector.py` 的 `_rate()`)。按差值算得负数、取绝对值会在图上画出一根
冲天的假尖峰 —— 而那种尖峰会被当成真的流量突发去排查。

同理**接口计数器一律优先 64 位 `ifHC*`**:48 口千兆交换机满速时 32 位的
`ifInOctets` 约 34 秒回绕一次,60 秒采集间隔算出的速率纯粹是噪声。
退回 32 位时要在 `meta.counter_32bit` 里标注,页面上要能看出数据成色。

---

## 各处的职责边界

```
probes/*.py       只发探测,只报事实(ProbeResult)。不判定、不写库、不开事件
probes/runner.py  evaluate() —— 唯一的阈值判定处。状态语义在这里定义完,
                  前端颜色、事件级别、大屏统计才对得上
events/engine.py  唯一的事件开关处。连续次数、级别升级、并发去重都在这
notify/dispatch   一个事件 → 所有匹配渠道。每个渠道独立 try
devices/profiles  型号差异的唯一去处。加型号/固件通常只改这个文件
devices/collector 通道选择、降级、写库、判阈值
```

**通道降级只在"通道级失败"时触发**(连不上、认证错、超时),不在"某个指标采不到"时
触发 —— 后者是画像的 `optional` 该处理的事。混在一起会导致一台温度传感器缺失的
C9200L 每分钟都白走一遍 SSH 降级。

**枚举只定义在后端。**`models.py` 里的 `TextChoices` → `/api/meta/choices/` →
前端 `useMetaStore()`。`.vue` 文件里**不许硬编码中文枚举标签**,那是两边漂移的起点。

顶部统计那五项(`views.py` 的 `TOP_KINDS`)和前端是对齐的,改一边要改另一边。

---

## 时序数据

原始秒级点只保留 `NETCHECK_RAW_RETENTION_HOURS` 小时,长期趋势查 `ProbeRollup`。

**不要为了省事直接查 `ProbeSample` 画长跨度的图** —— 一条 1 秒频率的线路一天
86400 行,十条线路一周的原始点扫一遍就够让接口超时。
粒度选择在两处(`ProbeTargetViewSet.series` 和 `dashboard_charts`),**保持一致**:

```
≤ 2 小时   原始点
≤ 2 天     1m 桶
≤ 14 天    5m 桶
更长       1h 桶
```

聚合链是 `原始 → 1m → 5m → 1h`,粗桶由细桶算,**不重扫原始表**。两个细节:

- **平均值按样本数加权。**直接对细桶的平均值再平均,会让一个 2 样本的桶和一个
  60 样本的桶等权。
- **P95 取细桶 P95 的最大值,不重算。**严格的 P95 需要全量原始点,而那些点可能
  已经清理了。取最大值是保守方向:只会偏高不会偏低,对"最慢的时候有多慢"是安全的。

`rollup_1m` 只处理**已经结束的**分钟。碰当前分钟会把不完整的桶 upsert 成完整的。

清理要**分批删**(每批一万行):这张表同时在被高频写入,一次大 DELETE 会长时间持锁。

---

## 前端

### 只有深色

这是挂墙上的监控大屏,不是白天办公的后台。**需要亮色是一次单独的改动** ——
不要临时给某个组件加 `@media (prefers-color-scheme: light)`,半套亮色比没有亮色更糟
(隔壁 `ops-ai-cmdb` 为此逐个算过九十多处令牌的对比度)。

### 三套颜色各管各的,不要混用

| 集合 | 用途 | 约束 |
|---|---|---|
| `NEON` | 边框、辉光、强调文字 | 都过 4.5:1(vs 面板底 `#0e1220`) |
| `STATE` / `SEVERITY` | 状态和级别 | 保留色,不参与分类着色 |
| `CATEGORICAL` | 图表线条、进度条 | **已用配色校验器验过** |

`CATEGORICAL` 刻意比 `NEON` 暗 —— 大面积高饱和色在深色底上会发晕、互相干扰。
它的 OKLCH 明度落在深色带 `[0.48, 0.67]`、色度 ≥0.1、全对色盲分离度 ΔE 8.1、
对底色对比度全 ≥3:1。**别凭手感改这八个值**,改了要重跑校验。

**标签的字色按底色亮度算,不写死白色。**`SeverityTag` 的 `ink` 计算属性就是干这个的:
警告档底色 `#ffb224` 上白字只有 1.83:1,根本读不出来。

### 动效的三条自律(`styles/cyber.css`)

1. **动效要么表达状态,要么表达数据流,不做纯装饰的乱动。**
   呼吸的状态灯=这条线还活着;脉冲的红边=有未恢复的严重事件;
   扫过的扫描线=这块面板在自动刷新(**暂停刷新时要把 `live` 关掉**,
   否则那道线就成了纯装饰)。
2. **数据区不动。**数字、表格行、图表线本身不加动画 —— 读数时底下在动,人会看错。
   唯一例外是统计格值变化时闪 450ms(`cy-flash`),大屏上没人盯着看,一次短暗示有用。
3. **一切动效受 `prefers-reduced-motion` 约束**,而且只用 transform/opacity。
   那个 media query 里停 animation 但**不停 transition** —— 后者是交互反馈,
   全停掉界面会显得没响应。

Orbitron 只用在标题和品牌字。**数字用 JetBrains Mono** ——
Orbitron 的零是"方框加斜线"的几何造型,大屏上一排 0 会被当成缺字形的豆腐块(实测)。

### 图表

`GroupChart.vue` 里三个不能改回去的决定:

- **默认画一个指标,切换着看,不是三个指标堆一张图。**量纲不同(ms/%/ms),
  十条线 × 三个指标 = 三十条曲线,读不出任何东西。
- **断线画成红色 `markArea` 竖带,不是把线画到 0。**画到 0 会让人以为延迟降到 0 了。
- **时间上不连续的两点之间插 null 断开**(`withGaps()`)。
  echarts 默认会用直线连起来,那根线看着像"这段时间延迟平稳",
  它其实是"这段时间没有数据" —— 两件事在监控上含义相反。
  阈值取采集间隔的 3 倍(偶尔迟到一两拍是正常的)。
- **延迟/抖动的 Y 轴不强制从 0 起**(`min: 'dataMin'`)。内网线路常年在 0.0x ms,
  从 0 起会把所有线挤在顶端一条缝里。丢包率相反,固定 0-100。
- `animation: false` —— 轮询刷新时开动画,线会一直抖。
- `setOption` 用 `notMerge: false`,这样刷新不会丢掉用户手动缩放的视图。

Sparkline 是**手写 SVG,不用 echarts**:一个大屏上有几十个,
每个 init 一个 echarts 实例会让首屏卡好几秒。

### 轮询(`usePolling.ts`)

三条:**页签隐藏时暂停**(回前台立刻补一次,不等周期);
**上一次没回来就跳过这一拍**(否则请求叠着堆积);
**失败不清空已有数据**(网络抖一下就清空图,比显示"数据是 5 秒前的"糟得多)。

大屏**一次刷新只打三个接口**(`overview` / `charts` / `devices`)。
别改成每条线路一个请求 —— 几十条线路 × 每 5 秒会把 gunicorn 打满。

### 加一张 CRUD 表

`models.py` → `serializers.py` → `views.py`(在 `urls.py` 注册)→ `filters.py` →
`admin.py`,然后前端在 `Config.vue` 里加一个 `fields` 数组(`FieldSpec[]`)和一个
`columns` 数组。**不要手写第二份表单模板** —— `SchemaForm.vue` 已经做完了,
而手写模板是"加字段忘了改表单"的高发地。

条件字段用 `FieldSpec.show`:SNMP v2c 和 v3 的字段完全不同、只有 FortiGate 有 VDOM,
全铺开会得到一个四十个输入框的表单而其中三十个和当前选择无关。

---

## 部署上的三个坑

1. **容器里的 ICMP 需要授权。**拨测走系统 `ping`(不用 raw socket 是为了不要
   `CAP_NET_RAW`,见 `probes/icmp.py`),但容器里非 root 跑 ping 仍需要
   `sysctls: net.ipv4.ping_group_range`。compose 里配好了,不支持的内核改用
   `cap_add: [NET_RAW]`。症状很明确:所有 ICMP 线路报 "Operation not permitted"。
2. **beat 只能一个实例。**它是定时器,起两个就是所有采集跑两遍。扛量加 worker。
3. **和别的项目共用 Redis 时 db 号必须错开。**这台机器上 `ops-ai-cmdb` 占了
   db 0(broker)/1(结果)/2(cache),所以裸机部署时本项目用 5/6/7。
   撞号的后果是互相清对方的队列,而症状是"任务偶尔丢",极难查。
   容器里是独占 Redis,从 0 用就行。

---

## 未在真机验证的部分

**SNMP / SSH / FortiGate REST API 三条设备采集通道没有接过真设备** ——
手边没有 C9300 / C9200L / FortiGate-401F。已验证的是代码路径、错误分类、
超时和降级处理;**没验证的是 OID 返回值的实际解析和 CLI 输出的实际格式**。

接真设备时:

- 用配置中心的「测主通道」按钮,它的报错是指向性的(见 DEPLOY.md 的排查一节)
- Cisco 的 CPU/内存 OID 在不同平台和固件上分布在不同 MIB 里,画像里给的是
  **候选 OID 列表,按顺序试第一个有值的**。真机上发现某个型号走的是另一个 OID,
  往那个列表里加一项就行,不要改成按版本号 if/else —— 版本号本身经常是错的
  (设备升级了但 CMDB 没更新)
- FortiOS 的 `resource/usage` 响应形状在小版本间有出入,`_extract_usage()` 认三种;
  遇到第四种就往那儿加,别只认一种(升级固件后指标会静默变空)
