# network-check

网络线路检测与展示平台 —— 秒级拨测、交换机/防火墙采集、事件追踪、告警推送。

```
   拨测线路 ──┐
              ├──→ 阈值判定 ──→ 事件(开/关) ──→ Telegram / Webhook
   交换机 ────┤                    │
   防火墙 ────┘                    └──→ 监控大屏 / 事件报告
```

技术栈:Django 6 + DRF + PostgreSQL 17 + Celery/Redis + pysnmp/paramiko;
前端 Vue 3 + TypeScript + Naive UI + ECharts,赛博朋克深色大屏。

**全站需要登录**(大屏也是),自带用户管理和**可选的**两步验证。

部署看 [DEPLOY.md](DEPLOY.md)。改代码看 [CLAUDE.md](CLAUDE.md)。

---

## 能做什么

### 线路拨测

六种协议,**频率可低到 1 秒**:

| 协议 | 测什么 | 能算出 |
|---|---|---|
| ICMP | 通断 | 延迟、丢包率、抖动 |
| TCP | 握手时间 | 延迟、抖动(连上立刻关,对被测服务无害) |
| UDP | 端口可达 | 延迟(无响应按通计,强度弱于 TCP) |
| HTTP / HTTPS | 状态码 + 响应内容 | 延迟、**证书剩余天数** |
| DNS | 指定 DNS 服务器的解析 | 延迟、解析结果是否被劫持 |

丢包率和抖动来自**一组包**(每次发 N 个),不是单次探测。抖动用相邻包延迟差的
平均绝对值(IPDV),不是 ping 的 mdev —— 后者对"稳定但偏高"的线路给不出区分度。

判定分三档:`正常` / `劣化`(通但超阈值) / `中断`。
每条线路有延迟、丢包、抖动各自的警告线和严重线。

### 设备采集

三条通道,按型号选主通道 + 降级通道:

| 通道 | 拿得到 | 拿不到 |
|---|---|---|
| **SNMP** v2c/v3 | 接口流量/错包、CPU、内存、温度、电源风扇 | FortiGate 的会话细节、策略命中 |
| **SSH CLI** | SNMP 没暴露的东西 | 需要按型号+版本写解析器,最脆 |
| **REST API**(FortiGate) | 会话数、策略命中、HA 成员、License 到期 | 只实现了 FortiOS |

在册型号(需求点名必须支持的四款):

- `C9300-48T`、`C9300-24T` — Catalyst 9300
- `C9200L-24T-4G` — 温度/电源在这款上常采不到,画像里声明为可选项
- `FortiGate-401F` — 推荐 `API 主 + SNMP 降级`

不在册的型号回落到「通用」画像,仍能采通断、接口流量、运行时长。
型号画像在 `backend/netcheck/devices/profiles.py`,加型号通常只改这一个文件。

### 事件

**一行一次异常**,不是一行一条日志:

```
类型 | 对象 | 详情 | 发生时间 | 恢复时间 | 持续 | 推送状态
```

- 连续 N 次失败才开事件,连续 M 次正常才关 —— 否则瞬时丢包会把告警刷爆
- 同一来源同一类型**同时只有一条未恢复事件**(数据库部分唯一索引兜底)
- 级别从警告升到严重时**升级现有事件并重推**,不新开一条
- 未恢复的事件持续时长实时计算

十五种事件类型,顶部统计的五项是:断线 / 丢包 / 延迟 / 抖动 / 异常。

### 告警推送

- **Telegram** — Bot Token + Chat ID,支持群组话题和反代地址
- **Webhook** — 留空发标准 JSON;填模板可对接钉钉/企微/飞书

过滤在推送侧做(级别下限、事件类型、监控类),事件该记的照记。
静默窗口防 flapping 轰炸。每次推送的结果都记在推送记录里 ——
"告警到底发出去没有"这个问题必须能回答。

### 账号与权限

全站要登录。**两步验证是自愿绑定的,平台不强制** —— 但要有这个能力,
所以管理后台里做全了:

- **TOTP 两步验证** —— 扫码绑定标准验证器 App(Google Authenticator /
  微软 Authenticator / 1Password 都行)。绑定要输一次码确认才算成功:
  跳过这一步的话,手机时间不同步这类问题要等到下次登录才暴露,
  而那时人已经被自己锁在门外了
- **恢复码** —— 十个一次性码,只在生成那一次显示明文(库里存哈希)。
  手机丢了时它是唯一能自己进来的路径
- **管理员可强制解绑** —— 恢复码也丢了时的最后一条路,这个动作会记进审计
- **登录审计** —— 成功和失败都记,而且分得开"密码错"和"验证码错":
  前者可能是有人在试口令,后者通常是自己手机时间不对
- **失败锁定** —— 按用户名和 IP 各记一份计数。只按 IP 记的话,
  出口 NAT 后面一个人输错会锁掉整个办公室

TOTP 密钥和设备凭据同一级别对待:落库用 `NETCHECK_ENCRYPTION_KEY` 加密。

---

## 四个页面

### 监控大屏 `/`

- 顶部:断线/丢包/延迟/抖动/异常**次数** + 线路可用率
- 中部:**一个监控类一张大图**,延迟/丢包/抖动切换;断线区间画成红带,
  阈值画成虚线;图右侧是该组线路的当前值清单
- 底部:交换机/防火墙卡片 —— CPU/内存/温度趋势、会话数、活动接口带宽

一次刷新只打三个接口(统计 5s / 图表 10s / 设备 30s),页签隐藏时自动暂停。

### 事件记录 `/events`

上面是汇总(总数、未恢复、平均持续、累计故障时长)和三个排行
(按类型、出事最多的线路、出事最多的设备),下面是可筛选分页的事件表。
支持认领和重推。

### 配置中心 `/config`

四个 tab:检测线路 / 监控类 / 网络设备 / 通知渠道。

每一类都有**「测试」按钮** —— 这是这一页最有价值的东西:
配错凭据是最常见的问题,不测的话要等一个采集周期再去大屏上找,
中间任何一环出错都分辨不出是哪儿的问题。

### 管理后台 `/manage`

四个 tab,其中**只有「我的安全」对所有登录用户开放**,另外三个要管理员:

| tab | 谁能看 | 干什么 |
|---|---|---|
| 用户管理 | 管理员 | 增删改、启用/停用、重置密码、强制解绑两步验证、清除失败锁定 |
| 我的安全 | 所有人 | 改自己的密码;绑定/解绑两步验证、重新生成恢复码 |
| 登录审计 | 管理员 | 谁在什么时候从哪个 IP 登的、失败的是密码还是验证码 |
| 系统信息 | 管理员 | 版本、PG/调度器连通、各表行数与占用 —— 把排查命令搬到页面上 |

有两条守卫是后端兜的,不是靠前端藏按钮:不能停用/降级/删除**自己**,
也不能把**最后一个管理员**停掉 —— 那会让所有人都进不来。

---

## 快速上手

```bash
cp .env.docker.example .env.docker
vi .env.docker                                    # 改四个密钥,见 DEPLOY.md
docker compose --env-file .env.docker up -d --build
curl -s http://127.0.0.1:18120/api/health/        # status 是 ok 才算好了

# 第一个管理员是首次启动自动建的,密码在日志里(没配 NETCHECK_ADMIN_PASSWORD 时)
docker compose --env-file .env.docker logs backend | grep -A3 "管理员账号已创建"
```

打开 `http://<IP>:18120/` → 登录 → 配置中心 → 建监控类 → 建线路 → 点「测试」。
登录后顺手去「管理后台 → 我的安全」改掉初始密码。

---

## 更新发布

代码更新后怎么发新版,两条路,取决于服务器能不能上网。

### 服务器能上网

服务器上留一份 git 工作副本,更新就是三行:

```bash
cd /path/to/network-check
git pull origin main
docker compose --env-file .env.docker up -d --build
```

`up -d --build` 只重启镜像变了的服务,**db / redis 不动** —— 数据在命名卷里,
不加 `-v` 就不会丢。

**不用手动跑 migrate**:backend 镜像的启动命令里已经串了
`migrate --noinput && collectstatic --noinput && gunicorn`,容器每次起来都会自动迁移。

依赖没改时后端重建十几秒(Dockerfile 里 `COPY pyproject.toml` 单独一层,
改业务代码命中缓存不重装依赖);前端要重跑 `vite build`,一两分钟。

### 机房无外网

本机构建 → 打包 → 拷过去 load。**日常更新不用带 postgres/redis 基础镜像**,
只带自己的两个,包从两百多 MB 降到几十 MB:

```bash
# ---- 有外网的机器 ----
git pull origin main
docker compose --env-file .env.docker build
docker save netcheck-backend:latest netcheck-frontend:latest | gzip > netcheck-app.tar.gz

# ---- 机房 ----
gunzip -c netcheck-app.tar.gz | docker load
docker compose --env-file .env.docker up -d --no-build
```

`--no-build` 是必须的,不加它会试着联网构建然后失败。
首次部署要连基础镜像一起带,见 [DEPLOY.md 第二节](DEPLOY.md#二离线部署机房没有外网)。

### 这一版带 migration 时,分两步发

compose 里 worker 依赖的是 backend 的 `service_started` 而不是 `service_healthy` ——
backend 容器一启动(migrate 还在跑)worker 就起来了。平时无所谓,
但**改了表结构的版本**里 worker 会撞上旧 schema 报一阵错。所以:

```bash
# 1. 先只更新 backend,等它 healthy —— 那说明 migrate 已经跑完
docker compose --env-file .env.docker up -d --build backend
docker compose --env-file .env.docker ps backend

# 2. 再滚采集进程和前端
docker compose --env-file .env.docker up -d --build worker beat frontend
```

### 回滚

镜像现在打的是 `:latest`,新版一构建就把旧版覆盖了,**回滚只能重新构建旧代码**。
需要秒级回滚就把 compose 里的 `image:` 改成 `netcheck-backend:${IMAGE_TAG:-latest}`,
发布时带上日期或 git tag,回滚就是改回上一个值重启。

### 发布后确认这一次

```bash
curl -s http://127.0.0.1:18120/api/health/
```

必须是 `"status": "ok"`。返回 `degraded` 时里面会写明哪些线路停滞了 ——
这比看容器是不是 `Up` 有用得多:**"接口 200 但采集停了"是这类平台最容易漏掉的故障**,
图还在,只是不再往前走。

---

## 项目结构

```
backend/
  config/            settings / celery / urls
  core/              BaseModel、EncryptedTextField(凭据落库加密)、分页
  accounts/          登录、两步验证(TOTP + 恢复码)、用户管理、登录审计
    totp.py          验证窗口/防重放/恢复码 —— 算法交给 pyotp,策略在这
    lockout.py       失败锁定(Redis 计数,按用户名 + IP 各一份)
  netcheck/
    models.py        12 张表:拨测 / 设备 / 事件 / 通知
    scheduler.py     秒级派发器(Redis ZSET 到期表)
    tasks.py         Celery 任务:派发 / 执行 / 聚合清理 / 通知
    probes/          icmp tcp http dns + runner(阈值判定)
    devices/         profiles(型号画像) snmp ssh_cli fortigate_api collector
    events/engine.py 事件开关 + 抖动抑制
    notify/          telegram webhook dispatch
    views.py         CRUD + 三个大屏聚合接口
frontend/src/
  theme.ts           赛博朋克配色(NEON / STATE / CATEGORICAL 三套)
  styles/cyber.css   动效(扫描线、辉光、呼吸灯、切角面板)
  components/        cyber/(面板、统计格、状态灯、仪表条) charts/(大图、sparkline)
  views/             Dashboard / Events / Config / Manage / Login
  stores/auth.ts     会话状态。ready 没到之前路由守卫不能判断,否则刷新闪登录页
```

## 数据保留

| 数据 | 保留 | 说明 |
|---|---|---|
| 原始秒级样本 | 48 小时(可配) | 大图细看用 |
| 1m 桶 | 7 天 | |
| 5m 桶 | 30 天 | |
| 1h 桶 | 永久 | 一条线路一年 8760 行,唯一能回答"去年这条线怎么样" |
| 事件 | 永久 | |
| 推送记录 | 30 天 | 审计材料 |

图表按时间跨度自动选粒度:≤2h 原始点 → ≤2d 1m → ≤14d 5m → 更长 1h。

## 当前状态

已验证:四种协议探测、阈值判定全分支、事件开关与抖动抑制、恢复流程、
Webhook 推送、秒级自动调度、Docker 全栈(含容器内 ICMP 权限)、页面渲染。
登录与管理后台有一组冒烟测试覆盖(15 项):密码/两步验证/恢复码登录、
验证码重放拒绝、失败锁定、CSRF 强制、权限边界(普通用户进不了 /api/manage/)、
最后一个管理员不能被停用、健康接口对未登录只给计数不给线路名。

**未在真机上验证**:SNMP / SSH / FortiGate API 三条设备采集通道 ——
手边没有 C9300 / C9200L / FortiGate-401F。代码路径、错误分类和超时处理都测过,
但 OID 返回值的实际解析、CLI 输出的实际格式需要接上真设备再核一遍。
接设备时用配置中心的「测主通道」按钮,它的报错是指向性的。
