# 部署手册

两种部署方式,推荐第一种。

- [一、Docker 部署(推荐)](#一docker-部署推荐)
- [二、离线部署(机房没有外网)](#二离线部署机房没有外网)
- [三、裸机部署](#三裸机部署)
- [四、部署后必做的四件事](#四部署后必做的四件事)
- [五、更新发布新版本](#五更新发布新版本)
- [六、故障排查](#六故障排查)

---

## 一、Docker 部署(推荐)

整段可复制的极简版在 [README 的「部署 / 更新 / 卸载」](README.md#部署--更新--卸载)。
这一节是同一件事的详细版,解释每一步在干什么。

### 1. 拉代码并准备配置

```bash
mkdir -p /data && cd /data
git clone https://github.com/jsops111/netwok-leyc.git
cd /data/netwok-leyc
cp .env.docker.example .env.docker
```

编辑 `.env.docker`,**四个值必须改**:

```bash
# 生成 Django 密钥
python3 -c "import secrets;print(secrets.token_urlsafe(50))"

# 生成凭据加密密钥(需要 cryptography;没有的话用下面的 docker 一行命令)
python3 -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"
# 没装 cryptography 时:
docker run --rm python:3.12-slim sh -c "pip install -q cryptography && python -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())'"

# 两个数据库密码随便生成强口令
python3 -c "import secrets;print(secrets.token_urlsafe(24))"
```

| 变量 | 说明 |
|---|---|
| `DJANGO_SECRET_KEY` | Django 会话签名 |
| `NETCHECK_ENCRYPTION_KEY` | **凭据加密密钥。丢了库里所有 SNMP community / SSH 口令 / API token 都解不出来** —— 和数据库备份分开存 |
| `POSTGRES_PASSWORD` | 库密码 |
| `REDIS_PASSWORD` | Redis 密码 |
| `WEB_PORT` | 对外访问端口,默认 `18120` |
| `NETCHECK_TICK_SECONDS` | 派发器唤醒间隔。要支持"每秒一次"的线路填 `1`;线路都在 10 秒以上填 `5` 更省资源 |
| `NETCHECK_ADMIN_PASSWORD` | 第一个管理员的初始密码。**留空更好** —— 留空会随机生成并打印到启动日志,填了它就一直躺在这个文件里 |
| `NETCHECK_SESSION_DAYS` | 会话有效期(天),默认 30。大屏是挂在墙上的,到期那块屏会停在登录页,**宁可长不要短** |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | **通过域名或 HTTPS 访问时必须填**,要带 scheme。不填的症状是"能登录但一保存就 403" |

```bash
chmod 600 .env.docker     # 里面有密钥,别让别人读
```

### 2. 构建并启动

```bash
docker compose --env-file .env.docker up -d --build
```

首次构建约 3-5 分钟(拉基础镜像 + 装依赖)。启动顺序由 healthcheck 控制:
`db`/`redis` 健康后才起 `backend`,`backend` 起来后才起 `worker`/`beat`。

### 3. 确认六个服务都活着

```bash
docker compose --env-file .env.docker ps
```

期望看到 `db` `redis` `backend` `frontend` 是 `healthy`,`worker` `beat` 是 `Up`。

```bash
# 健康检查接口 —— 它会告诉你采集是否真的在跑
curl -s http://127.0.0.1:18120/api/health/
```

`"status": "ok"` 才算真的好了。返回 `degraded` 时里面会写明是哪些线路停滞。

### 4. 拿到第一个管理员的密码

**全站需要登录**(大屏也是)。第一个管理员是 backend 容器首次启动时
自动建的 —— 不自动建的话页面会停在登录框,而库里一个账号都没有。

```bash
# 没在 .env.docker 里配 NETCHECK_ADMIN_PASSWORD 时,密码是随机生成的,
# 只打印这一次:
docker compose --env-file .env.docker logs backend | grep -A3 "管理员账号已创建"
```

用户名默认 `admin`(可用 `NETCHECK_ADMIN_USERNAME` 改)。
**登录后第一件事是去「管理后台 → 我的安全」改密码。**

初始化只在"库里一个用户都没有"时发生,所以重启容器不会把你改过的密码
重置回环境变量里那个值。

要另开账号,在「管理后台 → 用户管理」里建,不用进 Django admin。
Django 自带的 `/admin/` 仍然在,是给救急用的原始表格。

### 5. 打开页面并登录

```
http://<服务器IP>:18120/
```

**两步验证是自愿的** —— 不绑也能用。要绑就在「管理后台 → 我的安全」里扫码,
绑完会给十个恢复码,**只显示这一次**,现在就抄下来。

### 常用运维命令

```bash
# 看日志(采集问题优先看 worker)
docker compose --env-file .env.docker logs -f worker
docker compose --env-file .env.docker logs -f beat
docker compose --env-file .env.docker logs --tail 100 backend

# 改了代码重新部署
docker compose --env-file .env.docker up -d --build

# 只重启采集(改了阈值不用重启,配置是实时生效的)
docker compose --env-file .env.docker restart worker beat

# 加大采集能力:worker 起多个副本(beat 绝对不能多起)
docker compose --env-file .env.docker up -d --scale worker=3

# 停止(数据保留)
docker compose --env-file .env.docker down

# 停止并删数据 —— 历史样本和事件记录会全部丢失
docker compose --env-file .env.docker down -v
```

### 备份

```bash
# 库
docker compose --env-file .env.docker exec -T db \
  pg_dump -U netcheck network_check | gzip > netcheck-$(date +%F).sql.gz

# 恢复
gunzip -c netcheck-2026-08-28.sql.gz | \
  docker compose --env-file .env.docker exec -T db psql -U netcheck -d network_check
```

⚠ **备份数据库的同时要单独备份 `.env.docker` 里的 `NETCHECK_ENCRYPTION_KEY`。**
只有库没有密钥,恢复出来的凭据字段全是空的,所有设备都要重新填一遍口令。

---

## 二、离线部署(机房没有外网)

### 在有外网的机器上打包

```bash
cd /data/netwok-leyc

# 1. 构建镜像
docker compose --env-file .env.docker build

# 2. 把五个镜像存成一个 tar(基础镜像也要带上)
docker save -o netcheck-images.tar \
  netcheck-backend:latest \
  netcheck-frontend:latest \
  postgres:17-alpine \
  redis:8-alpine

# 3. 打包代码和配置(镜像里已含代码,这一份是给 compose 用的)
tar czf netcheck-deploy.tar.gz \
  docker-compose.yml .env.docker.example DEPLOY.md README.md

# 4. 两个文件拷到机房
ls -lh netcheck-images.tar netcheck-deploy.tar.gz
```

### 在机房机器上装载

```bash
# 1. 载入镜像
docker load -i netcheck-images.tar
docker images | grep netcheck

# 2. 解开配置
tar xzf netcheck-deploy.tar.gz
cp .env.docker.example .env.docker
vi .env.docker        # 按上面第一节改那四个密钥

# 3. 启动 —— 加 --no-build,否则它会试着联网构建
docker compose --env-file .env.docker up -d --no-build
```

---

## 三、裸机部署

已有 PostgreSQL 17 和 Redis 时可以不用容器。

```bash
# 1. 建库
psql -U postgres -c "CREATE DATABASE network_check OWNER <你的用户> ENCODING 'UTF8';"

# 2. 后端
cd backend
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e .

# 3. 配置(项目根目录的 .env,不是 .env.docker)
cd ..
cp .env.docker.example .env
vi .env
#   POSTGRES_HOST / REDIS_HOST 改成实际地址
#   ⚠ 和别的项目共用同一个 Redis 实例时,CELERY_BROKER_DB / CELERY_RESULT_DB /
#     NETCHECK_CACHE_DB 三个 db 号必须错开,撞号会互相清对方的队列

# 4. 迁移 + 建第一个管理员(全站要登录,不建的话没人进得去)
cd backend
.venv/bin/python manage.py migrate
.venv/bin/python manage.py collectstatic --noinput
.venv/bin/python manage.py bootstrap_admin      # 密码打印在输出里
#   已经有用户时它会跳过;要指定密码用 --password,或配 NETCHECK_ADMIN_PASSWORD

# 5. 三个进程(生产用 supervisor / systemd 托管)
.venv/bin/gunicorn config.wsgi:application --bind 127.0.0.1:8100 --workers 4 --timeout 90
.venv/bin/celery -A config worker -l info --concurrency=8 -Ofair
.venv/bin/celery -A config beat -l info

# 6. 前端
cd ../frontend
npm install
npm run build          # 产物在 dist/,交给 nginx
# 开发模式:npm run dev  → http://127.0.0.1:5273
```

裸机跑 ICMP 探测需要确认权限:

```bash
# 非 root 跑 worker 时,让它能开 ICMP socket
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
# 永久生效
echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee -a /etc/sysctl.conf
```

---

## 四、部署后必做的四件事

### 1. 建监控类和线路

配置中心 → 监控类 → 新建。**一个监控类就是大屏上的一张大图**,按线路的用途分:
互联网出口 / 专线 / 内网核心 / DNS / 业务域名。

然后配置中心 → 检测线路 → 新建。填完点**「测试」**,别等采集周期 ——
测试按钮直接返回一次真实探测结果,配错了立刻能看到。

频率填多少:出口和专线这类关键线路 1-5 秒;一般业务 10-30 秒;
外部域名 60 秒。**频率越密对 worker 压力越大**,见下面「采集迟到」那一节。

### 2. 建设备

在册型号采集最全:

| 型号 | 推荐通道 | 说明 |
|---|---|---|
| `C9300-48T` / `C9300-24T` | SNMP v2c/v3 | 必须用 ifHC* 64 位计数器(代码已处理) |
| `C9200L-24T-4G` | SNMP | 温度/电源在这款上经常采不到,是画像里声明的可选项,显示 `—` 不是故障 |
| `FortiGate-401F` | **API 主 + SNMP 降级** | 会话数、策略命中、HA 成员、License 到期只有 REST API 能拿全 |

不在册的型号选「通用」画像,能采到通断、接口流量、运行时长。

建完点**「测主通道」**,配了降级的再点「测降级」。

### 3. 建通知渠道并发测试

配置中心 → 通知渠道。**建完一定点「发测试」** ——
没测过的渠道等于没有渠道,真出故障时才发现 token 错了是最糟的情况。

- **Telegram**:向 `@BotFather` 申请 bot 拿 token;chat id 个人是数字、群组是负数。
  内网连不上 `api.telegram.org` 时在「API 地址」里填反代地址。
- **Webhook**:模板留空发平台标准 JSON。对接钉钉/企微/飞书要填它们要求的结构,
  占位符列表在表单提示里。

### 4. 确认采集真的在跑

大屏顶部那个健康指示灯是绿的,并且图上的点在往前走。

**"接口 200 但采集停了"是这类平台最难发现的故障** —— 图还在,只是不更新。
所以专门做了这个指示灯,以及 `/api/health/` 接口。

---

## 五、更新发布新版本

代码改完之后怎么把新版本发到服务器上。**首次部署看第一节,这一节是之后每一次更新。**

### 0. 先看这一版有没有改表结构

```bash
cd /data/netwok-leyc
git pull origin main
git log --oneline -5

# 有输出 = 这一版带 migration,按第 3 小节两步发;没输出 = 直接第 1 或第 2 小节
git diff --name-only HEAD@{1} HEAD -- backend/netcheck/migrations/
```

⚠ **带 migration 的版本,发布前先备份数据库**(备份命令见第一节末尾)。
迁移是不可逆的,回滚代码不会回滚表结构。

### 1. 服务器能上网 —— 直接构建

服务器上留一份 git 工作副本,更新就是三行:

```bash
cd /data/netwok-leyc
git pull origin main
docker compose --env-file .env.docker up -d --build
```

`up -d --build` 会重新构建变更的镜像,**只重启镜像真的变了的服务**;
`db` / `redis` 不动 —— 数据在命名卷里,不加 `-v` 就不会丢。

**不用手动跑 migrate。**backend 镜像的启动命令里已经串了:

```
python manage.py migrate --noinput && python manage.py collectstatic --noinput && gunicorn ...
```

容器每次启动都会自己迁移一遍(已迁移过的是空操作)。

耗时:依赖没改时后端重建十几秒(`backend/Dockerfile` 里 `COPY pyproject.toml`
单独一层,改业务代码命中缓存不重装依赖);前端要重跑 `vite build`,一两分钟。

⚠ **改了 `backend/pyproject.toml` 的依赖时,那一层缓存会失效,重建要三五分钟** ——
这是正常的,不是卡住了。

### 2. 机房无外网 —— 传镜像过去

和第二节的离线部署同一套办法,区别是:**日常更新不用带 `postgres` / `redis`
基础镜像**,它们没变。只带自己的两个,包能从两百多 MB 降到几十 MB。

```bash
# ---- 在有外网的机器上 ----
cd /data/netwok-leyc
git pull origin main
docker compose --env-file .env.docker build

docker save netcheck-backend:latest netcheck-frontend:latest \
  | gzip > netcheck-app-$(date +%F).tar.gz
ls -lh netcheck-app-*.tar.gz
```

```bash
# ---- 拷到机房机器上 ----
gunzip -c netcheck-app-2026-08-29.tar.gz | docker load
docker images | grep netcheck

cd /data/netwok-leyc                       # 这里只需要 docker-compose.yml 和 .env.docker
docker compose --env-file .env.docker up -d --no-build
```

⚠ **`--no-build` 必须加。**不加它会试着联网构建,然后在拉基础镜像那一步失败。

⚠ 只改了 compose 或 `.env.docker`(没改代码)时不用传镜像,
机房上直接 `docker compose --env-file .env.docker up -d --no-build` 就生效。

### 3. 带 migration 的版本,分两步发

`docker-compose.yml` 里 worker 依赖的是 backend 的 `service_started`,
不是 `service_healthy` —— backend 容器一启动(migrate 还在跑)worker 就起来了。
平时无所谓,但**这一版改了表结构**时,worker 会撞上旧 schema 报一阵错,
直到 migrate 跑完才自己恢复。要干净就分两步:

```bash
# 第一步:只更新 backend,等它 healthy —— healthy 就说明 migrate 已经跑完
docker compose --env-file .env.docker up -d --build backend
watch -n2 'docker compose --env-file .env.docker ps backend'   # 等到 (healthy),Ctrl-C 退出

# 第二步:再滚采集进程和前端
docker compose --env-file .env.docker up -d --build worker beat frontend
```

看迁移到底做了什么:

```bash
docker compose --env-file .env.docker exec backend python manage.py showmigrations netcheck
docker compose --env-file .env.docker logs backend | grep -i "applying"
```

### 4. 确认新版真的在跑

三件事都要看,缺一件都可能是"发了但没生效":

```bash
# 1) 六个服务的状态 —— db/redis/backend/frontend 是 healthy,worker/beat 是 Up
docker compose --env-file .env.docker ps

# 2) 容器用的确实是新构建的镜像(比对 CREATED 时间)
docker compose --env-file .env.docker images

# 3) 采集真的在跑 —— 这一条最关键
curl -s http://127.0.0.1:18120/api/health/
```

`"status": "ok"` 才算发布成功。返回 `degraded` 时里面会写明是哪些线路停滞。

⚠ **"页面能打开"不等于"发布成功"。**前端是静态文件,后端挂了页面照样出来,
只是图不再往前走 —— 所以必须看 `/api/health/`,不是看首页。

发布后几分钟里再扫一眼 worker 日志:

```bash
docker compose --env-file .env.docker logs --tail 50 -f worker
```

### 5. 回滚

镜像现在打的是 `:latest`,新版一构建就把旧版覆盖了,**所以回滚 = 切回旧代码重新构建**:

```bash
git log --oneline -10
git checkout <上一个正常的 commit>
docker compose --env-file .env.docker up -d --build
```

⚠ **代码能回滚,migration 不能。**旧代码配新表结构在大多数情况下能跑
(Django 不校验多出来的列),但删列/改类型的迁移回滚后会直接报错。
所以第 0 小节说的"带 migration 就先备份"不是客套话。

想要**秒级回滚**就给镜像打版本号,改 `docker-compose.yml` 两处 `image:`:

```yaml
image: netcheck-backend:${IMAGE_TAG:-latest}      # frontend 同理
```

发布时 `IMAGE_TAG=$(date +%Y%m%d) docker compose --env-file .env.docker up -d --build`,
回滚就是把 `IMAGE_TAG` 改回上一个值重启 —— 不重新构建,几秒钟。
配合 `git tag` 一起打,版本号和代码就对得上了。

### 6. 什么改动不需要重新构建镜像

| 改了什么 | 怎么生效 |
|---|---|
| 线路 / 设备 / 渠道 / 阈值 | **不用动容器**,配置是实时生效的 |
| `.env.docker` 里的参数 | `docker compose --env-file .env.docker up -d`(不加 `--build`) |
| `docker-compose.yml` | 同上 |
| 后端 / 前端代码 | 要 `--build` |

⚠ 改了 `NETCHECK_TICK_SECONDS`、`NETCHECK_RAW_RETENTION_HOURS` 这类采集参数,
要重启 `worker` 和 `beat` 才读得到新值。

---

## 六、故障排查

### 所有 ICMP 线路报 "Operation not permitted"

容器里非 root 用户没有 ICMP 权限。`docker-compose.yml` 的 worker 里已经配了
`sysctls: net.ipv4.ping_group_range`,某些内核/容器运行时不支持它。
把 worker 服务里 `cap_add: [NET_RAW]` 那两行注释放开,重启 worker。

验证:
```bash
docker compose --env-file .env.docker exec worker ping -c 2 127.0.0.1
```

### 图上的点变稀了 / 大屏提示"采集任务已迟到"

worker 跟不上派发。三个方向:

```bash
# 1. 加 worker 副本
docker compose --env-file .env.docker up -d --scale worker=3

# 2. 看是不是某条线路太慢拖住了 —— 一次探测最坏耗时 = 发包数 × 超时
#    (新建线路时表单会拦这种配置,但历史配置可能有)

# 3. 频率不需要那么密的线路调大间隔
```

判断依据:`/api/health/` 里 `scheduler.probe.overdue` 长期不为 0。

### 告警没收到

按这个顺序查:

1. 事件记录页面里那条事件的「推送」列 —— 显示「未推送」说明根本没发出去
2. 点那条事件的「重推」按钮,再看列变化
3. 配置中心 → 通知渠道 → 那个渠道的「发测试」
4. 渠道列表里的「失败」计数和最后错误
5. `docker compose logs worker | grep notify`

常见原因:渠道的**最低级别**设得比事件级别高;或者**静默窗口**内已经发过一条;
或者只勾了「推送告警」没勾「推送恢复」。这三项都在渠道的「过滤」列里显示。

### 忘了密码 / 被锁在外面

```bash
# 重置某个账号的密码(容器里)
docker compose --env-file .env.docker exec backend \
  python manage.py changepassword admin

# 一个管理员都进不去了 —— 强制重建 admin
docker compose --env-file .env.docker exec backend \
  python manage.py bootstrap_admin --force --username admin --password '新密码至少10位'
```

**两步验证的手机丢了**,按这个顺序:

1. 用绑定时保存的**恢复码**登录 —— 登录页那个验证码框直接输恢复码就行,
   两种它都试
2. 恢复码也没了 → 让**另一个管理员**在「管理后台 → 用户管理」里点「解绑2FA」
3. 只有一个管理员而且就是他 → 上面那条 `bootstrap_admin --force`
   只重置密码,**不解 2FA**,还要:

```bash
docker compose --env-file .env.docker exec backend python manage.py shell -c "
from accounts.models import TotpDevice, RecoveryCode
from django.contrib.auth.models import User
u = User.objects.get(username='admin')
TotpDevice.objects.filter(user=u).delete(); RecoveryCode.objects.filter(user=u).delete()
print('已解绑')"
```

### 403 / "CSRF验证失败" —— 登录不进去,或者一保存就报错

先确认 nginx 传的是 `$http_host` 而不是 `$host`:

```bash
docker compose --env-file .env.docker exec frontend \
  grep "proxy_set_header Host" /etc/nginx/conf.d/default.conf
```

**必须是 `$http_host`。**`$host` 会把端口去掉,而这个平台跑在 18120 这类
非标准端口上 —— Django 拿浏览器发来的 `Origin`(带端口)和它看到的 Host
(被剥了端口)比对,永远对不上,于是所有写操作 403。
镜像里是 `$host` 的话说明前端镜像太旧,`git pull` 后重新构建 frontend 即可。

### 通过域名 / HTTPS 访问时的 403

通过**域名**或 **HTTPS** 访问时,Django 要求请求的 Origin 在信任列表里。
在 `.env.docker` 里填上(**要带 scheme,多个用逗号分隔**),然后重启 backend:

```bash
DJANGO_CSRF_TRUSTED_ORIGINS=https://netcheck.example.com,http://10.0.0.5:18120
NETCHECK_COOKIE_SECURE=true        # 上了 HTTPS 才开;http 访问时开了会导致登不上
```

用 IP + http 直接访问时不需要配这一条。

### 大屏隔一阵就跳回登录页

会话到期了。默认 30 天,从**登录那一刻**算起(不做滑动续期 —— 开了的话
每个请求都要写一次 session,而大屏每 5 秒打三个接口)。

```bash
NETCHECK_SESSION_DAYS=90     # 改完重启 backend;已存在的会话不受影响
```

如果是**几分钟**就掉,那不是会话过期,看 backend 日志里有没有 `DJANGO_SECRET_KEY`
变过 —— 换了 secret 会让所有已签发的会话立刻失效。

### 登录一直提示"失败次数过多"

同一个用户名或同一个 IP 连续失败 8 次会锁 15 分钟(可配)。等窗口过去,
或者让管理员在「管理后台 → 用户管理」里点那一行的「解锁」。

要看是谁在试:**管理后台 → 登录审计**,按结果筛「密码错误」。
那里能分清是"有人在试口令"(密码错、用户名五花八门)还是
"自己手机时间不对"(验证码错、同一个用户名)。

### 设备采不到数据

```bash
# 先用配置中心的「测主通道」按钮,它的报错是指向性的:
#   "SNMP 无响应"          → 网络不通,或 community 错,或设备没开 SNMP
#   "读不到 sysDescr"       → community 的 view 限制了 OID 范围
#   "API Token 无效(401)"  → token 过期
#   "API 拒绝访问(403)"    → REST API 管理员的可信主机没放行本机 IP
#   "SSH 认证失败"          → 用户名/密码错
#   "no matching key exchange" → 老设备的 SSH 算法太旧(代码已自动放宽,
#                                 还报错说明设备侧更老)
```

某个指标一直是 `—`:先看设备卡片上写的是「该型号不提供此指标」还是「固件未上报」。
前者是画像里声明的缺项(比如 C9200L 的温度),不是故障。

### 磁盘涨得快

原始秒级样本是主要占用。一条 1 秒频率的线路一天约 86400 行 ≈ 20MB。

**先看页面**:管理后台 → 系统信息。那一页第一块就是磁盘 —— 总量、已用、
可用、使用率,以及「每天新增多少」和「保留期内稳定占用」。数字和宿主机上
`df -h` 看到的一致(容器里 `/` 是 overlay 挂载,统计的就是承载
`/var/lib/docker` 的那块盘)。

**然后在同一页改保留天数**(系统信息 → 数据保留),改完下一次清理任务
(每小时)就按新值执行,**不用重启任何进程**。磁盘告急先缩「原始秒级样本」
—— 它是主要消费者,而长期趋势看的是降采样桶,不受影响。

`.env.docker` 里的 `NETCHECK_RAW_RETENTION_HOURS` 现在只是**首次建行时的默认值**,
之后以页面上的设置为准 —— 否则页面上改完,下次重启又被环境变量盖回去。

⚠ 后端会挡住"粗粒度比细粒度留得短"的配置:图表按跨度选粒度,
细桶比粗桶留得久时,查粗桶的那个跨度就是一片空白。

### 看某张表实际有多大

```bash
docker compose --env-file .env.docker exec -T db psql -U netcheck -d network_check -c "
SELECT relname AS 表, pg_size_pretty(pg_total_relation_size(relid)) AS 大小
FROM pg_catalog.pg_statio_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 10;"
```
