# ---------------------------------------------------------------------------
# 后端镜像 —— Django(gunicorn) / Celery worker / Celery beat 三种角色共用它,
# 靠启动命令区分(见 docker-compose.yml)。一个镜像三个角色是有意的:
# 三者代码完全相同,分开构建只会出现"worker 是旧版本"这种最难查的故障。
# ---------------------------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=Asia/Shanghai

# iputils-ping 是**必需的**,不是可选项:ICMP 拨测走系统 ping 命令
#   (见 netcheck/probes/icmp.py 里为什么不用 raw socket)。
#   少了它所有 ICMP 线路都会报"容器里没有 ping 命令"。
# tzdata      容器里的日志和事件时间要和机房时间一致
# libpq5      psycopg[binary] 自带 libpq,但保留它让 psql 客户端也能用
# curl        健康检查用
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iputils-ping \
        tzdata \
        curl \
        libpq5 \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 先只拷依赖清单 —— 改业务代码时这一层命中缓存,不用重装依赖
COPY pyproject.toml /app/
RUN pip install --upgrade pip setuptools>=77 \
    && pip install -e . --no-build-isolation 2>/dev/null \
    || pip install \
        "django>=6.0.7" "djangorestframework>=3.17.1" "django-filter>=26.1" \
        "django-cors-headers>=4.9.0" "python-dotenv>=1.2.2" "psycopg[binary]>=3.3.4" \
        "celery>=5.6.3" "redis>=8.1.0" "pysnmp>=7.1.0" "paramiko>=5.0.0" \
        "requests>=2.32" "dnspython>=2.7" "cryptography>=50.0.0" \
        "gunicorn>=26.0.0" "whitenoise>=6.0"

COPY . /app/

# 以非 root 运行。ICMP 需要额外授权,两条路二选一(compose 里都配好了):
#   1. sysctls net.ipv4.ping_group_range —— 让这个 gid 能开 ICMP socket(推荐)
#   2. cap_add: NET_RAW —— 给容器 raw socket 权限
RUN groupadd -r netcheck --gid=10001 \
    && useradd -r -g netcheck --uid=10001 --home-dir=/app netcheck \
    && mkdir -p /app/staticfiles /app/logs \
    && chown -R netcheck:netcheck /app
USER netcheck

EXPOSE 8000

# 默认角色是 web。worker / beat 在 compose 里覆盖 command。
#
# bootstrap_admin 那一条**不能省**:全站要登录,而全新部署库里一个用户都没有,
# 页面会停在登录框而没有任何账号能进去。它只在"一个用户都没有"时动手,
# 所以重启容器不会把改过的密码重置回去(见 accounts/.../bootstrap_admin.py)。
# 初始密码取 NETCHECK_ADMIN_PASSWORD;没配就随机生成并打印到日志,
# 用 `docker compose logs backend` 捞。
CMD ["sh", "-c", "python manage.py migrate --noinput && \
     python manage.py collectstatic --noinput && \
     python manage.py bootstrap_admin && \
     exec gunicorn config.wsgi:application \
       --bind 0.0.0.0:8000 --workers 4 --timeout 90 --access-logfile - --error-logfile -"]
