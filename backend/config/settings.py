"""
network-check 的 Django 配置。

与 ops-ai-cmdb 共用同一台 PostgreSQL / Redis,靠**库名和 db 号**隔开,
不是靠实例隔开 —— 改 REDIS 的 db 号之前先确认没和隔壁撞上(见 .env 注释)。
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BASE_DIR.parent

# load_dotenv 不覆盖已存在的环境变量 —— supervisord 注入的值优先于 .env,
# 所以改了 .env 要 `supervisorctl update`(不是 restart)才生效。
load_dotenv(REPO_ROOT / ".env")


def env(key: str, default=None, required: bool = False) -> str:
    value = os.environ.get(key, default)
    if required and not value:
        raise RuntimeError(f"缺少必需的环境变量 {key},检查 {REPO_ROOT / '.env'}")
    return value


def env_bool(key: str, default: bool = False) -> bool:
    raw = os.environ.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


SECRET_KEY = env("DJANGO_SECRET_KEY", required=True)
DEBUG = env_bool("DJANGO_DEBUG", False)
ALLOWED_HOSTS = [h.strip() for h in env("DJANGO_ALLOWED_HOSTS", "*").split(",") if h.strip()]

# 凭据加密密钥,独立于 SECRET_KEY
NETCHECK_ENCRYPTION_KEY = env("NETCHECK_ENCRYPTION_KEY", required=True)

# ---------------------------------------------------------------- 应用

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "django_filters",
    "corsheaders",
    "core",
    "accounts",
    "netcheck",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ---------------------------------------------------------------- 数据库

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("POSTGRES_DB", required=True),
        "USER": env("POSTGRES_USER", required=True),
        "PASSWORD": env("POSTGRES_PASSWORD", required=True),
        "HOST": env("POSTGRES_HOST", "127.0.0.1"),
        "PORT": env("POSTGRES_PORT", "5432"),
        "CONN_MAX_AGE": 60,
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------- DRF

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    # **默认要登录。**放开的只有两个,而且都是显式写在视图上的 @AllowAny:
    #   /api/auth/session/  前端启动时要拿到"没登录"这个答案,顺带种 csrftoken
    #   /api/auth/login/    登录本身
    #   /api/health/        **容器 healthcheck 打的就是它**,收权限会让 backend
    #                       永远 unhealthy,而 worker/beat 依赖它才启动 ——
    #                       症状是"整个栈起不来",却看不出和权限有关
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    # 「没登录」要还原成 401 —— DRF 默认会把它和「权限不够」一起报 403,
    # 而前端对这两种情况的处置完全不同(见 accounts/exceptions.py)
    "EXCEPTION_HANDLER": "accounts.exceptions.api_exception_handler",
    "DEFAULT_PAGINATION_CLASS": "core.pagination.StandardPagination",
    "PAGE_SIZE": 20,
    "DATETIME_FORMAT": "%Y-%m-%d %H:%M:%S",
}

# ---------------------------------------------------------------- 认证与会话

# 会话存 Redis + 落库(cached_db):
#   纯 db —— 大屏每 5 秒三个请求,每个请求读一次 session 表,白读
#   纯 cache —— Redis 一重启所有人被踢下线,包括挂在墙上的那块屏
SESSION_ENGINE = "django.contrib.sessions.backends.cached_db"

# **大屏是挂在墙上长期不动的**,默认 30 天。会话到期那块屏会停在登录页,
# 所以这个值宁可长不要短;真要收紧就配短并接受要定期去点一次。
SESSION_COOKIE_AGE = env_int("NETCHECK_SESSION_DAYS", 30) * 86400
# 不做滑动续期:开了的话每个请求都要写一次 session,而大屏每 5 秒打三个接口。
# 代价是从登录那一刻算满 30 天就要重新登一次,与其每天写几万行 session 更新,
# 不如一个月点一次。
SESSION_SAVE_EVERY_REQUEST = False
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
# CSRF 的 cookie 前端 JS 要读得到(SPA 自己往 X-CSRFToken 里塞),所以不能 HttpOnly。
# 这不是漏洞:CSRF 防的是"别的站替你发请求",而别的站读不到你的 cookie。
CSRF_COOKIE_HTTPONLY = False
# 上了 HTTPS 就把这两个打开(反代终止 TLS 时同样要开)
SESSION_COOKIE_SECURE = env_bool("NETCHECK_COOKIE_SECURE", False)
CSRF_COOKIE_SECURE = env_bool("NETCHECK_COOKIE_SECURE", False)
# 反代后面用 https 访问时,Django 要知道原始协议才能通过 CSRF 的 Origin 校验
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
CSRF_TRUSTED_ORIGINS = [
    o.strip() for o in env("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",") if o.strip()
]

# 登录失败锁定(见 accounts/lockout.py)。按用户名和 IP 各记一份。
NETCHECK_LOGIN_MAX_FAILS = env_int("NETCHECK_LOGIN_MAX_FAILS", 8)
NETCHECK_LOGIN_LOCK_SECONDS = env_int("NETCHECK_LOGIN_LOCK_MINUTES", 15) * 60
# 登录审计保留多久。它是审计材料,比时序数据留得久。
NETCHECK_LOGIN_AUDIT_DAYS = env_int("NETCHECK_LOGIN_AUDIT_DAYS", 180)

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": env_int("NETCHECK_PASSWORD_MIN_LENGTH", 10)}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# 页面上「系统信息」那一栏显示的版本号
NETCHECK_VERSION = env("NETCHECK_VERSION", "0.3.0")

# 「系统信息」里磁盘用量看哪个路径。默认 `/` —— 在容器里它是 overlay 挂载,
# statvfs 返回的是**承载 /var/lib/docker 的那块宿主机磁盘**的大小,
# 而那正是数据涨起来会撑爆的那一块。
# 宿主机把 /var/lib/docker 单独挂在别的盘上时这个值仍然是对的。
# 要看别的路径(比如把宿主机根目录只读挂进来)就改这里。
NETCHECK_DISK_PATH = env("NETCHECK_DISK_PATH", "/")

# ---------------------------------------------------------------- Redis / Celery

REDIS_HOST = env("REDIS_HOST", "127.0.0.1")
REDIS_PORT = env_int("REDIS_PORT", 6379)
REDIS_PASSWORD = env("REDIS_PASSWORD", "")
# db 号从 5 起 —— 同一台 Redis 上 ops-ai-cmdb 占了 0(broker)/1(结果)/2(cache)。
# 撞号的后果是两个平台互相清对方的队列和缓存,而症状是"任务偶尔丢",极难查。
NETCHECK_CACHE_DB = env_int("NETCHECK_CACHE_DB", 7)

_redis_auth = f":{REDIS_PASSWORD}@" if REDIS_PASSWORD else ""
REDIS_URL_BASE = f"redis://{_redis_auth}{REDIS_HOST}:{REDIS_PORT}"

CELERY_BROKER_URL = f"{REDIS_URL_BASE}/{env_int('CELERY_BROKER_DB', 5)}"
CELERY_RESULT_BACKEND = f"{REDIS_URL_BASE}/{env_int('CELERY_RESULT_DB', 6)}"
CELERY_TIMEZONE = "Asia/Shanghai"
CELERY_TASK_TRACK_STARTED = True
# 拨测任务是"过期即无意义"的:worker 堆积时宁可丢掉旧的,也不要拿着十分钟前
# 的探测请求去打设备 —— 那样画出来的图是假的。
CELERY_TASK_SOFT_TIME_LIMIT = 120
CELERY_TASK_TIME_LIMIT = 180
CELERY_BROKER_TRANSPORT_OPTIONS = {"visibility_timeout": 300}
CELERY_WORKER_PREFETCH_MULTIPLIER = 4

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": f"{REDIS_URL_BASE}/{NETCHECK_CACHE_DB}",
        "KEY_PREFIX": "netcheck",
    }
}

# ---------------------------------------------------------------- 拨测参数

# beat 每几秒唤醒派发器一次。线路可配的最小频率不会低于这个值。
NETCHECK_TICK_SECONDS = env_int("NETCHECK_TICK_SECONDS", 1)
# 原始秒级样本保留多久(小时),过期清理。长期趋势看 1m/5m/1h 三张降采样表。
NETCHECK_RAW_RETENTION_HOURS = env_int("NETCHECK_RAW_RETENTION_HOURS", 48)

# ---------------------------------------------------------------- 国际化 / 静态

LANGUAGE_CODE = "zh-hans"
TIME_ZONE = "Asia/Shanghai"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

CORS_ALLOW_ALL_ORIGINS = DEBUG
CORS_ALLOWED_ORIGINS = [
    "http://127.0.0.1:5273",
    "http://localhost:5273",
]
CORS_ALLOW_CREDENTIALS = True

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "std": {"format": "[{asctime}] {levelname} {name}: {message}", "style": "{"},
    },
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "std"}},
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {
        # 拨测每秒都在跑,DEBUG 会把日志刷爆
        "netcheck": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "django.db.backends": {"level": "WARNING"},
    },
}
