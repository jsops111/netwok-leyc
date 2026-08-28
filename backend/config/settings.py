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
    # 拨测大屏是内网只读展示,先放开;要收权限在这里换成 IsAuthenticated
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_PAGINATION_CLASS": "core.pagination.StandardPagination",
    "PAGE_SIZE": 20,
    "DATETIME_FORMAT": "%Y-%m-%d %H:%M:%S",
}

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
