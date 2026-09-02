"""
账号 API 与管理后台 API。

三组:

    /api/auth/*      登录、会话、改密、两步验证的自助绑定    —— 登录相关的放开
    /api/manage/*    用户管理、登录审计、系统信息            —— 仅管理员(is_staff)
    /api/health/     容器 healthcheck 用,始终放开(见 netcheck/views.py)

登录这条路径上有四个不能省的动作,少一个都会留下具体的洞:

    1. 先查锁定 —— 不查的话密码和验证码都能被慢慢试出来
    2. 认证失败要**记审计**,而且要分清"密码错"和"验证码错"
    3. 成功后 django.contrib.auth.login() 会轮换 session key(防会话固定)
    4. 成功后清掉失败计数 —— 否则白天输错几次会影响晚上正常登录
"""

from __future__ import annotations

import logging
import shutil

from django.conf import settings
from django.contrib.auth import authenticate, login as django_login, logout as django_logout
from django.contrib.auth.models import User
from django.db import connection
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response

from accounts import lockout, totp as totp_lib
from accounts.models import LoginAudit, LoginResult, RecoveryCode, TotpDevice
from accounts.serializers import (
    LoginAuditSerializer,
    RetentionPolicySerializer,
    LoginSerializer,
    MeSerializer,
    OtpConfirmSerializer,
    PasswordChangeSerializer,
    PasswordConfirmSerializer,
    ResetPasswordSerializer,
    UserSerializer,
)

log = logging.getLogger("netcheck.auth")


def _audit(request, username: str, result: str, *, user=None, used_2fa=False, detail="") -> None:
    """写一行登录审计。**它自己不能把登录搞挂** —— 审计失败只记日志。"""

    try:
        LoginAudit.objects.create(
            username=(username or "")[:150],
            user=user,
            result=result,
            used_2fa=used_2fa,
            ip=lockout.client_ip(request),
            user_agent=(request.META.get("HTTP_USER_AGENT") or "")[:300],
            detail=detail[:200],
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("写登录审计失败:%s", exc)


def _me(user: User) -> dict:
    return MeSerializer(user).data


# ---------------------------------------------------------------- 会话


@api_view(["GET"])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def session(request):
    """
    当前会话。**前端启动时第一个调它**,有两个用途:

    1. 知道现在是谁(或者没登录),路由守卫据此决定去不去登录页
    2. `@ensure_csrf_cookie` 顺手把 csrftoken 种下来 —— SPA 不渲染 Django 表单,
       不主动种一次的话第一个 POST(登录)就会被 CSRF 拦掉,
       而错误信息是"CSRF Failed",指不到这里
    """

    if not request.user.is_authenticated:
        return Response({"authenticated": False, "user": None})
    return Response({"authenticated": True, "user": _me(request.user)})


@api_view(["POST"])
@permission_classes([AllowAny])
@csrf_protect
def login_view(request):
    """
    登录。密码正确但绑了两步验证时**先返回 otp_required**,不是报错 ——
    那是流程的第二步,前端据此把界面切到验证码输入。

    `@csrf_protect` 是显式加的:DRF 的 SessionAuthentication **只对已认证的
    请求校验 CSRF**,而登录时请求还是匿名的,等于这一个接口没有防护。
    没有它,别人可以让你的浏览器悄悄登进*他的*账号,你之后的操作
    (改配置、认领事件)就都记在他的账上了。

    前端启动时必然先打过 /auth/session/(它带 ensure_csrf_cookie),
    所以 cookie 一定已经种下,这里不会误伤正常登录。
    """

    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    username = serializer.validated_data["username"].strip()
    password = serializer.validated_data["password"]
    otp = (serializer.validated_data.get("otp") or "").strip()
    ip = lockout.client_ip(request)

    remaining = lockout.locked_seconds(username, ip)
    if remaining:
        _audit(request, username, LoginResult.LOCKED)
        return Response(
            {"detail": f"失败次数过多,请 {max(1, remaining // 60)} 分钟后再试",
             "code": "locked", "retry_after": remaining},
            status=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    user = authenticate(request, username=username, password=password)
    if user is None:
        # 账号存在但被停用时,authenticate() 同样返回 None。分开报是有意的:
        # 内网平台里"我的号被停了"和"我密码记错了"是两种完全不同的处置,
        # 含糊其辞只会让人反复试密码
        existing = User.objects.filter(username__iexact=username).first()
        if existing and not existing.is_active:
            _audit(request, username, LoginResult.INACTIVE, user=existing)
            return Response({"detail": "账号已停用,联系管理员", "code": "inactive"},
                            status=status.HTTP_403_FORBIDDEN)
        lockout.record_failure(username, ip)
        _audit(request, username, LoginResult.BAD_PASSWORD, user=existing)
        return Response({"detail": "用户名或密码错误", "code": "bad_credentials"},
                        status=status.HTTP_400_BAD_REQUEST)

    device = getattr(user, "totp", None)
    used_2fa = False
    detail = ""
    if device and device.is_active:
        if not otp:
            _audit(request, username, LoginResult.OTP_REQUIRED, user=user)
            return Response({
                "status": "otp_required",
                "detail": "请输入验证器上的 6 位验证码",
                "recovery_left": totp_lib.remaining_recovery_codes(user),
            })
        ok = totp_lib.verify_device(device, otp)
        by_recovery = False
        if not ok:
            # 验证码不对时再当作恢复码试一次 —— 两个输入框会让人选错,
            # 一个框两种含义在这里是更好的交互
            ok = by_recovery = totp_lib.consume_recovery_code(user, otp)
        if not ok:
            lockout.record_failure(username, ip)
            _audit(request, username, LoginResult.BAD_OTP, user=user)
            return Response({"detail": "验证码不正确或已被使用", "code": "bad_otp"},
                            status=status.HTTP_400_BAD_REQUEST)
        used_2fa = True
        if by_recovery:
            # 用掉一个恢复码是要能在审计里一眼看到的事:它意味着这个人
            # 的验证器出了问题,而且恢复码是有限的
            left = totp_lib.remaining_recovery_codes(user)
            detail = f"用恢复码登录,剩余 {left} 个"

    django_login(request, user)          # 会轮换 session key,防会话固定
    lockout.clear(username, ip)
    _audit(request, username, LoginResult.OK, user=user, used_2fa=used_2fa, detail=detail)
    return Response({"authenticated": True, "user": _me(user)})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    _audit(request, request.user.username, LoginResult.LOGOUT, user=request.user)
    django_logout(request)
    return Response({"authenticated": False})


# ---------------------------------------------------------------- 自助:密码


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password(request):
    serializer = PasswordChangeSerializer(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    if not request.user.check_password(serializer.validated_data["old_password"]):
        return Response({"old_password": ["当前密码不正确"]}, status=status.HTTP_400_BAD_REQUEST)
    request.user.set_password(serializer.validated_data["new_password"])
    request.user.save(update_fields=["password"])
    # set_password 之后不重新登录的话,当前这条会话会因为 session hash 变了
    # 而立刻失效 —— 人刚改完密码就被踢出去,看着像改失败了
    django_login(request, request.user)
    return Response({"detail": "密码已修改"})


# ---------------------------------------------------------------- 自助:两步验证


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def totp_setup(request):
    """
    开始绑定:生成一个**未确认**的密钥,返回二维码。

    未确认的记录不参与登录校验(见 models.TotpDevice)—— 所以这一步可以
    反复点,每点一次换一个新密钥,扫旧码的验证器会失效,这是对的。
    """

    device, _ = TotpDevice.objects.get_or_create(
        user=request.user, defaults={"secret": totp_lib.new_secret()}
    )
    if device.is_active:
        return Response({"detail": "已经绑定过了,要换设备请先解绑"},
                        status=status.HTTP_400_BAD_REQUEST)
    device.secret = totp_lib.new_secret()
    device.last_step = 0
    device.save(update_fields=["secret", "last_step", "updated_at"])

    uri = totp_lib.provisioning_uri(request.user.username, device.secret)
    return Response({
        "secret": device.secret,          # 扫不了码时手动输入用
        "uri": uri,
        "qr_svg": totp_lib.qr_svg(uri),
        "issuer": totp_lib.ISSUER,
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def totp_confirm(request):
    """
    输一次验证码确认绑定,成功后返回恢复码。

    **必须验证一次才算绑定成功。**跳过这一步的话,手机上密钥输错、
    时间不同步这类问题要等到下次登录才暴露,而那时人已经被锁在门外了。
    """

    serializer = OtpConfirmSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    device = getattr(request.user, "totp", None)
    if device is None:
        return Response({"detail": "还没开始绑定,先点「生成二维码」"},
                        status=status.HTTP_400_BAD_REQUEST)
    if device.is_active:
        return Response({"detail": "已经绑定过了"}, status=status.HTTP_400_BAD_REQUEST)
    if not totp_lib.verify_device(device, serializer.validated_data["code"]):
        return Response({"code": ["验证码不正确。检查手机时间是否准确"]},
                        status=status.HTTP_400_BAD_REQUEST)

    device.confirmed_at = timezone.now()
    device.save(update_fields=["confirmed_at", "updated_at"])
    codes = totp_lib.generate_recovery_codes(request.user)
    return Response({
        "detail": "两步验证已开启",
        "recovery_codes": codes,     # 明文只在这里出现一次
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def totp_disable(request):
    """解绑。要再输一次当前密码 —— 会话还在不等于人还在。"""

    serializer = PasswordConfirmSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    if not request.user.check_password(serializer.validated_data["password"]):
        return Response({"password": ["密码不正确"]}, status=status.HTTP_400_BAD_REQUEST)
    TotpDevice.objects.filter(user=request.user).delete()
    RecoveryCode.objects.filter(user=request.user).delete()
    return Response({"detail": "两步验证已关闭"})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def totp_recovery_regenerate(request):
    """重新生成恢复码,旧的全部作废。"""

    serializer = PasswordConfirmSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    if not request.user.check_password(serializer.validated_data["password"]):
        return Response({"password": ["密码不正确"]}, status=status.HTTP_400_BAD_REQUEST)
    device = getattr(request.user, "totp", None)
    if not (device and device.is_active):
        return Response({"detail": "还没开启两步验证"}, status=status.HTTP_400_BAD_REQUEST)
    return Response({"recovery_codes": totp_lib.generate_recovery_codes(request.user)})


# ---------------------------------------------------------------- 管理后台


class UserViewSet(viewsets.ModelViewSet):
    """用户管理。仅管理员(is_staff)。"""

    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]
    queryset = User.objects.all().order_by("-is_superuser", "-is_staff", "username")
    search_fields = ["username", "first_name", "email"]
    ordering_fields = ["username", "last_login", "date_joined"]
    filterset_fields = ["is_active", "is_staff", "is_superuser"]

    def perform_destroy(self, instance: User) -> None:
        # 删掉自己 = 把自己锁在外面,而且删掉最后一个管理员之后没人能再进来。
        # 这两条在序列化器里管不到(那里没有 request),所以放在这里
        if instance.pk == self.request.user.pk:
            raise _bad("不能删除自己")
        if instance.is_staff and User.objects.filter(is_staff=True, is_active=True).count() <= 1:
            raise _bad("这是最后一个管理员,删掉就没人能进管理后台了")
        instance.delete()

    def perform_update(self, serializer) -> None:
        instance = serializer.instance
        data = serializer.validated_data
        if instance.pk == self.request.user.pk:
            if data.get("is_active") is False:
                raise _bad("不能停用自己")
            if data.get("is_staff") is False:
                raise _bad("不能撤销自己的管理员权限")
        # 最后一个管理员被降级/停用,和删掉他是同一个后果
        if (data.get("is_staff") is False or data.get("is_active") is False) and instance.is_staff:
            others = User.objects.filter(is_staff=True, is_active=True).exclude(pk=instance.pk)
            if not others.exists():
                raise _bad("这是最后一个管理员,不能停用或降级")
        serializer.save()

    @action(detail=True, methods=["post"])
    def reset_password(self, request, pk=None):
        """管理员给别人重置密码。用户下次登录用新密码,两步验证不受影响。"""

        target = self.get_object()
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        target.set_password(serializer.validated_data["password"])
        target.save(update_fields=["password"])
        lockout.clear(target.username, None)
        return Response({"detail": f"{target.username} 的密码已重置"})

    @action(detail=True, methods=["post"])
    def disable_2fa(self, request, pk=None):
        """
        强制解绑别人的两步验证。

        **这是手机丢了/验证器被误删时唯一的自救路径**(恢复码也没了的话)。
        它会被记进登录审计 —— 强制解绑等于降低一个账号的安全等级,
        必须留痕,否则事后查不出是谁在什么时候解的。
        """

        target = self.get_object()
        had = TotpDevice.objects.filter(user=target, confirmed_at__isnull=False).exists()
        TotpDevice.objects.filter(user=target).delete()
        RecoveryCode.objects.filter(user=target).delete()
        if had:
            _audit(request, target.username, LoginResult.LOGOUT, user=target,
                   detail=f"管理员 {request.user.username} 强制解绑两步验证")
        return Response({"detail": "已解绑" if had else "该账号本来就没绑"})

    @action(detail=True, methods=["post"])
    def unlock(self, request, pk=None):
        """清掉这个账号的登录失败计数,不用等锁定窗口过去。"""

        target = self.get_object()
        lockout.clear(target.username, None)
        return Response({"detail": f"{target.username} 已解锁"})


class LoginAuditViewSet(viewsets.ReadOnlyModelViewSet):
    """登录审计,只读。审计记录不该有"编辑"这个动作。"""

    serializer_class = LoginAuditSerializer
    permission_classes = [IsAdminUser]
    queryset = LoginAudit.objects.select_related("user").all()
    search_fields = ["username", "ip", "detail"]
    ordering_fields = ["created_at", "username", "result"]
    filterset_fields = ["result", "username", "used_2fa"]


@api_view(["GET"])
@permission_classes([IsAdminUser])
def system_info(request):
    """
    系统信息。把 DEPLOY.md 排查一节里那几条命令搬到页面上 ——
    不然每次都要 `docker compose exec` 进容器敲 SQL。

    这一页的重点是**磁盘**:这是个数据采集平台,涨起来的就是磁盘,
    而"还能撑多久"这个问题在磁盘真的满了之后才问就晚了。
    """

    from netcheck import scheduler
    from netcheck.models import (
        Device,
        DeviceBackup,
        Event,
        FirewallPolicy,
        Notifier,
        ProbeTarget,
        RetentionPolicy,
        Server,
    )

    policy = RetentionPolicy.load()
    info: dict = {
        "version": settings.NETCHECK_VERSION,
        "time": timezone.now(),
        "timezone": settings.TIME_ZONE,
        "debug": settings.DEBUG,
        "tick_seconds": settings.NETCHECK_TICK_SECONDS,
        "raw_retention_hours": policy.raw_hours,
        "session_days": settings.SESSION_COOKIE_AGE // 86400,
        "retention": RetentionPolicySerializer(policy).data,
    }

    # ---- 磁盘 ----
    # 容器里 `/` 是 overlay 挂载,statvfs 返回的是承载 /var/lib/docker 的那块
    # **宿主机磁盘** —— 正是数据会撑爆的那一块,所以不用把宿主机根目录挂进来
    try:
        usage = shutil.disk_usage(settings.NETCHECK_DISK_PATH)
        info["disk"] = {
            "ok": True,
            "path": settings.NETCHECK_DISK_PATH,
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent": round(usage.used / usage.total * 100, 1) if usage.total else None,
        }
    except Exception as exc:  # noqa: BLE001
        info["disk"] = {"ok": False, "error": str(exc)[:200]}

    # 三个依赖各自独立 try —— 一个挂了要能看出是哪一个挂了,
    # 而不是整个接口 500(那时候正是最需要这一页的时候)
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT version()")
            info["database"] = {"ok": True, "version": cur.fetchone()[0].split(",")[0]}
    except Exception as exc:  # noqa: BLE001
        info["database"] = {"ok": False, "error": str(exc)[:200]}

    try:
        info["scheduler"] = {"ok": True, **scheduler.stats()}
    except Exception as exc:  # noqa: BLE001
        info["scheduler"] = {"ok": False, "error": str(exc)[:200]}

    try:
        info["counts"] = {
            "probes": ProbeTarget.objects.count(),
            "probes_enabled": ProbeTarget.objects.filter(enabled=True).count(),
            "devices": Device.objects.count(),
            "servers": Server.objects.count(),
            "servers_enabled": Server.objects.filter(enabled=True).count(),
            "notifiers": Notifier.objects.count(),
            "events": Event.objects.count(),
            # 配置版本是**全文**存的,一份几十 KB 到几 MB —— 它是这张表
            # 里最占地方的东西,而"占了多少"在下面的 tables 里能看到
            "device_backups": DeviceBackup.objects.count(),
            "firewall_policies": FirewallPolicy.objects.count(),
            # **样本表不做 count(\*)。**Postgres 的精确计数要全表扫描,
            # 这张表上千万行时一次几秒钟,而这一页恰恰是磁盘告急时才会打开的
            "samples": _estimated_rows("netcheck_probesample"),
            "samples_estimated": True,
            "users": User.objects.count(),
            "users_active": User.objects.filter(is_active=True).count(),
            "users_2fa": TotpDevice.objects.filter(confirmed_at__isnull=False).count(),
        }
    except Exception as exc:  # noqa: BLE001
        info["counts"] = {"error": str(exc)[:200]}

    # ---- 增长估算 ----
    # 不去查表算增速(那要扫大表),直接从**线路配置**推:每条线路每天写
    # 86400/间隔 行,这是确定的。单行字节数用"表大小 ÷ 估算行数"反推。
    try:
        per_day = sum(
            86400 / max(1, iv) for iv in
            ProbeTarget.objects.filter(enabled=True).values_list("interval_seconds", flat=True)
        )
        rows = _estimated_rows("netcheck_probesample")
        size = _table_bytes("netcheck_probesample")
        per_row = (size / rows) if rows and size else None
        info["growth"] = {
            "rows_per_day": int(per_day),
            "bytes_per_row": round(per_row, 1) if per_row else None,
            "bytes_per_day": int(per_day * per_row) if per_row else None,
            # 保留期内的稳态占用 —— 清理跑起来之后原始表会稳定在这个量级
            "steady_bytes": int(per_day * policy.raw_hours / 24 * per_row) if per_row else None,
        }
    except Exception as exc:  # noqa: BLE001
        info["growth"] = {"error": str(exc)[:200]}

    # 表占用。原始秒级样本是磁盘的主要消费者 —— "磁盘涨得快"的第一现场
    try:
        with connection.cursor() as cur:
            cur.execute("""
                SELECT relname, pg_total_relation_size(relid),
                       pg_size_pretty(pg_total_relation_size(relid))
                FROM pg_catalog.pg_statio_user_tables
                ORDER BY pg_total_relation_size(relid) DESC LIMIT 12
            """)
            info["tables"] = [
                {"name": name, "bytes": size, "pretty": pretty}
                for name, size, pretty in cur.fetchall()
            ]
    except Exception as exc:  # noqa: BLE001
        info["tables"] = []
        info["tables_error"] = str(exc)[:200]

    return Response(info)


def _bad(message: str):
    from rest_framework.exceptions import ValidationError

    return ValidationError({"detail": message})


def _estimated_rows(table: str) -> int | None:
    """
    行数估算,取自 pg_class.reltuples(ANALYZE 维护的统计值)。

    **不用 count(*)**:精确计数要全表扫描,而这张表可能上千万行 ——
    这一页正是磁盘告急时打开的,那时候不能再压一次全表扫描上去。
    估算值在 autovacuum 跑过之后误差通常在百分之几,对"还能撑多久"够用了。
    """

    try:
        with connection.cursor() as cur:
            cur.execute("SELECT reltuples::bigint FROM pg_class WHERE relname = %s", [table])
            row = cur.fetchone()
        return max(0, int(row[0])) if row and row[0] is not None else None
    except Exception:  # noqa: BLE001
        return None


def _table_bytes(table: str) -> int | None:
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT pg_total_relation_size(to_regclass(%s))", [table])
            row = cur.fetchone()
        return int(row[0]) if row and row[0] is not None else None
    except Exception:  # noqa: BLE001
        return None


@api_view(["GET", "PATCH"])
@permission_classes([IsAdminUser])
def retention(request):
    """
    数据保留策略的读写。

    改这个的典型场景是**磁盘快满了的半夜** —— 所以它必须是页面上点几下就能改的,
    而不是改环境变量 + 重启容器。改完下一次清理任务(每小时)就按新值执行,
    不用重启任何进程。
    """

    from netcheck.models import RetentionPolicy

    policy = RetentionPolicy.load()
    if request.method == "GET":
        return Response(RetentionPolicySerializer(policy).data)

    serializer = RetentionPolicySerializer(policy, data=request.data, partial=True)
    serializer.is_valid(raise_exception=True)
    serializer.save(updated_by=request.user.username[:64])
    log.info("保留策略被 %s 修改为 %s", request.user.username, serializer.data)
    return Response(serializer.data)
