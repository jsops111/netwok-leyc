"""
账号、两步验证、登录审计。

这里只有三张表,但有三条不能改的规矩:

1. **TOTP 密钥落库必须加密。**它和 SNMP community、SSH 口令是同一级别的东西 ——
   拿到密钥就能永久生成别人的验证码,而且当事人毫无察觉。用的是和设备凭据
   同一个 `core.crypto.EncryptedTextField`(密钥来自 NETCHECK_ENCRYPTION_KEY)。

2. **验证过的时间步要记下来(`last_step`)。**TOTP 一个码在 30 秒窗口内一直有效,
   不记的话:肩窥/日志里捞到一个码的人,在这 30 秒里能拿它再登一次。
   记下来之后同一个 step 只能用一次。

3. **恢复码只存哈希,而且只在生成的那一次返回明文。**它等价于密码,
   库里存明文等于 2FA 白做。用 sha256 而不是 Django 的 password hasher:
   恢复码是我们自己生成的高熵随机串(50 bit),不需要抗字典攻击的慢哈希,
   而登录时要逐个比对十个码 —— 十次 pbkdf2 会让登录明显变慢。
"""

from __future__ import annotations

from django.contrib.auth.models import User
from django.db import models

from core.crypto import EncryptedTextField
from core.models import TimeStampedModel


class LoginResult(models.TextChoices):
    """登录审计里那一列。**失败原因要分得开** —— "密码错"和"验证码错"
    在排查时是完全不同的两件事:前者可能是有人在试口令,后者通常是
    自己手机时间不对。"""

    OK = "ok", "登录成功"
    BAD_PASSWORD = "bad_password", "密码错误"
    BAD_OTP = "bad_otp", "验证码错误"
    OTP_REQUIRED = "otp_required", "待输入验证码"
    INACTIVE = "inactive", "账号已停用"
    LOCKED = "locked", "已锁定(失败次数过多)"
    LOGOUT = "logout", "退出登录"


class TotpDevice(TimeStampedModel):
    """
    一个用户一个 TOTP 绑定。**绑定是自愿的** —— 平台不强制两步验证,
    没有这条记录就是只用密码登录。

    `confirmed_at` 为空表示"扫了码但还没验证成功",这种半成品记录不参与登录校验:
    否则用户扫码后关掉页面,下次登录就会被一个他从没验证过的密钥锁在门外。
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="totp", verbose_name="用户"
    )
    secret = EncryptedTextField("TOTP 密钥(base32,落库加密)")
    confirmed_at = models.DateTimeField("绑定确认时间", null=True, blank=True)
    last_step = models.BigIntegerField("最后使用的时间步", default=0)
    last_used_at = models.DateTimeField("最后验证时间", null=True, blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "两步验证绑定"

    def __str__(self) -> str:
        return f"{self.user.username} 的两步验证"

    @property
    def is_active(self) -> bool:
        return self.confirmed_at is not None


class RecoveryCode(models.Model):
    """
    一次性恢复码。手机丢了/验证器被删干净时的自救路径 ——
    没有它,唯一的出路是让管理员在后台强制解绑,而管理员自己被锁在外面时无解。
    """

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="recovery_codes", verbose_name="用户"
    )
    code_hash = models.CharField("恢复码哈希", max_length=64, db_index=True)
    created_at = models.DateTimeField("生成时间", auto_now_add=True)
    used_at = models.DateTimeField("使用时间", null=True, blank=True)

    class Meta:
        verbose_name = verbose_name_plural = "恢复码"
        indexes = [models.Index(fields=["user", "used_at"])]

    def __str__(self) -> str:
        return f"{self.user.username} 的恢复码({'已用' if self.used_at else '未用'})"


class LoginAudit(models.Model):
    """
    登录审计。**成功和失败都记** —— 只记失败回答不了"这个账号昨晚是谁在用",
    只记成功回答不了"是不是有人在爆破"。

    `username` 是独立字段而不是只靠外键:登录失败时可能根本没有这个用户,
    而"有人在试一个不存在的用户名"恰恰是要看到的信号。
    """

    username = models.CharField("用户名", max_length=150, db_index=True)
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="login_audits", verbose_name="用户",
    )
    result = models.CharField(
        "结果", max_length=20, choices=LoginResult.choices, db_index=True
    )
    used_2fa = models.BooleanField("走了两步验证", default=False)
    ip = models.GenericIPAddressField("来源 IP", null=True, blank=True)
    user_agent = models.CharField("浏览器标识", max_length=300, blank=True)
    detail = models.CharField("补充说明", max_length=200, blank=True)
    created_at = models.DateTimeField("时间", auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = verbose_name_plural = "登录审计"
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["-created_at", "result"])]

    def __str__(self) -> str:
        return f"[{self.created_at:%F %T}] {self.username} {self.get_result_display()}"
