"""
账号相关序列化器。

和 netcheck 那边同一条规矩:**跨字段校验写在这里,不能只写在 Model.clean()** ——
DRF 从不调用 full_clean(),而页面上所有写入都走 API。
"""

from __future__ import annotations

from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from accounts.models import LoginAudit
from accounts.totp import remaining_recovery_codes


def _check_password_strength(value: str, user: User | None = None) -> str:
    """把 Django 的密码校验器接到 DRF 的错误格式上。"""

    try:
        validate_password(value, user)
    except DjangoValidationError as exc:
        raise serializers.ValidationError(list(exc.messages)) from exc
    return value


class MeSerializer(serializers.ModelSerializer):
    """当前登录者。前端靠 `is_staff` 决定「用户管理」这个 tab 显不显示。"""

    display_name = serializers.CharField(source="first_name", read_only=True)
    two_factor = serializers.SerializerMethodField()
    recovery_left = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id", "username", "display_name", "email",
            "is_staff", "is_superuser", "last_login",
            "two_factor", "recovery_left",
        ]

    def get_two_factor(self, obj: User) -> bool:
        device = getattr(obj, "totp", None)
        return bool(device and device.is_active)

    def get_recovery_left(self, obj: User) -> int:
        return remaining_recovery_codes(obj)


class UserSerializer(serializers.ModelSerializer):
    """
    用户管理表格用。

    `password` 是 write_only 且**新建时必填、编辑时留空表示不改** ——
    和配置中心那些凭据字段一个规矩(留空 = 不修改),否则编辑一次昵称
    就会把密码清空。
    """

    display_name = serializers.CharField(
        source="first_name", required=False, allow_blank=True, max_length=150,
        label="姓名",
    )
    password = serializers.CharField(
        write_only=True, required=False, allow_blank=True, style={"input_type": "password"},
        help_text="留空表示不修改",
    )
    two_factor = serializers.SerializerMethodField()
    recovery_left = serializers.SerializerMethodField()
    last_login_ip = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id", "username", "display_name", "email", "password",
            "is_active", "is_staff", "is_superuser",
            "last_login", "date_joined",
            "two_factor", "recovery_left", "last_login_ip",
        ]
        read_only_fields = ["last_login", "date_joined"]

    def get_two_factor(self, obj: User) -> bool:
        device = getattr(obj, "totp", None)
        return bool(device and device.is_active)

    def get_recovery_left(self, obj: User) -> int:
        return remaining_recovery_codes(obj)

    def get_last_login_ip(self, obj: User) -> str:
        row = (
            LoginAudit.objects.filter(user=obj, result="ok")
            .order_by("-created_at")
            .values_list("ip", flat=True)
            .first()
        )
        return row or ""

    def validate_username(self, value: str) -> str:
        value = (value or "").strip()
        if not value:
            raise serializers.ValidationError("用户名不能为空")
        qs = User.objects.filter(username__iexact=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        # 大小写不同的同名账号是审计的噩梦:日志里 Admin 和 admin 看着像同一个人
        if qs.exists():
            raise serializers.ValidationError("这个用户名已经有了(不区分大小写)")
        return value

    def validate(self, attrs: dict) -> dict:
        password = attrs.get("password")
        if self.instance is None and not password:
            raise serializers.ValidationError({"password": "新建用户必须设置初始密码"})
        if password:
            _check_password_strength(password, self.instance)
        # is_superuser 必然是 staff —— 否则会造出一个"有全部权限但进不去后台"
        # 的账号,而页面上看不出为什么
        if attrs.get("is_superuser"):
            attrs["is_staff"] = True
        return attrs

    def create(self, validated_data: dict) -> User:
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

    def update(self, instance: User, validated_data: dict) -> User:
        password = validated_data.pop("password", None)
        for key, value in validated_data.items():
            setattr(instance, key, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class LoginAuditSerializer(serializers.ModelSerializer):
    result_label = serializers.CharField(source="get_result_display", read_only=True)

    class Meta:
        model = LoginAudit
        fields = [
            "id", "username", "user", "result", "result_label",
            "used_2fa", "ip", "user_agent", "detail", "created_at",
        ]


# ---------------------------------------------------------------- 动作型入参


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(style={"input_type": "password"})
    # 只有绑了两步验证的账号才需要,所以是选填 —— 第一步返回 otp_required
    # 之后前端再带上来
    otp = serializers.CharField(required=False, allow_blank=True, max_length=32)


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(style={"input_type": "password"})
    new_password = serializers.CharField(style={"input_type": "password"})

    def validate_new_password(self, value: str) -> str:
        return _check_password_strength(value, self.context.get("request").user)


class PasswordConfirmSerializer(serializers.Serializer):
    """解绑两步验证、重发恢复码这类操作要再输一次当前密码。

    理由:这些操作的后果是"账号的第二道锁没了",而浏览器可能是别人的 ——
    会话还在不等于人还在。"""

    password = serializers.CharField(style={"input_type": "password"})


class OtpConfirmSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=32)


class ResetPasswordSerializer(serializers.Serializer):
    """管理员给别人重置密码。"""

    password = serializers.CharField(style={"input_type": "password"})

    def validate_password(self, value: str) -> str:
        return _check_password_strength(value, None)
