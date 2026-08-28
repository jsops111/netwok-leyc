from django.contrib import admin

from accounts.models import LoginAudit, RecoveryCode, TotpDevice


@admin.register(TotpDevice)
class TotpDeviceAdmin(admin.ModelAdmin):
    list_display = ["user", "confirmed_at", "last_used_at", "created_at"]
    list_filter = ["confirmed_at"]
    search_fields = ["user__username"]
    # secret 是加密字段,但 Django admin 会把它解密后原样显示出来 ——
    # 密钥出现在任何一块屏幕上都等于泄露,所以整个表单只读且不含它
    readonly_fields = ["user", "confirmed_at", "last_step", "last_used_at"]
    exclude = ["secret", "meta"]


@admin.register(RecoveryCode)
class RecoveryCodeAdmin(admin.ModelAdmin):
    list_display = ["user", "created_at", "used_at"]
    list_filter = ["used_at"]
    search_fields = ["user__username"]
    readonly_fields = ["user", "code_hash", "created_at", "used_at"]


@admin.register(LoginAudit)
class LoginAuditAdmin(admin.ModelAdmin):
    list_display = ["created_at", "username", "result", "used_2fa", "ip"]
    list_filter = ["result", "used_2fa"]
    search_fields = ["username", "ip", "detail"]
    date_hierarchy = "created_at"

    # 审计记录不能改也不能新增 —— 能改的审计不是审计
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
