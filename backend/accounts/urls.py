"""
账号与管理后台的路由。

分两段挂载(见 config/urls.py):

    /api/auth/     登录相关。login/session 是放开的,其余要登录
    /api/manage/   管理后台。**整段仅 is_staff**,权限写在视图上不是写在路由上
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from accounts import views

router = DefaultRouter()
router.register("users", views.UserViewSet, basename="user")
router.register("login-audit", views.LoginAuditViewSet, basename="login-audit")

auth_patterns = [
    path("session/", views.session, name="auth-session"),
    path("login/", views.login_view, name="auth-login"),
    path("logout/", views.logout_view, name="auth-logout"),
    path("password/", views.change_password, name="auth-password"),
    path("2fa/setup/", views.totp_setup, name="auth-2fa-setup"),
    path("2fa/confirm/", views.totp_confirm, name="auth-2fa-confirm"),
    path("2fa/disable/", views.totp_disable, name="auth-2fa-disable"),
    path("2fa/recovery/", views.totp_recovery_regenerate, name="auth-2fa-recovery"),
]

manage_patterns = [
    path("", include(router.urls)),
    path("system/", views.system_info, name="manage-system"),
]

urlpatterns = [
    path("auth/", include(auth_patterns)),
    path("manage/", include(manage_patterns)),
]
