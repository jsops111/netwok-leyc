from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    # Django 自带后台。页面上的「管理后台」是 /manage(前端),两者不是一回事:
    # 这个是给开发/救急用的原始表格,那个是给运维用的
    path("admin/", admin.site.urls),
    # 账号、两步验证、用户管理、登录审计、系统信息
    path("api/", include("accounts.urls")),
    path("api/", include("netcheck.urls")),
]
