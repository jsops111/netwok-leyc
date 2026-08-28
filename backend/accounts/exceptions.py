"""
DRF 异常处理:把「没登录」还原成 401。

DRF 默认在**没有 WWW-Authenticate 头可发**的时候,把 NotAuthenticated 当成 403 返回
(SessionAuthentication 就是这种情况)。结果是前端拿到两个含义完全不同、
状态码却一样的 403:

    没登录             → 应该跳登录页
    登录了但不是管理员 → 应该原地提示"没有权限",跳登录页只会让人更迷惑

靠 detail 文案区分是会漂的(Django 改一次翻译就失效)。所以这里把前者还原成
401,并带上稳定的 `code` 字段,前端按 code 判断。
"""

from __future__ import annotations

from rest_framework.exceptions import NotAuthenticated
from rest_framework.views import exception_handler as drf_exception_handler


def api_exception_handler(exc, context):
    response = drf_exception_handler(exc, context)
    if response is not None and isinstance(exc, NotAuthenticated):
        response.status_code = 401
        if isinstance(response.data, dict):
            response.data["code"] = "not_authenticated"
    return response
