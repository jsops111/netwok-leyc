"""
通用 Webhook 推送。

模板留空时发平台标准 JSON(base.render 里那份 payload) —— 这样对接自己写的
接收端最省事。填了模板则按模板渲染,用来对接钉钉/企业微信/飞书这类
**要求特定 JSON 结构**的机器人:它们不接受任意字段,必须是
`{"msgtype":"text","text":{"content":"..."}}` 这种形状。

模板渲染用 str.format_map 而不是 Jinja:占位符替换是这里的全部需求,
引入模板引擎意味着模板里能跑逻辑,而这个字段是从页面上填进来的。
"""

from __future__ import annotations

import json

import requests

from netcheck.models import Notifier

from .base import Message


class _SafeDict(dict):
    """模板里写了不存在的占位符时保留原样,不抛 KeyError —— 一个笔误不该让告警发不出去。"""

    def __missing__(self, key):
        return "{" + key + "}"


def render_template(template: str, payload: dict) -> str:
    flat = {k: ("" if v is None else v) for k, v in payload.items()}
    try:
        return template.format_map(_SafeDict(flat))
    except (ValueError, IndexError) as exc:
        # 模板里有落单的 { 或 } —— 把原始模板发出去总比什么都不发好
        return f"{template}\n\n[模板渲染失败: {exc}]"


def send(notifier: Notifier, message: Message) -> tuple[bool, int | None, str]:
    url = notifier.webhook_url
    if not url:
        return False, None, "未配置 Webhook 地址"

    method = (notifier.webhook_method or "POST").upper()
    headers = {"Content-Type": "application/json", "User-Agent": "network-check/0.1"}
    if isinstance(notifier.webhook_headers, dict):
        headers.update({str(k): str(v) for k, v in notifier.webhook_headers.items()})

    if notifier.webhook_template:
        rendered = render_template(notifier.webhook_template, message.payload)
        # 模板渲染出的东西如果本身是合法 JSON,就当 JSON 发(钉钉那类);
        # 否则当纯文本 body 发 —— 两种接收端都有,靠内容自己判断比加个开关好
        try:
            body = json.loads(rendered)
            data, json_body = None, body
        except json.JSONDecodeError:
            data, json_body = rendered.encode("utf-8"), None
    else:
        data, json_body = None, message.payload

    try:
        resp = requests.request(
            method, url, headers=headers, json=json_body, data=data,
            timeout=notifier.timeout_seconds, verify=notifier.webhook_verify_tls,
        )
    except requests.Timeout:
        return False, None, f"请求超时(>{notifier.timeout_seconds}s)"
    except requests.RequestException as exc:
        return False, None, f"请求失败: {str(exc)[:180]}"

    if 200 <= resp.status_code < 300:
        return True, resp.status_code, f"HTTP {resp.status_code} {resp.text[:120]}"
    return False, resp.status_code, f"HTTP {resp.status_code}: {resp.text[:180]}"


def verify(notifier: Notifier) -> tuple[bool, str]:
    ok, code, detail = send(
        notifier,
        Message(
            title="测试",
            text="network-check 通道测试",
            payload={
                "event_id": 0, "status": "test", "phase": "test",
                "severity": "info", "severity_label": "提示",
                "kind": "test", "kind_label": "通道测试",
                "source_type": "probe", "source": "配置中心测试",
                "title": "network-check 通道测试",
                "message": "这条消息说明 Webhook 地址是通的。",
                "value": None, "threshold": None, "unit": "", "fail_count": 0,
                "started_at": "", "resolved_at": None, "duration_s": None, "duration": "-",
            },
        ),
    )
    return (True, f"已送达({detail})") if ok else (False, detail)
