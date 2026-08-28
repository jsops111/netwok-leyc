"""
Telegram Bot 推送。

用 sendMessage 的 **plain text**,不开 parse_mode —— Markdown/HTML 模式下
消息里任何一个未转义的 `_`、`*`、`[` 都会让整条消息被 API 拒绝(400
"can't parse entities"),而告警文本里带这些字符是常态:接口名 `Gi1/0/1`、
带下划线的域名、正则片段。为了排版好看丢掉告警,是不划算的交易。
"""

from __future__ import annotations

import requests

from netcheck.models import Notifier

from .base import Message

# Telegram 单条消息上限 4096 字符
_MAX_LEN = 4000


def send(notifier: Notifier, message: Message) -> tuple[bool, int | None, str]:
    """返回 (是否成功, HTTP 状态码, 摘要)。"""

    token = notifier.telegram_bot_token
    if not token:
        return False, None, "未配置 Bot Token"

    base = (notifier.telegram_api_base or "https://api.telegram.org").rstrip("/")
    url = f"{base}/bot{token}/sendMessage"
    text = message.text
    if len(text) > _MAX_LEN:
        text = text[:_MAX_LEN] + "\n…(已截断)"

    payload: dict = {
        "chat_id": notifier.telegram_chat_id,
        "text": text,
        "disable_web_page_preview": True,
    }
    if notifier.telegram_thread_id:
        payload["message_thread_id"] = notifier.telegram_thread_id

    try:
        resp = requests.post(url, json=payload, timeout=notifier.timeout_seconds)
    except requests.Timeout:
        return False, None, f"请求超时(>{notifier.timeout_seconds}s)"
    except requests.RequestException as exc:
        # 内网直连不了 api.telegram.org 是最常见的原因,提示往这个方向引
        return False, None, f"请求失败: {str(exc)[:180]}(内网需在渠道里填反代地址)"

    if resp.status_code == 200 and resp.json().get("ok"):
        return True, 200, "已发送"

    # Telegram 的错误描述很具体(chat not found / bot was blocked),原样带回去
    detail = ""
    try:
        body = resp.json()
        detail = body.get("description") or str(body)[:200]
    except ValueError:
        detail = resp.text[:200]
    return False, resp.status_code, f"HTTP {resp.status_code}: {detail}"


def verify(notifier: Notifier) -> tuple[bool, str]:
    """配置中心「测试」按钮:先 getMe 验 token,再发一条测试消息验 chat_id。"""

    token = notifier.telegram_bot_token
    if not token:
        return False, "未配置 Bot Token"
    base = (notifier.telegram_api_base or "https://api.telegram.org").rstrip("/")
    try:
        me = requests.get(f"{base}/bot{token}/getMe", timeout=notifier.timeout_seconds)
    except requests.RequestException as exc:
        return False, f"无法连接 Telegram API: {str(exc)[:180]}"
    if me.status_code != 200 or not me.json().get("ok"):
        return False, "Bot Token 无效"
    bot_name = me.json().get("result", {}).get("username", "?")

    ok, _, detail = send(
        notifier,
        Message(
            title="测试",
            text="✅ network-check 通道测试\n\n这条消息说明 Bot Token 和 Chat ID 都是通的。",
            payload={},
        ),
    )
    return (True, f"@{bot_name} 测试消息已送达") if ok else (False, f"@{bot_name} 但发送失败:{detail}")
