"""
TOTP(RFC 6238)与恢复码。

算法本身交给 `pyotp`,这个文件负责的是**围绕算法的那几个容易做错的决定**:

- **验证窗口只放宽 ±1 步(±30 秒)。**放宽到 ±2 是常见的"体贴"做法,
  代价是一个码的有效期变成 2.5 分钟 —— 那正好是别人从你屏幕上看一眼、
  走回工位再输进去的时间。手机时间偏差超过 30 秒是设备该修的问题,
  不是这里该迁就的问题。
- **验证成功后记下时间步,同一步不再接受。**见 models.py 的第 2 条。
- **二维码在后端渲染成 SVG。**前端不引 QR 库:一个只在绑定时用一次的功能,
  不值得让每个访问大屏的人都下载一份 QR 生成器。SVG 也不需要 Pillow。
"""

from __future__ import annotations

import hashlib
import io
import secrets
from typing import TYPE_CHECKING

import pyotp
import qrcode
import qrcode.image.svg
from django.utils import timezone

if TYPE_CHECKING:
    from django.contrib.auth.models import User

    from accounts.models import TotpDevice

ISSUER = "NET-CHECK"

# 恢复码字母表:去掉 0/O/1/I/L 这些抄的时候会认错的字符。
# 用户是从屏幕上抄到纸上再敲回来的,认错一个字符就是一次无谓的失败。
_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_CODE_LEN = 10          # 31^10 ≈ 2^49,足够抗在线爆破(何况有登录锁定)
_CODE_COUNT = 10


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(username: str, secret: str) -> str:
    """otpauth:// URI —— 验证器 App 扫的就是这个。"""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def qr_svg(uri: str) -> str:
    """把 URI 画成 SVG 字符串。前端直接塞进 DOM,不用 QR 库。"""
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, border=1)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


def check_code(secret: str, code: str) -> int | None:
    """
    校验一个 6 位码。通过返回它对应的**时间步**,不通过返回 None。

    返回时间步而不是 True 是为了让调用方能做重放检查 —— 见 verify_device()。
    """

    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    now = timezone.now()
    for offset in (0, -1, 1):          # 只放宽 ±1 步
        step = totp.timecode(now) + offset
        if secrets.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def verify_device(device: TotpDevice, code: str) -> bool:
    """
    校验并**消费**一个码。同一个时间步只接受一次(防重放)。

    通过时顺手更新 last_step / last_used_at —— 放在这里而不是调用方,
    是因为忘记更新的后果(重放窗口重新打开)在测试里看不出来。
    """

    step = check_code(device.secret, code)
    if step is None or step <= device.last_step:
        return False
    device.last_step = step
    device.last_used_at = timezone.now()
    device.save(update_fields=["last_step", "last_used_at", "updated_at"])
    return True


# ---------------------------------------------------------------- 恢复码


def _hash(code: str) -> str:
    return hashlib.sha256(normalize_recovery(code).encode()).hexdigest()


def normalize_recovery(code: str) -> str:
    """抄写容错:大小写、空格、连字符都不计较。"""
    return (code or "").upper().replace("-", "").replace(" ", "").strip()


def _format(raw: str) -> str:
    return f"{raw[:5]}-{raw[5:]}"


def generate_recovery_codes(user: User) -> list[str]:
    """
    重新生成一整套恢复码,**旧的全部作废**。

    返回明文,而且**这是明文唯一一次出现的地方** —— 库里只有哈希,
    页面关掉就再也拿不回来了。这一点必须在界面上写清楚。
    """

    from accounts.models import RecoveryCode

    RecoveryCode.objects.filter(user=user).delete()
    codes = ["".join(secrets.choice(_ALPHABET) for _ in range(_CODE_LEN))
             for _ in range(_CODE_COUNT)]
    RecoveryCode.objects.bulk_create(
        [RecoveryCode(user=user, code_hash=_hash(c)) for c in codes]
    )
    return [_format(c) for c in codes]


def consume_recovery_code(user: User, code: str) -> bool:
    """用掉一个恢复码。一次性 —— 用过的标记 used_at,不删除(审计要看得到)。"""

    from accounts.models import RecoveryCode

    normalized = normalize_recovery(code)
    if len(normalized) != _CODE_LEN:
        return False
    row = RecoveryCode.objects.filter(
        user=user, used_at__isnull=True, code_hash=_hash(normalized)
    ).first()
    if not row:
        return False
    row.used_at = timezone.now()
    row.save(update_fields=["used_at"])
    return True


def remaining_recovery_codes(user: User) -> int:
    from accounts.models import RecoveryCode

    return RecoveryCode.objects.filter(user=user, used_at__isnull=True).count()
