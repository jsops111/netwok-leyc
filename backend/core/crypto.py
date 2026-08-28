"""
凭据字段的对称加密。

密钥来自 settings.NETCHECK_ENCRYPTION_KEY,与 DJANGO_SECRET_KEY 分开保管 ——
这样轮换 Django secret 不会导致已存的 SNMP community / SSH 口令解不开。

库里存的是带 "fernet:" 前缀的密文,前缀便于识别以及后续做密钥轮换迁移。
"""

from __future__ import annotations

from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import models

CIPHER_PREFIX = "fernet:"


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    return Fernet(settings.NETCHECK_ENCRYPTION_KEY.encode())


def encrypt(plaintext: str) -> str:
    if plaintext in (None, ""):
        return ""
    return CIPHER_PREFIX + _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    if ciphertext in (None, ""):
        return ""
    if not ciphertext.startswith(CIPHER_PREFIX):
        # 尚未加密的历史数据 —— 原样返回,下次保存时自动加密
        return ciphertext
    try:
        return _fernet().decrypt(ciphertext[len(CIPHER_PREFIX):].encode()).decode()
    except InvalidToken:
        # 密钥已轮换 / 数据被篡改。不抛异常,否则整个列表接口 500。
        return ""


class EncryptedTextField(models.TextField):
    """
    读写自动加解密的 TextField。

    Python 侧始终是明文,落库始终是密文。代价是无法在 SQL 里对该字段过滤或
    排序 —— 这是有意的,凭据本来就不该被检索。
    """

    def get_prep_value(self, value):
        if value is None:
            return None
        return encrypt(str(value))

    def from_db_value(self, value, expression, connection):
        return decrypt(value) if value is not None else None
