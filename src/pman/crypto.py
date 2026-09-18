"""加密原语：PBKDF2-HMAC-SHA256 密钥派生 + AES-256-GCM 认证加密。

仅依赖 cryptography（AES-GCM）；KDF 使用标准库 hashlib，避免额外依赖。
测试可通过环境变量 PM_KDF_ITERATIONS 降低迭代次数加速。
"""
from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
DEFAULT_KDF_ITERATIONS = 600_000


def kdf_iterations() -> int:
    raw = os.environ.get("PM_KDF_ITERATIONS", "")
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return DEFAULT_KDF_ITERATIONS


def derive_kek(password: str, salt: bytes) -> bytes:
    """由主密码派生 32 字节密钥加密密钥（KEK）。"""
    if not password:
        raise ValueError("密码不能为空")
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, kdf_iterations(), KEY_BYTES
    )


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM 加密，返回 nonce(12B) || ciphertext || tag(16B)。"""
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt(key: bytes, payload: bytes) -> bytes:
    """解密 encrypt() 的输出；密钥错误或密文被篡改会抛异常。"""
    if len(payload) < NONCE_BYTES + 16:
        raise ValueError("密文长度非法")
    nonce, ct = payload[:NONCE_BYTES], payload[NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ct, None)
