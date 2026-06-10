"""Password-based key derivation and verifier helpers."""

from __future__ import annotations

import hashlib
import hmac

import config
from utils.security_utils import wipe_bytearray

VERIFIER_CONTEXT = b"SM4_SECURE_VAULT_PASSWORD_VERIFIER_V1"


def derive_keys(password: str, salt: bytes, iterations: int | None = None) -> tuple[bytes, bytes]:
    """Derive a 16-byte encryption key and a 32-byte authentication key."""
    if not isinstance(password, str):
        raise TypeError("password must be str")
    if not salt:
        raise ValueError("salt must not be empty")

    rounds = iterations if iterations is not None else config.KDF_ITERATIONS
    key_material = bytearray(hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        rounds,
        dklen=48,
    ))
    try:
        return bytes(key_material[:16]), bytes(key_material[16:])
    finally:
        wipe_bytearray(key_material)


def make_password_verifier(auth_key: bytes, salt: bytes) -> str:
    """Build an HMAC verifier for checking future password attempts."""
    return hmac.new(auth_key, VERIFIER_CONTEXT + salt, hashlib.sha256).hexdigest()


def verify_password(auth_key: bytes, salt: bytes, verifier: str) -> bool:
    """Return True when auth_key matches the stored password verifier."""
    expected = make_password_verifier(auth_key, salt)
    return hmac.compare_digest(expected, verifier)
