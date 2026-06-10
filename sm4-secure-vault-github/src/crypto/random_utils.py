"""Random byte and object-id generation helpers."""

from __future__ import annotations

import secrets

import config


def generate_salt(length: int = config.SALT_SIZE) -> bytes:
    """Generate a cryptographic random salt."""
    return secrets.token_bytes(length)


def generate_iv(length: int = config.IV_SIZE) -> bytes:
    """Generate a cryptographic random IV."""
    return secrets.token_bytes(length)


def generate_object_id() -> str:
    """Generate a random encrypted object filename."""
    return f"{secrets.token_hex(16)}.enc"
