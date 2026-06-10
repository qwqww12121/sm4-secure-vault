"""SM4 block cipher modes used by the secure vault."""

from __future__ import annotations

from config import BLOCK_SIZE
from crypto.padding import pkcs7_pad, pkcs7_unpad
from crypto.sm4 import (
    expand_key,
    sm4_decrypt_block_with_round_keys,
    sm4_encrypt_block_with_round_keys,
)


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def sm4_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt plaintext with SM4-CBC and PKCS#7 padding."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be exactly 16 bytes")

    round_keys = expand_key(key)
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    prev = iv
    blocks: list[bytes] = []
    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        encrypted = sm4_encrypt_block_with_round_keys(_xor_bytes(block, prev), round_keys)
        blocks.append(encrypted)
        prev = encrypted
    return b"".join(blocks)


def sm4_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt SM4-CBC ciphertext and remove PKCS#7 padding."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be exactly 16 bytes")
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a positive multiple of 16 bytes")

    round_keys = expand_key(key)
    prev = iv
    blocks: list[bytes] = []
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        decrypted = sm4_decrypt_block_with_round_keys(block, round_keys)
        blocks.append(_xor_bytes(decrypted, prev))
        prev = block
    return pkcs7_unpad(b"".join(blocks), BLOCK_SIZE)
