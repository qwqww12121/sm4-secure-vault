"""PKCS#7 padding helpers."""

from __future__ import annotations


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Pad data to an integer number of blocks."""
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be between 1 and 255")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Remove PKCS#7 padding, raising ValueError for malformed input."""
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be between 1 and 255")
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid padded data length")

    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding bytes")
    return data[:-pad_len]
