"""Metadata record builder for encrypted file objects."""

from __future__ import annotations

import base64
from datetime import datetime


def build_file_record(filename: str, object_id: str, size: int, iv: bytes) -> dict:
    """Build a JSON-serializable file record for the encrypted index."""
    return {
        "filename": filename,
        "object_id": object_id,
        "size": size,
        "iv": base64.b64encode(iv).decode("ascii"),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
