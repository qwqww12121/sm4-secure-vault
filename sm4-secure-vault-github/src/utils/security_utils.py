"""Best-effort local filesystem hardening helpers.

Python cannot guarantee full secure memory wiping or SSD-safe file erasure, but
these helpers improve the local-storage behavior without adding dependencies.
"""

from __future__ import annotations

import os
from pathlib import Path


def restrict_permissions(path: str | Path, directory: bool = False) -> None:
    """Apply owner-only permissions where the platform honors chmod."""
    mode = 0o700 if directory else 0o600
    try:
        os.chmod(Path(path), mode)
    except OSError:
        # Windows ACLs and some filesystems may ignore or reject POSIX modes.
        pass


def secure_delete(path: str | Path) -> None:
    """Overwrite a file with zero bytes before unlinking it, best effort only."""
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        return

    try:
        size = file_path.stat().st_size
        with file_path.open("r+b") as file:
            chunk = b"\x00" * min(size, 1024 * 1024)
            remaining = size
            while remaining > 0:
                written = min(remaining, len(chunk))
                file.write(chunk[:written])
                remaining -= written
            file.flush()
            os.fsync(file.fileno())
    except OSError:
        pass
    try:
        file_path.unlink()
    except FileNotFoundError:
        pass


def wipe_bytearray(data: bytearray) -> None:
    """Overwrite a mutable bytearray in place."""
    for index in range(len(data)):
        data[index] = 0
