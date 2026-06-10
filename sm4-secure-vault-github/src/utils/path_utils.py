"""Path helpers used by the vault."""

from __future__ import annotations

from pathlib import Path


def ensure_dir(path: str | Path) -> Path:
    """Create a directory and return it as a Path."""
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def get_filename(path: str | Path) -> str:
    """Return only the final filename component from a path."""
    return Path(path).name


def safe_join(base_dir: str | Path, filename: str) -> Path:
    """Join base_dir and filename while rejecting path traversal."""
    if not filename or Path(filename).name != filename:
        raise ValueError("filename must not contain path separators")

    base = Path(base_dir).resolve()
    target = (base / filename).resolve()
    if target.parent != base:
        raise ValueError("path traversal is not allowed")
    return target
