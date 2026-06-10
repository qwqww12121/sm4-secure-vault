"""Read and write plaintext files and encrypted vault objects."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

import config
from exceptions import FileNotFoundInVaultError, InvalidCiphertextError
from utils.security_utils import restrict_permissions, secure_delete

OBJECT_MAC_CONTEXT = b"SM4_SECURE_VAULT_FILE_OBJECT_V1"


def _object_path(object_id: str) -> Path:
    if Path(object_id).name != object_id or not object_id.endswith(".enc"):
        raise InvalidCiphertextError("invalid object id")
    return config.OBJECTS_DIR / object_id


def read_plain_file(path: str) -> bytes:
    """Read a plaintext file in binary mode."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"file does not exist: {file_path}")
    return file_path.read_bytes()


def write_plain_file(path: str, data: bytes) -> None:
    """Write a plaintext file in binary mode."""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(data)


def _object_mac(auth_key: bytes, filename: str, iv: bytes, ciphertext: bytes) -> str:
    associated_data = filename.encode("utf-8") + b"\x00" + iv
    return hmac.new(auth_key, OBJECT_MAC_CONTEXT + associated_data + ciphertext, hashlib.sha256).hexdigest()


def save_cipher_file(
    object_id: str,
    data: bytes,
    auth_key: bytes | None = None,
    filename: str | None = None,
    iv: bytes | None = None,
) -> None:
    """Save encrypted object bytes, optionally as an authenticated container."""
    config.OBJECTS_DIR.mkdir(parents=True, exist_ok=True)
    restrict_permissions(config.OBJECTS_DIR, directory=True)
    path = _object_path(object_id)

    if auth_key is not None and filename is not None and iv is not None:
        container = {
            "version": "1.0",
            "algorithm": "SM4-CBC-HMAC-SHA256",
            "ciphertext": base64.b64encode(data).decode("ascii"),
            "mac": _object_mac(auth_key, filename, iv, data),
        }
        path.write_text(json.dumps(container, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        path.write_bytes(data)
    restrict_permissions(path)


def load_cipher_file(
    object_id: str,
    auth_key: bytes | None = None,
    filename: str | None = None,
    iv: bytes | None = None,
) -> bytes:
    """Load encrypted object bytes and verify MAC for new-format objects."""
    path = _object_path(object_id)
    if not path.is_file():
        raise FileNotFoundInVaultError(f"encrypted object is missing: {object_id}")
    raw = path.read_bytes()
    if not raw.lstrip().startswith(b"{"):
        return raw

    if auth_key is None or filename is None or iv is None:
        raise InvalidCiphertextError("file object authentication context is missing")
    try:
        container = json.loads(raw.decode("utf-8"))
        ciphertext = base64.b64decode(container["ciphertext"], validate=True)
        stored_mac = container["mac"]
    except (KeyError, ValueError, json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
        raise InvalidCiphertextError("encrypted file object is malformed") from exc

    actual_mac = _object_mac(auth_key, filename, iv, ciphertext)
    if not hmac.compare_digest(actual_mac, stored_mac):
        raise InvalidCiphertextError("encrypted file object MAC verification failed")
    return ciphertext


def delete_cipher_file(object_id: str) -> None:
    """Delete an encrypted object if it exists."""
    path = _object_path(object_id)
    if path.exists():
        secure_delete(path)
