"""Encrypted index file manager.

The on-disk index is authenticated and encrypted. Only the outer container
fields (IV, ciphertext, and MAC) are stored as readable JSON.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from binascii import Error as Base64Error

import config
from crypto.random_utils import generate_iv
from crypto.sm4_modes import sm4_cbc_decrypt, sm4_cbc_encrypt
from exceptions import InvalidCiphertextError, WrongPasswordError
from utils.security_utils import restrict_permissions


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def _mac(auth_key: bytes, iv: bytes, ciphertext: bytes) -> str:
    return hmac.new(auth_key, iv + ciphertext, hashlib.sha256).hexdigest()


def create_empty_index(enc_key: bytes, auth_key: bytes) -> None:
    """Create an encrypted empty index."""
    save_index({"version": "1.0", "files": []}, enc_key, auth_key)


def load_index(enc_key: bytes, auth_key: bytes) -> dict:
    """Load, authenticate, and decrypt the index."""
    try:
        raw = config.INDEX_FILE.read_text(encoding="utf-8")
        container = json.loads(raw)
        iv = _b64decode(container["iv"])
        ciphertext = _b64decode(container["ciphertext"])
        stored_mac = container["mac"]
    except (OSError, KeyError, json.JSONDecodeError, UnicodeDecodeError, Base64Error, TypeError) as exc:
        raise InvalidCiphertextError("index.enc is missing or malformed") from exc

    actual_mac = _mac(auth_key, iv, ciphertext)
    if not hmac.compare_digest(actual_mac, stored_mac):
        raise WrongPasswordError("wrong password or modified encrypted index")

    try:
        plaintext = sm4_cbc_decrypt(ciphertext, enc_key, iv)
        index = json.loads(plaintext.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InvalidCiphertextError("encrypted index cannot be decrypted") from exc

    if not isinstance(index, dict) or "files" not in index or not isinstance(index["files"], list):
        raise InvalidCiphertextError("decrypted index has invalid structure")
    return index


def save_index(index: dict, enc_key: bytes, auth_key: bytes) -> None:
    """Encrypt, authenticate, and save the index."""
    config.VAULT_DIR.mkdir(parents=True, exist_ok=True)
    restrict_permissions(config.VAULT_DIR, directory=True)
    plaintext = json.dumps(index, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    iv = generate_iv()
    ciphertext = sm4_cbc_encrypt(plaintext, enc_key, iv)
    container = {
        "iv": _b64encode(iv),
        "ciphertext": _b64encode(ciphertext),
        "mac": _mac(auth_key, iv, ciphertext),
    }
    config.INDEX_FILE.write_text(
        json.dumps(container, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    restrict_permissions(config.INDEX_FILE)
