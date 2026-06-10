"""Core encrypted vault operations."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

import config
from crypto.kdf import derive_keys, make_password_verifier, verify_password
from crypto.random_utils import generate_iv, generate_object_id, generate_salt
from crypto.sm4_modes import sm4_cbc_decrypt, sm4_cbc_encrypt
from exceptions import (
    FileAlreadyExistsError,
    FileNotFoundInVaultError,
    InvalidCiphertextError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
    WrongPasswordError,
)
from storage.file_manager import (
    delete_cipher_file,
    load_cipher_file,
    read_plain_file,
    save_cipher_file,
    write_plain_file,
)
from storage.decoy_manager import add_decoy_file, extract_decoy_file, list_decoy_files, remove_decoy_file
from storage.index_manager import create_empty_index, load_index, save_index
from storage.metadata import build_file_record
from utils.path_utils import ensure_dir, get_filename, safe_join
from utils.security_utils import restrict_permissions


@dataclass(frozen=True)
class VaultAccess:
    """Password access result for either the real vault or the decoy view."""

    mode: str
    enc_key: bytes | None = None
    auth_key: bytes | None = None


def _read_meta() -> dict:
    try:
        return json.loads(config.META_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VaultNotInitializedError("vault is not initialized") from exc


def _require_initialized() -> None:
    if not config.META_FILE.is_file() or not config.INDEX_FILE.is_file():
        raise VaultNotInitializedError("vault is not initialized; run init first")


def _derive_from_meta(password: str, meta: dict, prefix: str = "") -> tuple[bytes, bytes, bytes, str]:
    salt_key = f"{prefix}salt"
    verifier_key = f"{prefix}verifier"
    try:
        salt = base64.b64decode(meta[salt_key], validate=True)
        verifier = meta[verifier_key]
        iterations = int(meta.get("iterations", config.KDF_ITERATIONS))
    except (KeyError, ValueError, TypeError) as exc:
        raise InvalidCiphertextError("vault.meta is malformed") from exc

    enc_key, auth_key = derive_keys(password, salt, iterations=iterations)
    return enc_key, auth_key, salt, verifier


def _load_access(password: str) -> VaultAccess:
    _require_initialized()
    meta = _read_meta()

    enc_key, auth_key, salt, verifier = _derive_from_meta(password, meta)
    if not verify_password(auth_key, salt, verifier):
        return VaultAccess(mode="decoy")
    return VaultAccess(mode="real", enc_key=enc_key, auth_key=auth_key)


def _load_keys(password: str) -> tuple[bytes, bytes]:
    """Load real vault keys, raising for non-real passwords."""
    access = _load_access(password)
    if access.mode != "real" or access.enc_key is None or access.auth_key is None:
        raise WrongPasswordError("wrong password")
    return access.enc_key, access.auth_key


def _find_record(index: dict, filename: str) -> dict | None:
    return next((record for record in index["files"] if record["filename"] == filename), None)


def init_vault(password: str, decoy_password: str | None = None) -> None:
    """Initialize the vault metadata and encrypted empty index."""
    if config.META_FILE.exists() or config.INDEX_FILE.exists():
        raise VaultAlreadyInitializedError("vault is already initialized")
    if decoy_password and decoy_password == password:
        raise ValueError("decoy password must be different from master password")

    ensure_dir(config.OBJECTS_DIR)
    salt = generate_salt()
    enc_key, auth_key = derive_keys(password, salt)
    meta = {
        "version": "1.0",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": config.KDF_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "verifier": make_password_verifier(auth_key, salt),
    }
    if decoy_password:
        decoy_salt = generate_salt()
        _, decoy_auth_key = derive_keys(decoy_password, decoy_salt)
        meta["decoy"] = {
            "enabled": True,
            "salt": base64.b64encode(decoy_salt).decode("ascii"),
            "verifier": make_password_verifier(decoy_auth_key, decoy_salt),
        }
    config.META_FILE.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    restrict_permissions(config.META_FILE)
    create_empty_index(enc_key, auth_key)


def add_file(file_path: str, password: str) -> dict:
    """Encrypt a plaintext file and add it to the vault."""
    access = _load_access(password)
    if access.mode == "decoy":
        return add_decoy_file(file_path)
    enc_key = access.enc_key
    auth_key = access.auth_key
    if enc_key is None or auth_key is None:
        raise WrongPasswordError("wrong password")
    index = load_index(enc_key, auth_key)
    filename = get_filename(file_path)
    if _find_record(index, filename) is not None:
        raise FileAlreadyExistsError(f"file already exists in vault: {filename}")

    plaintext = read_plain_file(file_path)
    iv = generate_iv()
    ciphertext = sm4_cbc_encrypt(plaintext, enc_key, iv)

    object_id = generate_object_id()
    while (config.OBJECTS_DIR / object_id).exists():
        object_id = generate_object_id()

    save_cipher_file(object_id, ciphertext, auth_key=auth_key, filename=filename, iv=iv)
    record = build_file_record(filename, object_id, len(plaintext), iv)
    index["files"].append(record)
    try:
        save_index(index, enc_key, auth_key)
    except Exception:
        delete_cipher_file(object_id)
        raise
    return record


def list_files(password: str) -> list[dict]:
    """Return decrypted file records from the vault index."""
    access = _load_access(password)
    if access.mode == "decoy":
        return list_decoy_files()
    enc_key = access.enc_key
    auth_key = access.auth_key
    if enc_key is None or auth_key is None:
        raise WrongPasswordError("wrong password")
    index = load_index(enc_key, auth_key)
    return list(index["files"])


def extract_file(filename: str, output_dir: str, password: str) -> Path:
    """Decrypt a stored file and write it into output_dir."""
    access = _load_access(password)
    if access.mode == "decoy":
        return extract_decoy_file(filename, output_dir)
    enc_key = access.enc_key
    auth_key = access.auth_key
    if enc_key is None or auth_key is None:
        raise WrongPasswordError("wrong password")
    index = load_index(enc_key, auth_key)
    record = _find_record(index, filename)
    if record is None:
        raise FileNotFoundInVaultError(f"file not found in vault: {filename}")

    try:
        iv = base64.b64decode(record["iv"], validate=True)
        ciphertext = load_cipher_file(record["object_id"], auth_key=auth_key, filename=filename, iv=iv)
        plaintext = sm4_cbc_decrypt(ciphertext, enc_key, iv)
    except (KeyError, ValueError) as exc:
        raise InvalidCiphertextError("stored file record or ciphertext is invalid") from exc

    output_path = safe_join(ensure_dir(output_dir), filename)
    write_plain_file(str(output_path), plaintext)
    return output_path


def remove_file(filename: str, password: str) -> dict:
    """Delete an encrypted file object and remove its index record."""
    access = _load_access(password)
    if access.mode == "decoy":
        return remove_decoy_file(filename)
    enc_key = access.enc_key
    auth_key = access.auth_key
    if enc_key is None or auth_key is None:
        raise WrongPasswordError("wrong password")
    index = load_index(enc_key, auth_key)
    record = _find_record(index, filename)
    if record is None:
        raise FileNotFoundInVaultError(f"file not found in vault: {filename}")

    delete_cipher_file(record["object_id"])
    index["files"] = [item for item in index["files"] if item["filename"] != filename]
    save_index(index, enc_key, auth_key)
    return record
