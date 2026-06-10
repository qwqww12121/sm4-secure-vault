"""Global configuration for the SM4 secure vault project."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VAULT_DIR = PROJECT_ROOT / "vault_data"
OBJECTS_DIR = VAULT_DIR / "objects"
META_FILE = VAULT_DIR / "vault.meta"
INDEX_FILE = VAULT_DIR / "index.enc"
DECOY_INDEX_FILE = VAULT_DIR / "decoy_index.json"

BLOCK_SIZE = 16
KDF_ITERATIONS = 100000
SALT_SIZE = 16
IV_SIZE = 16


def set_vault_dir(vault_dir: Path) -> None:
    """Redirect vault storage paths, mainly for tests."""
    global VAULT_DIR, OBJECTS_DIR, META_FILE, INDEX_FILE, DECOY_INDEX_FILE

    VAULT_DIR = Path(vault_dir)
    OBJECTS_DIR = VAULT_DIR / "objects"
    META_FILE = VAULT_DIR / "vault.meta"
    INDEX_FILE = VAULT_DIR / "index.enc"
    DECOY_INDEX_FILE = VAULT_DIR / "decoy_index.json"
