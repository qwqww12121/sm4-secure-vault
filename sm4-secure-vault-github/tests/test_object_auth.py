"""Tests for encrypted file object authentication."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import config
from exceptions import InvalidCiphertextError
from vault_core import add_file, extract_file, init_vault


class TestObjectAuthentication(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.old_vault = config.VAULT_DIR
        self.old_iterations = config.KDF_ITERATIONS
        config.set_vault_dir(self.tmp / "vault_data")
        config.KDF_ITERATIONS = 1000
        self.sample = self.tmp / "sample.txt"
        self.sample.write_text("authenticated object test", encoding="utf-8")

    def tearDown(self) -> None:
        config.set_vault_dir(self.old_vault)
        config.KDF_ITERATIONS = self.old_iterations
        shutil.rmtree(self.tmp)

    def test_tampered_object_is_rejected_before_plaintext_output(self) -> None:
        init_vault("correct password")
        add_file(str(self.sample), "correct password")

        object_path = next(config.OBJECTS_DIR.glob("*.enc"))
        raw = bytearray(object_path.read_bytes())
        raw[-10] ^= 1
        object_path.write_bytes(bytes(raw))

        with self.assertRaises(InvalidCiphertextError):
            extract_file("sample.txt", str(self.tmp / "out"), "correct password")
        self.assertFalse((self.tmp / "out" / "sample.txt").exists())


if __name__ == "__main__":
    unittest.main()
