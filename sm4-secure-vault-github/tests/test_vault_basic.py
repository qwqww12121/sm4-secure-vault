"""End-to-end tests for vault initialization and file operations."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import config
from vault_core import add_file, extract_file, init_vault, list_files, remove_file


class TestVaultBasic(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.old_vault = config.VAULT_DIR
        self.old_iterations = config.KDF_ITERATIONS
        config.set_vault_dir(self.tmp / "vault_data")
        config.KDF_ITERATIONS = 1000
        self.sample = self.tmp / "sample.txt"
        self.sample.write_text("hello secure vault\n这是测试内容\n", encoding="utf-8")

    def tearDown(self) -> None:
        config.set_vault_dir(self.old_vault)
        config.KDF_ITERATIONS = self.old_iterations
        shutil.rmtree(self.tmp)

    def test_init_add_list_extract_remove(self) -> None:
        init_vault("correct password")
        add_file(str(self.sample), "correct password")

        records = list_files("correct password")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["filename"], "sample.txt")

        output_dir = self.tmp / "out"
        extracted = extract_file("sample.txt", str(output_dir), "correct password")
        self.assertEqual(extracted.read_bytes(), self.sample.read_bytes())

        remove_file("sample.txt", "correct password")
        self.assertEqual(list_files("correct password"), [])


if __name__ == "__main__":
    unittest.main()
