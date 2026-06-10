"""Tests that wrong passwords enter the decoy view safely."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import config
from vault_core import add_file, extract_file, init_vault, list_files, remove_file


class TestWrongPassword(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.old_vault = config.VAULT_DIR
        self.old_iterations = config.KDF_ITERATIONS
        config.set_vault_dir(self.tmp / "vault_data")
        config.KDF_ITERATIONS = 1000
        self.sample = self.tmp / "sample.txt"
        self.other = self.tmp / "other.txt"
        self.sample.write_text("secret text", encoding="utf-8")
        self.other.write_text("other text", encoding="utf-8")
        init_vault("correct password", decoy_password="backup password")
        add_file(str(self.sample), "correct password")

    def tearDown(self) -> None:
        config.set_vault_dir(self.old_vault)
        config.KDF_ITERATIONS = self.old_iterations
        shutil.rmtree(self.tmp)

    def test_wrong_password_enters_decoy_view(self) -> None:
        decoy_records = list_files("wrong password")
        self.assertGreaterEqual(len(decoy_records), 1)
        self.assertNotIn("sample.txt", {record["filename"] for record in decoy_records})

        decoy_filename = decoy_records[0]["filename"]
        decoy_output = extract_file(decoy_filename, str(self.tmp / "out"), "wrong password")
        self.assertTrue(decoy_output.exists())
        self.assertNotEqual(decoy_output.read_bytes(), self.sample.read_bytes())
        self.assertIn("诱骗视图".encode("utf-8"), decoy_output.read_bytes())

        fake_added = add_file(str(self.other), "wrong password")
        self.assertEqual(fake_added["filename"], "other.txt")
        removed = remove_file(decoy_filename, "wrong password")
        self.assertEqual(removed["filename"], decoy_filename)

        unknown_decoy_output = extract_file("sample.txt", str(self.tmp / "out2"), "wrong password")
        self.assertTrue(unknown_decoy_output.exists())
        self.assertNotEqual(unknown_decoy_output.read_bytes(), self.sample.read_bytes())
        self.assertIn("sample.txt - 诱骗视图导出内容".encode("utf-8"), unknown_decoy_output.read_bytes())

        self.assertEqual(len(list_files("correct password")), 1)

    def test_backup_decoy_password_enters_decoy_view(self) -> None:
        decoy_records = list_files("backup password")
        self.assertGreaterEqual(len(decoy_records), 1)
        self.assertTrue(all(record.get("decoy") for record in decoy_records))
        self.assertNotIn("sample.txt", {record["filename"] for record in decoy_records})

    def test_decoy_add_can_later_extract_fake_plaintext(self) -> None:
        added = add_file(str(self.sample), "backup password")
        self.assertEqual(added["filename"], "sample.txt")

        decoy_records = list_files("backup password")
        self.assertIn("sample.txt", {record["filename"] for record in decoy_records})

        output_path = extract_file("sample.txt", str(self.tmp / "decoy_out"), "backup password")
        self.assertTrue(output_path.exists())
        self.assertNotEqual(output_path.read_bytes(), self.sample.read_bytes())
        self.assertIn("诱骗视图".encode("utf-8"), output_path.read_bytes())

        self.assertEqual(len(list_files("correct password")), 1)


if __name__ == "__main__":
    unittest.main()
