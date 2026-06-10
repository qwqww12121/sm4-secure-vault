"""Tests for the pure Python SM4 block cipher."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crypto.sm4 import sm4_decrypt_block, sm4_encrypt_block


class TestSM4(unittest.TestCase):
    def test_standard_vector_encrypt(self) -> None:
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
        ciphertext = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
        self.assertEqual(sm4_encrypt_block(plaintext, key), ciphertext)

    def test_standard_vector_decrypt(self) -> None:
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
        ciphertext = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
        self.assertEqual(sm4_decrypt_block(ciphertext, key), plaintext)

    def test_invalid_lengths(self) -> None:
        key = b"\x00" * 16
        block = b"\x00" * 16
        with self.assertRaises(ValueError):
            sm4_encrypt_block(b"short", key)
        with self.assertRaises(ValueError):
            sm4_encrypt_block(block, b"short")
        with self.assertRaises(ValueError):
            sm4_decrypt_block(b"short", key)


if __name__ == "__main__":
    unittest.main()
