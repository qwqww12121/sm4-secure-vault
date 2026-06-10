"""Tests for PKCS#7 padding."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crypto.padding import pkcs7_pad, pkcs7_unpad


class TestPadding(unittest.TestCase):
    def test_pad_and_unpad_regular_data(self) -> None:
        data = b"hello sm4"
        padded = pkcs7_pad(data, 16)
        self.assertEqual(len(padded), 16)
        self.assertEqual(pkcs7_unpad(padded, 16), data)

    def test_full_block_gets_extra_block(self) -> None:
        data = b"a" * 16
        padded = pkcs7_pad(data, 16)
        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[-1], 16)
        self.assertEqual(pkcs7_unpad(padded, 16), data)

    def test_empty_data(self) -> None:
        padded = pkcs7_pad(b"", 16)
        self.assertEqual(padded, bytes([16]) * 16)
        self.assertEqual(pkcs7_unpad(padded, 16), b"")

    def test_invalid_padding(self) -> None:
        for bad in (b"", b"abc", b"abc" + bytes([0]) * 13, b"a" * 15 + b"\x02"):
            with self.assertRaises(ValueError):
                pkcs7_unpad(bad, 16)


if __name__ == "__main__":
    unittest.main()
