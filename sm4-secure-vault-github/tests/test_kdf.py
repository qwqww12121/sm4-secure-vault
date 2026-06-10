"""Tests for PBKDF2-derived keys and password verifier."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from crypto.kdf import derive_keys, make_password_verifier, verify_password


class TestKDF(unittest.TestCase):
    def test_same_password_and_salt_same_keys(self) -> None:
        salt = b"1" * 16
        self.assertEqual(
            derive_keys("pass", salt, iterations=1000),
            derive_keys("pass", salt, iterations=1000),
        )

    def test_different_salt_different_keys(self) -> None:
        self.assertNotEqual(
            derive_keys("pass", b"1" * 16, iterations=1000),
            derive_keys("pass", b"2" * 16, iterations=1000),
        )

    def test_different_password_different_keys(self) -> None:
        salt = b"1" * 16
        self.assertNotEqual(
            derive_keys("pass1", salt, iterations=1000),
            derive_keys("pass2", salt, iterations=1000),
        )

    def test_password_verifier(self) -> None:
        salt = b"salt_for_testing"
        _, auth_key = derive_keys("correct", salt, iterations=1000)
        _, wrong_auth_key = derive_keys("wrong", salt, iterations=1000)
        verifier = make_password_verifier(auth_key, salt)
        self.assertTrue(verify_password(auth_key, salt, verifier))
        self.assertFalse(verify_password(wrong_auth_key, salt, verifier))


if __name__ == "__main__":
    unittest.main()
