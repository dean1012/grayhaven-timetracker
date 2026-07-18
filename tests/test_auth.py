"""Authentication and validation helper tests."""

from __future__ import annotations

import unittest

import pyotp

from grayhaven_timetracker.auth import (
    LoginLimiter,
    consume_totp,
    generate_temporary_password,
    hash_password,
    normalize_email,
    password_error,
    provisioning_uri,
    qr_data_uri,
    required_text,
    safe_next_url,
    valid_totp_secret,
    verify_password,
    verify_password_constant_time,
    verify_totp,
)
from grayhaven_timetracker.models import User


class InputValidationTests(unittest.TestCase):
    def test_email_normalization_and_rejection(self) -> None:
        self.assertEqual(normalize_email("  USER@Example.COM "), "user@example.com")
        for value in ("missing-at", "a@b", "a b@example.com", "@example.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_email(value)
        with self.assertRaises(ValueError):
            normalize_email("a" * 250 + "@example.com")
        with self.assertRaises(ValueError):
            normalize_email("user\u202e@example.com")

    def test_required_text_normalizes_and_bounds_values(self) -> None:
        self.assertEqual(
            required_text("  Alpha\n Beta ", "Name", maximum=20), "Alpha Beta"
        )
        with self.assertRaisesRegex(ValueError, "required"):
            required_text(" \t ", "Name", maximum=20)
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            required_text("too long", "Name", maximum=3)
        with self.assertRaisesRegex(ValueError, "control characters"):
            required_text("unsafe\x00name", "Name", maximum=20)

    def test_password_policy_reports_each_requirement(self) -> None:
        cases = {
            "Short1!": "at least 32",
            "a" * 31 + "1!": "uppercase",
            "A" * 31 + "1!": "lowercase",
            "Aa" * 16 + "!": "number",
            "Aa1" * 11: "special",
            "A" * 1025 + "a1!": "cannot exceed",
        }
        for password, message in cases.items():
            with self.subTest(message=message):
                self.assertIn(message, password_error(password) or "")
        self.assertIsNone(password_error("Acceptable-Password-With-32-Characters-1!"))

    def test_password_hashing_and_verification(self) -> None:
        password = "Acceptable-Password-With-32-Characters-1!"
        encoded = hash_password(password)
        self.assertTrue(encoded.startswith("$argon2id$"))
        self.assertTrue(verify_password(encoded, password))
        self.assertFalse(verify_password(encoded, "incorrect"))
        self.assertFalse(verify_password("not-a-hash", password))
        self.assertFalse(verify_password(encoded, "x" * 1025))
        with self.assertRaises(ValueError):
            hash_password("short")

    def test_temporary_passwords_are_random_and_policy_compliant(self) -> None:
        first = generate_temporary_password()
        second = generate_temporary_password()
        self.assertEqual(len(first), 40)
        self.assertIsNone(password_error(first))
        self.assertNotEqual(first, second)

    def test_constant_time_password_path_supports_missing_users(self) -> None:
        self.assertFalse(verify_password_constant_time(None, "incorrect"))
        user = User(
            password_hash=hash_password("Valid-User-Password-For-Testing-0001!")
        )
        self.assertTrue(
            verify_password_constant_time(user, "Valid-User-Password-For-Testing-0001!")
        )


class TotpAndNavigationTests(unittest.TestCase):
    def test_totp_validation_and_verification(self) -> None:
        secret = pyotp.random_base32()
        token = pyotp.TOTP(secret).now()
        self.assertTrue(valid_totp_secret(secret))
        self.assertTrue(verify_totp(secret, token))
        self.assertTrue(verify_totp(secret, f"{token[:3]} {token[3:]}"))
        self.assertFalse(verify_totp(secret, "abcdef"))
        self.assertFalse(verify_totp(secret, "12345"))
        self.assertFalse(valid_totp_secret("invalid!"))
        self.assertFalse(valid_totp_secret("MY======"))
        self.assertFalse(consume_totp(User(totp_secret=None), token))

    def test_provisioning_uri_and_qr_data(self) -> None:
        user = User(email="person@example.invalid")
        secret = pyotp.random_base32()
        uri = provisioning_uri(user, secret)
        self.assertIn("Grayhaven%20Systems%20LLC", uri)
        self.assertIn("Grayhaven%20Systems%20LLC%20Time%20Tracker", uri)
        self.assertTrue(qr_data_uri(uri).startswith("data:image/png;base64,"))

    def test_safe_next_url_accepts_only_local_absolute_paths(self) -> None:
        self.assertEqual(
            safe_next_url("/contracts/1?tab=tasks"), "/contracts/1?tab=tasks"
        )
        for value in (
            None,
            "",
            "relative",
            "//evil.invalid",
            "/%2fevil.invalid",
            "/\\evil.invalid",
            "/%5cevil.invalid",
            "/profile%0d%0aX-Test: value",
            "https://evil.invalid",
        ):
            with self.subTest(value=value):
                self.assertIsNone(safe_next_url(value))


class LoginLimiterTests(unittest.TestCase):
    def test_failure_window_blocking_clearing_and_pruning(self) -> None:
        limiter = LoginLimiter(limit=2, window_seconds=10, maximum_keys=2)
        self.assertFalse(limiter.blocked("alpha", now=100))
        limiter.record_failure("alpha", now=100)
        limiter.record_failure("alpha", now=101)
        self.assertTrue(limiter.blocked("alpha", now=102))
        self.assertFalse(limiter.blocked("alpha", now=112))
        limiter.record_failure("alpha", now=120)
        limiter.clear("alpha")
        self.assertFalse(limiter.blocked("alpha", now=120))

    def test_limiter_bounds_distinct_keys(self) -> None:
        limiter = LoginLimiter(limit=1, maximum_keys=2)
        limiter.record_failure("one", now=1)
        limiter.record_failure("two", now=1)
        limiter.record_failure("three", now=1)
        self.assertFalse(limiter.blocked("one", now=1))
        self.assertTrue(limiter.blocked("three", now=1))

        # Exercise the defensive size bound even if configuration changes after
        # the limiter already contains more keys than its new maximum.
        limiter.maximum_keys = 1
        self.assertFalse(limiter.blocked("missing", now=1))
        self.assertEqual(list(limiter._attempts), ["three"])


if __name__ == "__main__":
    unittest.main()
