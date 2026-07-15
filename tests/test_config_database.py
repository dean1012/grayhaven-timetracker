"""Configuration, bootstrap, model, and SQLCipher integrity tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pyotp
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from grayhaven_timetracker.auth import hash_password, verify_password
from grayhaven_timetracker.bootstrap import reconcile_initial_admin
from grayhaven_timetracker.config import (
    ConfigurationError,
    environment_config,
    validate_branding,
    validate_contact_url,
    validate_timezone,
)
from grayhaven_timetracker.database import (
    DatabaseError,
    connect_sqlcipher,
    database_is_encrypted,
    initialize_database,
    session_scope,
    sql_literal,
)
from grayhaven_timetracker.models import Subtask, Task, TimeEntry, User
from tests.helpers import (
    ADMIN_EMAIL,
    ADMIN_PASSWORD_HASH,
    ADMIN_TOTP_SECRET,
    AppTestCase,
)


class ConfigurationTests(unittest.TestCase):
    def required_environment(self) -> dict[str, str]:
        return {
            "INITIAL_ADMIN_EMAIL": "admin@example.invalid",
            "INITIAL_ADMIN_FIRST_NAME": "Admin",
            "INITIAL_ADMIN_LAST_NAME": "Operator",
            "INITIAL_ADMIN_PASSWORD_HASH": ADMIN_PASSWORD_HASH,
            "INITIAL_ADMIN_TOTP_SECRET": ADMIN_TOTP_SECRET,
            "SECRET_KEY": "Configuration-test-secret-key-at-least-32!",
            "SQLCIPHER_PASSPHRASE": "Configuration-test-passphrase-at-least-32!",
        }

    def test_environment_config_reads_values_and_defaults(self) -> None:
        values = self.required_environment()
        values.update(
            {
                "SESSION_COOKIE_SECURE": "yes",
                "TRUSTED_PROXY_COUNT": "2",
                "TZ": "UTC",
            }
        )
        with patch.dict(os.environ, values, clear=True):
            config = environment_config()
        self.assertEqual(config["DISPLAY_TIMEZONE"], "UTC")
        self.assertEqual(config["TRUSTED_PROXY_COUNT"], 2)
        self.assertTrue(config["SESSION_COOKIE_SECURE"])
        self.assertEqual(config["DATABASE_PATH"], "/app/data/timetracker.sqlite3")

    def test_environment_config_reads_secret_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret_file = root / "secret"
            cipher_file = root / "cipher"
            secret_file.write_text("S" * 32 + "\n", encoding="utf-8")
            cipher_file.write_text("C" * 32 + "\n", encoding="utf-8")
            values = self.required_environment()
            del values["SECRET_KEY"]
            del values["SQLCIPHER_PASSPHRASE"]
            values["SECRET_KEY_FILE"] = str(secret_file)
            values["SQLCIPHER_PASSPHRASE_FILE"] = str(cipher_file)
            with patch.dict(os.environ, values, clear=True):
                config = environment_config()
        self.assertEqual(config["SECRET_KEY"], "S" * 32)
        self.assertEqual(config["SQLCIPHER_PASSPHRASE"], "C" * 32)

    def test_environment_config_rejects_conflicts_and_invalid_values(self) -> None:
        cases = [
            {"SECRET_KEY_FILE": "/tmp/unused"},
            {"SECRET_KEY": "short"},
            {"SQLCIPHER_PASSPHRASE": "short"},
            {"SESSION_COOKIE_SECURE": "sometimes"},
            {"TRUSTED_PROXY_COUNT": "invalid"},
            {"TRUSTED_PROXY_COUNT": "-1"},
        ]
        for additions in cases:
            values = self.required_environment()
            values.update(additions)
            with (
                self.subTest(additions=additions),
                patch.dict(os.environ, values, clear=True),
                self.assertRaises(ConfigurationError),
            ):
                environment_config()

        def secret_with_nul(name: str, *, required: bool = True) -> str | None:
            if name == "SQLCIPHER_PASSPHRASE":
                return "A" * 32 + "\x00"
            if required:
                return "S" * 32
            return None

        with (
            patch(
                "grayhaven_timetracker.config._read_secret", side_effect=secret_with_nul
            ),
            patch.dict(os.environ, {}, clear=True),
            self.assertRaises(ConfigurationError),
        ):
            environment_config()

    def test_validators_accept_and_reject_expected_values(self) -> None:
        validate_timezone("America/Chicago")
        validate_contact_url("https://example.invalid/contact")
        with self.assertRaises(ConfigurationError):
            validate_timezone("Not/A-Timezone")
        for url in ("http://example.invalid", "relative", ""):
            with self.subTest(url=url), self.assertRaises(ConfigurationError):
                validate_contact_url(url)

    def test_branding_validation_requires_every_runtime_asset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ConfigurationError):
                validate_branding(str(root))
            assets = (
                "grayhaven-logo-wordmark-dark.svg",
                "grayhaven-logo-wordmark-light.png",
                "favicon.ico",
                "favicon-16.png",
                "favicon-32.png",
                "apple-touch-icon.png",
                "fonts/inter-400.ttf",
                "fonts/inter-500.ttf",
                "fonts/inter-600.ttf",
                "fonts/inter-700.ttf",
            )
            for asset in assets:
                path = root / asset
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            validate_branding(str(root))


class DatabaseAndModelTests(AppTestCase):
    def test_sql_literal_escapes_quotes_and_rejects_nul(self) -> None:
        self.assertEqual(sql_literal("alpha'beta"), "'alpha''beta'")
        with self.assertRaises(DatabaseError):
            sql_literal("alpha\x00beta")

    def test_database_file_is_encrypted_and_wrong_key_is_rejected(self) -> None:
        database_path = Path(str(self.app.config["DATABASE_PATH"]))
        self.assertTrue(database_is_encrypted(database_path))
        self.assertNotEqual(database_path.read_bytes()[:16], b"SQLite format 3\x00")
        with self.assertRaises(DatabaseError):
            connect_sqlcipher(database_path, "Wrong-passphrase-with-at-least-32-chars!")
        plain = self.root / "plain.sqlite3"
        plain.write_bytes(b"SQLite format 3\x00" + b"x" * 32)
        self.assertFalse(database_is_encrypted(plain))
        self.assertFalse(database_is_encrypted(self.root / "missing.sqlite3"))

    def test_session_scope_rolls_back_failed_work(self) -> None:
        with self.assertRaises(RuntimeError), session_scope(self.app) as database:
            database.add(
                User(
                    email="rollback@example.invalid",
                    first_name="Rollback",
                    last_name="User",
                    password_hash=ADMIN_PASSWORD_HASH,
                    role="user",
                    is_enabled=True,
                    session_version=1,
                    created_at=datetime(2026, 7, 15),
                )
            )
            raise RuntimeError("force rollback")
        with session_scope(self.app) as database:
            self.assertIsNone(
                database.scalar(
                    select(User).where(User.email == "rollback@example.invalid")
                )
            )

    def test_schema_one_is_migrated_without_replacing_existing_data(self) -> None:
        engine = self.app.extensions["database_engine"]
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP INDEX uq_contract_report_token_hash")
            connection.exec_driver_sql(
                "ALTER TABLE contract DROP COLUMN report_expires_at"
            )
            connection.exec_driver_sql(
                "ALTER TABLE contract DROP COLUMN report_token_hash"
            )
            connection.exec_driver_sql(
                "ALTER TABLE user_account DROP COLUMN password_change_required"
            )
            connection.execute(
                text(
                    "UPDATE application_metadata SET value = '1' "
                    "WHERE key = 'schema_version'"
                )
            )

        initialize_database(engine)

        with engine.connect() as connection:
            user_columns = {
                row[1]
                for row in connection.exec_driver_sql("PRAGMA table_info(user_account)")
            }
            contract_columns = {
                row[1]
                for row in connection.exec_driver_sql("PRAGMA table_info(contract)")
            }
            client_columns = {
                row[1]
                for row in connection.exec_driver_sql("PRAGMA table_info(client)")
            }
            version = connection.execute(
                text(
                    "SELECT value FROM application_metadata "
                    "WHERE key = 'schema_version'"
                )
            ).scalar_one()
            admin_count = connection.exec_driver_sql(
                "SELECT count(*) FROM user_account WHERE email = ?", (ADMIN_EMAIL,)
            ).scalar_one()
        self.assertIn("password_change_required", user_columns)
        self.assertIn("report_token_hash", contract_columns)
        self.assertIn("report_expires_at", contract_columns)
        self.assertIn("report_password_hash", client_columns)
        self.assertIn("report_password_version", client_columns)
        self.assertEqual(version, "2")
        self.assertEqual(admin_count, 1)

    def test_database_guards_active_timer_subtask_and_last_admin(self) -> None:
        seed = self.seed_contract()
        user = self.create_user()
        with session_scope(self.app) as database:
            first = TimeEntry(
                user_id=user.id,
                task_id=seed.task_id,
                started_at=datetime(2026, 7, 15, 12, 0, 0),
            )
            database.add(first)
            database.flush()
            database.add(
                TimeEntry(
                    user_id=user.id,
                    task_id=seed.task_id,
                    started_at=datetime(2026, 7, 15, 12, 1, 0),
                )
            )
            with self.assertRaises(IntegrityError):
                database.flush()
            database.rollback()

            unrelated_task = Task(contract_id=seed.contract_id, name="Unrelated task")
            database.add(unrelated_task)
            database.flush()
            database.add(
                TimeEntry(
                    user_id=user.id,
                    task_id=unrelated_task.id,
                    subtask_id=seed.subtask_id,
                    started_at=datetime(2026, 7, 15, 13, 0, 0),
                    stopped_at=datetime(2026, 7, 15, 13, 1, 0),
                )
            )
            with self.assertRaises(IntegrityError):
                database.flush()
            database.rollback()

            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.role = "user"
            with self.assertRaises(IntegrityError):
                database.flush()
            database.rollback()

    def test_model_properties(self) -> None:
        seed = self.seed_contract()
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            task = database.get(Task, seed.task_id)
            subtask = database.get(Subtask, seed.subtask_id)
            entry = database.get(TimeEntry, seed.entry_id)
            assert admin and task and subtask and entry
            self.assertEqual(admin.full_name, "Admin Operator")
            self.assertTrue(admin.is_admin)
            self.assertEqual(task.contract.hourly_rate_cents, 5500)
            self.assertEqual(entry.contract.id, seed.contract_id)


class BootstrapTests(AppTestCase):
    def test_unchanged_bootstrap_preserves_in_app_authentication_changes(self) -> None:
        replacement = hash_password("Replacement-In-App-Password-0001!")
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.password_hash = replacement
            admin.totp_secret = pyotp.random_base32()
        with session_scope(self.app) as database:
            reconcile_initial_admin(self.app, database)
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            self.assertEqual(admin.password_hash, replacement)
            self.assertNotEqual(admin.totp_secret, ADMIN_TOTP_SECRET)

    def test_changed_bootstrap_authentication_updates_and_invalidates_sessions(
        self,
    ) -> None:
        new_password = "Updated-Bootstrap-Password-0001!"
        new_hash = hash_password(new_password)
        new_secret = pyotp.random_base32()
        self.app.config["INITIAL_ADMIN_PASSWORD_HASH"] = new_hash
        self.app.config["INITIAL_ADMIN_TOTP_SECRET"] = new_secret
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            prior_version = admin.session_version
            reconcile_initial_admin(self.app, database)
            self.assertTrue(verify_password(admin.password_hash, new_password))
            self.assertEqual(admin.totp_secret, new_secret)
            self.assertEqual(admin.session_version, prior_version + 1)

    def test_new_bootstrap_email_creates_another_administrator(self) -> None:
        self.app.config.update(
            {
                "INITIAL_ADMIN_EMAIL": "new-admin@example.invalid",
                "INITIAL_ADMIN_FIRST_NAME": "New",
                "INITIAL_ADMIN_LAST_NAME": "Administrator",
            }
        )
        with session_scope(self.app) as database:
            reconcile_initial_admin(self.app, database)
            users = database.scalars(select(User).order_by(User.id)).all()
            self.assertEqual(len(users), 2)
            self.assertTrue(all(user.is_admin for user in users))

    def test_bootstrap_rejects_invalid_configuration_and_can_be_skipped(self) -> None:
        self.app.config["INITIAL_ADMIN_PASSWORD_HASH"] = "invalid"
        with session_scope(self.app) as database, self.assertRaises(ConfigurationError):
            reconcile_initial_admin(self.app, database)
        self.app.config["INITIAL_ADMIN_PASSWORD_HASH"] = ADMIN_PASSWORD_HASH
        self.app.config["INITIAL_ADMIN_TOTP_SECRET"] = "invalid"
        with session_scope(self.app) as database, self.assertRaises(ConfigurationError):
            reconcile_initial_admin(self.app, database)
        self.app.config["SKIP_BOOTSTRAP"] = True
        with session_scope(self.app) as database:
            reconcile_initial_admin(self.app, database)


if __name__ == "__main__":
    unittest.main()
