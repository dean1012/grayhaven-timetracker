"""Configuration, bootstrap, model, and SQLCipher integrity tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import date, datetime
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

import pyotp
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from grayhaven_timetracker import create_app
from grayhaven_timetracker.audit import record_audit_event
from grayhaven_timetracker.auth import hash_password, verify_password
from grayhaven_timetracker.bootstrap import reconcile_bootstrap_users
from grayhaven_timetracker.config import (
    ConfigurationError,
    environment_config,
    validate_branding,
    validate_contact_url,
    validate_public_base_url,
    validate_public_deployment,
    validate_timezone,
)
from grayhaven_timetracker.database import (
    CURRENT_SCHEMA_VERSION,
    DatabaseError,
    connect_sqlcipher,
    database_is_encrypted,
    dispose_app_database,
    rollback_request_session,
    session_scope,
    sql_literal,
    verify_cipher_integrity,
)
from grayhaven_timetracker.models import (
    ApplicationMetadata,
    AuditEvent,
    Subtask,
    SchemaVersion,
    Task,
    TimeEntry,
    User,
)
from tests.helpers import (
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    ADMIN_PASSWORD_HASH,
    ADMIN_TOTP_SECRET,
    AppTestCase,
    test_config,
)


class ConfigurationTests(unittest.TestCase):
    def required_environment(self) -> dict[str, str]:
        return {
            "BOOTSTRAP_USERS": json.dumps(
                [
                    {
                        "email": "admin@example.invalid",
                        "first_name": "Admin",
                        "last_name": "Operator",
                        "password_hash": ADMIN_PASSWORD_HASH,
                        "role": "admin",
                        "totp_secret": ADMIN_TOTP_SECRET,
                    }
                ]
            ),
            "SECRET_KEY": "Configuration-test-secret-key-at-least-32!",
            "SQLCIPHER_PASSPHRASE": "Configuration-test-passphrase-at-least-32!",
        }

    def test_environment_config_reads_values_and_defaults(self) -> None:
        values = self.required_environment()
        values.update(
            {
                "SESSION_COOKIE_SECURE": "yes",
                "TRUSTED_PROXY_COUNT": "2",
                "TRUSTED_HOSTS": "time.example.invalid,.internal.example.invalid",
                "TZ": "UTC",
                "PUBLIC_BASE_URL": "https://time.example.invalid/",
            }
        )
        with patch.dict(os.environ, values, clear=True):
            config = environment_config()
        self.assertEqual(config["DISPLAY_TIMEZONE"], "UTC")
        self.assertEqual(config["TRUSTED_PROXY_COUNT"], 2)
        self.assertTrue(config["SESSION_COOKIE_SECURE"])
        self.assertEqual(config["DATABASE_PATH"], "/app/data/timetracker.sqlite3")
        self.assertEqual(config["PUBLIC_BASE_URL"], "https://time.example.invalid")
        self.assertEqual(
            config["TRUSTED_HOSTS"],
            ["time.example.invalid", ".internal.example.invalid"],
        )

        values["SESSION_COOKIE_SECURE"] = "off"
        with patch.dict(os.environ, values, clear=True):
            config = environment_config()
        self.assertFalse(config["SESSION_COOKIE_SECURE"])

    def test_environment_config_reads_secret_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret_file = root / "secret"
            cipher_file = root / "cipher"
            bootstrap_file = root / "bootstrap-users.json"
            secret_file.write_text("S" * 32 + "\n", encoding="utf-8")
            cipher_file.write_text("C" * 32 + "\n", encoding="utf-8")
            bootstrap_file.write_text("[]\n", encoding="utf-8")
            values = self.required_environment()
            del values["SECRET_KEY"]
            del values["SQLCIPHER_PASSPHRASE"]
            del values["BOOTSTRAP_USERS"]
            values["SECRET_KEY_FILE"] = str(secret_file)
            values["SQLCIPHER_PASSPHRASE_FILE"] = str(cipher_file)
            values["BOOTSTRAP_USERS_FILE"] = str(bootstrap_file)
            with patch.dict(os.environ, values, clear=True):
                config = environment_config()
        self.assertEqual(config["SECRET_KEY"], "S" * 32)
        self.assertEqual(config["SQLCIPHER_PASSPHRASE"], "C" * 32)
        self.assertEqual(config["BOOTSTRAP_USERS"], "[]")

    def test_environment_config_allows_removed_bootstrap_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            values = self.required_environment()
            values.pop("BOOTSTRAP_USERS")
            values["BOOTSTRAP_USERS_FILE"] = str(
                Path(directory) / "deleted-after-install.json"
            )
            with patch.dict(os.environ, values, clear=True):
                config = environment_config()
        self.assertIsNone(config["BOOTSTRAP_USERS"])

    def test_environment_config_rejects_conflicts_and_invalid_values(self) -> None:
        cases = [
            {"SECRET_KEY_FILE": "/tmp/unused"},
            {"SECRET_KEY": "short"},
            {"SQLCIPHER_PASSPHRASE": "short"},
            {"SESSION_COOKIE_SECURE": "sometimes"},
            {"TRUSTED_PROXY_COUNT": "invalid"},
            {"TRUSTED_PROXY_COUNT": "-1"},
            {"TRUSTED_HOSTS": "https://example.invalid"},
            {"TRUSTED_HOSTS": "*"},
            {"TRUSTED_HOSTS": "time\u202e.example.invalid"},
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

        values = self.required_environment()
        del values["SECRET_KEY"]
        with (
            patch.dict(os.environ, values, clear=True),
            self.assertRaises(ConfigurationError),
        ):
            environment_config()

        values = self.required_environment()
        del values["SQLCIPHER_PASSPHRASE"]
        values["SQLCIPHER_PASSPHRASE_FILE"] = "/does/not/exist"
        with (
            patch.dict(os.environ, values, clear=True),
            self.assertRaises(ConfigurationError),
        ):
            environment_config()

    def test_validators_accept_and_reject_expected_values(self) -> None:
        validate_timezone("America/Chicago")
        validate_contact_url("https://example.invalid/contact")
        validate_public_base_url("https://time.example.invalid")
        validate_public_base_url(None)
        validate_public_deployment(
            "https://time.example.invalid",
            True,
            ["time.example.invalid"],
        )
        validate_public_deployment(
            "https://time.example.invalid", True, [".example.invalid"]
        )
        validate_public_deployment(None, False, None)
        with self.assertRaises(ConfigurationError):
            validate_timezone("Not/A-Timezone")
        for url in (
            "http://example.invalid",
            "relative",
            "",
            "https://user:password@example.invalid",
            "https://example.invalid:invalid",
            "https://example.invalid/contact\u202e",
        ):
            with self.subTest(url=url), self.assertRaises(ConfigurationError):
                validate_contact_url(url)
        for url in (
            "http://time.example.invalid",
            "https://user@example.invalid",
            "https://time.example.invalid/path",
            "https://time.example.invalid?query=value",
            "https://time.example.invalid:invalid",
            "https://time.example.invalid\\@evil.invalid",
            "https://time\u202e.example.invalid",
        ):
            with self.subTest(url=url), self.assertRaises(ConfigurationError):
                validate_public_base_url(url)
        with self.assertRaises(ConfigurationError):
            validate_public_deployment(
                "https://time.example.invalid", False, ["time.example.invalid"]
            )
        with self.assertRaises(ConfigurationError):
            validate_public_deployment(
                "https://time.example.invalid", True, ["other.example.invalid"]
            )
        with self.assertRaises(ConfigurationError):
            validate_public_deployment("https:///", True, [])

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

    def test_factory_uses_environment_branding_proxy_and_existing_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            branding = root / "branding"
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
                path = branding / asset
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            config = test_config(
                root,
                SKIP_BRANDING_VALIDATION=False,
                TRUSTED_PROXY_COUNT=1,
            )
            with patch("grayhaven_timetracker.environment_config", return_value=config):
                first_app = create_app()
            try:
                response = first_app.test_client().get(
                    "/health",
                    headers={
                        "X-Forwarded-For": "192.0.2.20",
                        "X-Forwarded-Host": "time.example.invalid",
                        "X-Forwarded-Proto": "https",
                    },
                )
                self.assertEqual(response.status_code, 200)
                self.assertIn(
                    "max-age=31536000",
                    response.headers["Strict-Transport-Security"],
                )
            finally:
                dispose_app_database(first_app)

            second_app = create_app(config)
            try:
                self.assertIn("database_engine", second_app.extensions)
            finally:
                dispose_app_database(second_app)


class DatabaseAndModelTests(AppTestCase):
    def test_database_schema_version_is_recorded(self) -> None:
        with session_scope(self.app) as database:
            marker = database.get(SchemaVersion, 1)
            self.assertIsNotNone(marker)
            assert marker is not None
            self.assertEqual(marker.version, CURRENT_SCHEMA_VERSION)

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

        connection = MagicMock()
        connection.execute.return_value.fetchone.return_value = None
        with (
            patch(
                "grayhaven_timetracker.database.sqlcipher.connect",
                return_value=connection,
            ),
            self.assertRaises(DatabaseError),
        ):
            connect_sqlcipher(
                self.root / "unsupported.sqlite3",
                "Another-passphrase-with-at-least-32-characters!",
            )
        connection.close.assert_called_once_with()

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

    def test_integrity_validation_reports_cipher_and_sqlite_failures(self) -> None:
        engine = MagicMock()
        connection = engine.connect.return_value.__enter__.return_value
        connection.exec_driver_sql.return_value = [("page authentication failed",)]
        with self.assertRaises(DatabaseError):
            verify_cipher_integrity(engine)

        cipher_result = MagicMock()
        cipher_result.__iter__.return_value = iter(())
        sqlite_result = MagicMock()
        sqlite_result.scalar_one.return_value = "corrupt"
        connection.exec_driver_sql.side_effect = [cipher_result, sqlite_result]
        with self.assertRaises(DatabaseError):
            verify_cipher_integrity(engine)

        with self.app.app_context():
            rollback_request_session()

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

    def test_audit_events_are_sanitized_and_database_immutable(self) -> None:
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            item = record_audit_event(
                database,
                "test_action",
                source="admin",
                actor=admin,
                details={
                    "safe": "visible\u202e",
                    "day": date(2026, 7, 15),
                    "object": Path("representative"),
                    "temporary_password": "must-not-be-stored",
                },
            )
            database.flush()
            item_id = item.id
            self.assertEqual(
                item.details,
                {
                    "day": "2026-07-15",
                    "object": "representative",
                    "safe": "visible�",
                },
            )

        with session_scope(self.app) as database:
            loaded_item = database.get(AuditEvent, item_id)
            assert loaded_item is not None
            loaded_item.event = "changed"
            with self.assertRaises(IntegrityError):
                database.flush()
            database.rollback()

            reloaded_item = database.get(AuditEvent, item_id)
            assert reloaded_item is not None
            database.delete(reloaded_item)
            with self.assertRaises(IntegrityError):
                database.flush()
            database.rollback()

        malformed = AuditEvent(details_json="[]")
        self.assertEqual(malformed.details, {})
        malformed.details_json = "not-json"
        self.assertEqual(malformed.details, {})


class BootstrapTests(AppTestCase):
    def bootstrap_manifest(self) -> list[dict[str, object]]:
        """Return the current first-install account manifest."""
        return json.loads(cast(str, self.app.config["BOOTSTRAP_USERS"]))

    def test_manifest_creates_initial_users_and_is_ignored_afterward(self) -> None:
        manifest = [
            {
                "email": "first-admin@example.invalid",
                "first_name": "First",
                "last_name": "Administrator",
                "password_hash": ADMIN_PASSWORD_HASH,
                "role": "admin",
            },
            {
                "email": "first-user@example.invalid",
                "first_name": "First",
                "last_name": "User",
                "password_hash": ADMIN_PASSWORD_HASH,
                "role": "user",
            },
        ]
        self.app.config["BOOTSTRAP_USERS"] = json.dumps(manifest)
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            database.delete(admin)
            database.flush()
            outcomes = reconcile_bootstrap_users(self.app, database)
            self.assertEqual([item.outcome for item in outcomes], ["created", "created"])

        manifest[0]["first_name"] = "Changed"
        manifest.append(
            {
                "email": "ignored@example.invalid",
                "first_name": "Ignored",
                "last_name": "Later",
                "password_hash": ADMIN_PASSWORD_HASH,
                "role": "user",
            }
        )
        self.app.config["BOOTSTRAP_USERS"] = json.dumps(manifest)
        with session_scope(self.app) as database:
            self.assertEqual(reconcile_bootstrap_users(self.app, database), [])
            first_admin = database.scalar(
                select(User).where(User.email == "first-admin@example.invalid")
            )
            assert first_admin is not None
            self.assertEqual(first_admin.first_name, "First")
            self.assertIsNone(
                database.scalar(select(User).where(User.email == "ignored@example.invalid"))
            )

            first_admin.password_hash = hash_password(
                "Changed-In-App-Password-0001-Long-Enough!"
            )
            first_admin.totp_secret = pyotp.random_base32()
            changed_hash = first_admin.password_hash
            changed_totp = first_admin.totp_secret

        self.app.config["BOOTSTRAP_USERS"] = "not-json"
        with session_scope(self.app) as database:
            self.assertEqual(reconcile_bootstrap_users(self.app, database), [])
            first_admin = database.scalar(
                select(User).where(User.email == "first-admin@example.invalid")
            )
            assert first_admin is not None
            self.assertEqual(first_admin.password_hash, changed_hash)
            self.assertEqual(first_admin.totp_secret, changed_totp)

    @unittest.skip("Bootstrap is now one-time first-install provisioning")
    def test_unchanged_bootstrap_preserves_in_app_authentication_changes(self) -> None:
        replacement = hash_password("Replacement-In-App-Password-0001!")
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.password_hash = replacement
            admin.totp_secret = pyotp.random_base32()
        with session_scope(self.app) as database:
            result = reconcile_bootstrap_users(self.app, database)
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            self.assertEqual(admin.password_hash, replacement)
            self.assertNotEqual(admin.totp_secret, ADMIN_TOTP_SECRET)
            self.assertEqual(result[0].outcome, "unchanged")

    @unittest.skip("Bootstrap is now one-time first-install provisioning")
    def test_changed_bootstrap_totp_updates_but_password_hash_is_initial_only(
        self,
    ) -> None:
        new_password = "Updated-Bootstrap-Password-0001!"
        new_hash = hash_password(new_password)
        new_secret = pyotp.random_base32()
        manifest = self.bootstrap_manifest()
        manifest[0]["password_hash"] = new_hash
        manifest[0]["totp_secret"] = new_secret
        self.app.config["BOOTSTRAP_USERS"] = json.dumps(manifest)
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            original_hash = admin.password_hash
            prior_version = admin.session_version
            result = reconcile_bootstrap_users(self.app, database)
            self.assertEqual(admin.password_hash, original_hash)
            self.assertTrue(verify_password(admin.password_hash, ADMIN_PASSWORD))
            self.assertEqual(admin.totp_secret, new_secret)
            self.assertEqual(admin.session_version, prior_version + 1)
            self.assertEqual(result[0].outcome, "updated")

    @unittest.skip("Bootstrap is now one-time first-install provisioning")
    def test_manifest_creates_another_administrator(self) -> None:
        manifest = self.bootstrap_manifest()
        manifest.append(
            {
                "email": "new-admin@example.invalid",
                "first_name": "New",
                "last_name": "Administrator",
                "password_hash": ADMIN_PASSWORD_HASH,
                "role": "admin",
            }
        )
        self.app.config["BOOTSTRAP_USERS"] = json.dumps(manifest)
        with session_scope(self.app) as database:
            result = reconcile_bootstrap_users(self.app, database)
            users = database.scalars(select(User).order_by(User.id)).all()
            self.assertEqual(len(users), 2)
            self.assertTrue(all(user.is_admin for user in users))
            self.assertEqual(result[1].outcome, "created")

    @unittest.skip("Bootstrap is now one-time first-install provisioning")
    def test_manifest_without_totp_creates_admin_and_preserves_in_app_setup(
        self,
    ) -> None:
        manifest = self.bootstrap_manifest()
        manifest.append(
            {
                "email": "password-only-admin@example.invalid",
                "first_name": "Password Only",
                "last_name": "Administrator",
                "password_hash": ADMIN_PASSWORD_HASH,
                "role": "admin",
            }
        )
        self.app.config["BOOTSTRAP_USERS"] = json.dumps(manifest)
        with session_scope(self.app) as database:
            result = reconcile_bootstrap_users(self.app, database)
            admin = database.scalar(
                select(User).where(User.email == "password-only-admin@example.invalid")
            )
            assert admin is not None
            self.assertIsNone(admin.totp_secret)
            self.assertEqual(result[1].outcome, "created")

            enrolled_secret = pyotp.random_base32()
            admin.totp_secret = enrolled_secret

        with session_scope(self.app) as database:
            self.assertEqual(
                reconcile_bootstrap_users(self.app, database)[1].outcome,
                "unchanged",
            )
            admin = database.scalar(
                select(User).where(User.email == "password-only-admin@example.invalid")
            )
            assert admin is not None
            self.assertEqual(admin.totp_secret, enrolled_secret)

    @unittest.skip("Bootstrap is now one-time first-install provisioning")
    def test_manifest_bootstrap_creates_admin_and_standard_user(self) -> None:
        user_secret = pyotp.random_base32()
        self.app.config.update(
            {
                "BOOTSTRAP_USERS": json.dumps(
                    [
                        {
                            "email": "managed-admin@example.invalid",
                            "first_name": "Managed",
                            "last_name": "Administrator",
                            "password_hash": ADMIN_PASSWORD_HASH,
                            "role": "admin",
                        },
                        {
                            "email": "managed-user@example.invalid",
                            "enabled": True,
                            "first_name": "Managed",
                            "last_name": "User",
                            "password_hash": ADMIN_PASSWORD_HASH,
                            "role": "user",
                            "totp_secret": user_secret,
                        },
                    ]
                ),
            }
        )
        with session_scope(self.app) as database:
            outcomes = reconcile_bootstrap_users(self.app, database)
            managed_admin = database.scalar(
                select(User).where(User.email == "managed-admin@example.invalid")
            )
            managed_user = database.scalar(
                select(User).where(User.email == "managed-user@example.invalid")
            )
            assert managed_admin is not None and managed_user is not None
            self.assertEqual(
                [item.outcome for item in outcomes],
                ["created", "created", "disabled"],
            )
            self.assertTrue(managed_admin.is_admin)
            self.assertIsNone(managed_admin.totp_secret)
            self.assertFalse(managed_user.is_admin)
            self.assertTrue(managed_user.is_enabled)
            self.assertEqual(managed_user.totp_secret, user_secret)
            self.assertTrue(managed_admin.email)
            managed_user_id = managed_user.id

        seed = self.seed_contract(entry_user_id=managed_user_id)
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, seed.entry_id)
            assert entry is not None
            entry.stopped_at = None

        manifest = json.loads(cast(str, self.app.config["BOOTSTRAP_USERS"]))
        manifest[1]["enabled"] = False
        self.app.config["BOOTSTRAP_USERS"] = json.dumps(manifest)
        with session_scope(self.app) as database:
            outcomes = reconcile_bootstrap_users(self.app, database)
            managed_user = database.get(User, managed_user_id)
            entry = database.get(TimeEntry, seed.entry_id)
            assert managed_user is not None and entry is not None
            self.assertEqual(outcomes[1].outcome, "disabled")
            self.assertFalse(managed_user.is_enabled)
            self.assertIsNotNone(entry.stopped_at)

        manifest[1]["enabled"] = True
        self.app.config["BOOTSTRAP_USERS"] = json.dumps(manifest)
        with session_scope(self.app) as database:
            reconcile_bootstrap_users(self.app, database)
            managed_user = database.get(User, managed_user_id)
            assert managed_user is not None
            self.assertTrue(managed_user.is_enabled)

        self.app.config["BOOTSTRAP_USERS"] = json.dumps(manifest[:1])
        with session_scope(self.app) as database:
            outcomes = reconcile_bootstrap_users(self.app, database)
            managed_user = database.get(User, managed_user_id)
            assert managed_user is not None
            self.assertEqual(outcomes[-1].outcome, "disabled")
            self.assertFalse(managed_user.is_enabled)
            self.assertTrue(managed_user.email)
            self.assertEqual(
                reconcile_bootstrap_users(self.app, database)[-1].outcome,
                "unchanged",
            )

    def test_manifest_bootstrap_rejects_unsafe_or_ambiguous_entries(self) -> None:
        with session_scope(self.app) as database:
            for user in database.scalars(select(User)).all():
                database.delete(user)
            database.flush()
        valid = {
            "email": "managed-admin@example.invalid",
            "first_name": "Managed",
            "last_name": "Administrator",
            "password_hash": ADMIN_PASSWORD_HASH,
            "role": "admin",
        }
        invalid_manifests = [
            "{",
            "{}",
            "[]",
            json.dumps([1]),
            json.dumps([{**valid, "unsupported": True}]),
            json.dumps(
                [{key: value for key, value in valid.items() if key != "email"}]
            ),
            json.dumps([{**valid, "email": 7}]),
            json.dumps([{**valid, "enabled": "yes"}]),
            json.dumps([{**valid, "role": "owner"}]),
            json.dumps([{**valid, "first_name": ""}]),
            json.dumps([{**valid, "totp_secret": "not-base32!"}]),
            json.dumps([valid, valid]),
            json.dumps([{**valid, "role": "user"}]),
            json.dumps([valid] * 1001),
        ]
        for manifest in invalid_manifests:
            self.app.config["BOOTSTRAP_USERS"] = manifest
            with (
                self.subTest(manifest=manifest),
                session_scope(self.app) as database,
                self.assertRaises(ConfigurationError),
            ):
                reconcile_bootstrap_users(self.app, database)

    @unittest.skip("Bootstrap metadata reconciliation was removed")
    def test_manifest_bootstrap_recovers_missing_or_malformed_metadata(self) -> None:
        self.app.config.update(
            {
                "BOOTSTRAP_USERS": json.dumps(
                    [
                        {
                            "email": ADMIN_EMAIL,
                            "first_name": "Managed",
                            "last_name": "Administrator",
                            "password_hash": ADMIN_PASSWORD_HASH,
                            "role": "admin",
                        }
                    ]
                ),
            }
        )
        with session_scope(self.app) as database:
            self.assertEqual(
                reconcile_bootstrap_users(self.app, database)[0].outcome,
                "updated",
            )
            marker = database.scalar(
                select(ApplicationMetadata).where(
                    ApplicationMetadata.key.startswith("bootstrap_user_")
                )
            )
            assert marker is not None
            marker.value = "{"

        with session_scope(self.app) as database:
            reconcile_bootstrap_users(self.app, database)
            marker = database.scalar(
                select(ApplicationMetadata).where(
                    ApplicationMetadata.key.startswith("bootstrap_user_")
                )
            )
            assert marker is not None
            marker.value = "[]"

        with session_scope(self.app) as database:
            self.assertEqual(
                reconcile_bootstrap_users(self.app, database)[0].outcome,
                "unchanged",
            )

    def test_bootstrap_waits_for_manifest_only_on_first_install(self) -> None:
        self.app.config["BOOTSTRAP_USERS"] = None
        with session_scope(self.app) as database:
            self.assertEqual(reconcile_bootstrap_users(self.app, database), [])

            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            database.delete(admin)
            database.flush()
            with self.assertRaises(ConfigurationError):
                reconcile_bootstrap_users(self.app, database)
        self.app.config["SKIP_BOOTSTRAP"] = True
        with session_scope(self.app) as database:
            self.assertEqual(reconcile_bootstrap_users(self.app, database), [])


if __name__ == "__main__":
    unittest.main()
