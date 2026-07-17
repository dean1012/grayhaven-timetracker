"""SQLCipher maintenance, demo seeding, and structured logging tests."""

from __future__ import annotations

import io
import json
import logging
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from sqlalchemy import func, select

from grayhaven_timetracker import create_app
from grayhaven_timetracker.database import (
    DatabaseError,
    connect_sqlcipher,
    database_is_encrypted,
    dispose_app_database,
    session_scope,
)
from grayhaven_timetracker.logging_config import JsonFormatter, configure_logging
from grayhaven_timetracker.models import Client, TimeEntry
from scripts import database_maintenance, seed_demo_data
from tests.helpers import SQLCIPHER_PASSPHRASE, AppTestCase, test_config


class DatabaseMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temporary.name)
        self.database = self.root / "timetracker.sqlite3"
        self.old_key_file = self.root / "old.key"
        self.new_key_file = self.root / "new.key"
        self.old_key_file.write_text(SQLCIPHER_PASSPHRASE, encoding="utf-8")
        self.new_key_file.write_text(
            "Replacement-SQLCipher-passphrase-for-testing!", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_encrypted_database(self) -> None:
        connection = connect_sqlcipher(self.database, SQLCIPHER_PASSPHRASE)
        connection.execute("CREATE TABLE sample (value TEXT NOT NULL)")
        connection.execute("INSERT INTO sample VALUES ('preserved')")
        connection.commit()
        connection.close()

    def test_read_secret_and_sidecar_helpers(self) -> None:
        self.assertEqual(
            database_maintenance.read_secret(self.old_key_file),
            SQLCIPHER_PASSPHRASE,
        )
        with self.assertRaises(DatabaseError):
            database_maintenance.read_secret(self.root / "missing")
        short = self.root / "short.key"
        short.write_text("short", encoding="utf-8")
        with self.assertRaises(DatabaseError):
            database_maintenance.read_secret(short)

        backup = self.root / "backup.sqlite3"
        backup.write_bytes(b"backup")
        self.database.write_bytes(b"database")
        for suffix in ("-wal", "-shm"):
            self.database.with_name(self.database.name + suffix).touch()
        database_maintenance.restore_database(backup, self.database)
        self.assertEqual(self.database.read_bytes(), b"backup")
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)
        for suffix in ("-wal", "-shm"):
            self.assertFalse(
                self.database.with_name(self.database.name + suffix).exists()
            )
        with self.assertRaises(DatabaseError):
            database_maintenance.restore_database(self.database, self.database)

    def test_verify_reports_integrity_and_plaintext_header_failures(self) -> None:
        self.database.write_bytes(b"representative database bytes")
        connection = MagicMock()
        connection.execute.return_value.fetchall.return_value = [("failure",)]
        connection.execute.return_value.fetchone.return_value = ("ok",)
        with (
            patch.object(
                database_maintenance,
                "connect_sqlcipher",
                return_value=connection,
            ),
            self.assertRaises(DatabaseError),
        ):
            database_maintenance.verify_database(self.database, self.old_key_file)
        connection.close.assert_called_once_with()

        connection = MagicMock()
        connection.execute.return_value.fetchall.return_value = []
        connection.execute.return_value.fetchone.return_value = ("ok",)
        with (
            patch.object(
                database_maintenance,
                "connect_sqlcipher",
                return_value=connection,
            ),
            patch.object(
                database_maintenance,
                "database_is_encrypted",
                return_value=False,
            ),
            self.assertRaises(DatabaseError),
        ):
            database_maintenance.verify_database(self.database, self.old_key_file)

    def test_verify_backup_and_key_rotation_preserve_encrypted_data(self) -> None:
        self.create_encrypted_database()
        database_maintenance.verify_database(self.database, self.old_key_file)
        backup = self.root / "backups" / "online.sqlite3"
        database_maintenance.create_backup(self.database, self.old_key_file, backup)
        self.assertTrue(database_is_encrypted(backup))
        database_maintenance.verify_database(backup, self.old_key_file)
        with self.assertRaises(DatabaseError):
            database_maintenance.create_backup(self.database, self.old_key_file, backup)
        with self.assertRaises(DatabaseError):
            database_maintenance.create_backup(
                self.database, self.old_key_file, self.database
            )

        pre_rotation = database_maintenance.rotate_key(
            self.database, self.old_key_file, self.new_key_file
        )
        self.assertTrue(pre_rotation.is_file())
        database_maintenance.verify_database(self.database, self.new_key_file)
        connection = connect_sqlcipher(
            self.database, database_maintenance.read_secret(self.new_key_file)
        )
        self.assertEqual(
            connection.execute("SELECT value FROM sample").fetchone()[0], "preserved"
        )
        connection.close()
        with self.assertRaises(DatabaseError):
            database_maintenance.verify_database(self.database, self.old_key_file)

    def test_maintenance_rejects_unsafe_sources_and_equal_keys(self) -> None:
        plaintext = sqlite3.connect(self.database)
        plaintext.execute("CREATE TABLE sample (value TEXT)")
        plaintext.commit()
        plaintext.close()
        with self.assertRaises(DatabaseError):
            database_maintenance.verify_database(self.database, self.old_key_file)
        with self.assertRaises(DatabaseError):
            database_maintenance.rotate_key(
                self.database, self.old_key_file, self.new_key_file
            )
        with self.assertRaises(DatabaseError):
            database_maintenance.create_backup(
                self.database,
                self.old_key_file,
                self.root / "plaintext-backup.sqlite3",
            )

        self.database.unlink()
        self.create_encrypted_database()
        with self.assertRaises(DatabaseError):
            database_maintenance.rotate_key(
                self.database, self.old_key_file, self.old_key_file
            )

    def test_verify_missing_database_fails_without_creating_it(self) -> None:
        missing = self.root / "missing.sqlite3"
        with self.assertRaises(DatabaseError):
            database_maintenance.verify_database(missing, self.old_key_file)
        self.assertFalse(missing.exists())

    def test_backup_rejects_source_and_sidecar_path_collisions(self) -> None:
        colliding_source = self.root / ".online.sqlite3.tmp"
        self.database = colliding_source
        self.create_encrypted_database()

        formerly_colliding_output = self.root / "online.sqlite3"
        database_maintenance.create_backup(
            self.database, self.old_key_file, formerly_colliding_output
        )
        database_maintenance.verify_database(
            formerly_colliding_output, self.old_key_file
        )

        for output in (
            self.database.with_name(self.database.name + "-wal"),
            self.database.with_name(self.database.name + "-shm"),
        ):
            with self.subTest(output=output), self.assertRaises(DatabaseError):
                database_maintenance.create_backup(
                    self.database, self.old_key_file, output
                )

        database_maintenance.verify_database(self.database, self.old_key_file)
        connection = connect_sqlcipher(self.database, SQLCIPHER_PASSPHRASE)
        self.assertEqual(
            connection.execute("SELECT value FROM sample").fetchone()[0], "preserved"
        )
        connection.close()

    def test_failed_rekey_backup_copy_preserves_the_source(self) -> None:
        self.create_encrypted_database()

        def fail_after_partial_copy(source: Path, destination: Path) -> None:
            Path(destination).write_bytes(Path(source).read_bytes()[:1024])
            raise OSError("simulated interrupted copy")

        with (
            patch(
                "scripts.database_maintenance.shutil.copy2",
                side_effect=fail_after_partial_copy,
            ),
            self.assertRaises(OSError),
        ):
            database_maintenance.rotate_key(
                self.database, self.old_key_file, self.new_key_file
            )

        database_maintenance.verify_database(self.database, self.old_key_file)
        connection = connect_sqlcipher(self.database, SQLCIPHER_PASSPHRASE)
        self.assertEqual(
            connection.execute("SELECT value FROM sample").fetchone()[0], "preserved"
        )
        connection.close()
        self.assertEqual(list(self.root.glob("timetracker.sqlite3.pre-rekey-*")), [])

    def test_failed_post_rekey_verification_restores_the_recovery_copy(self) -> None:
        self.create_encrypted_database()

        def verification_failure(database: Path, key_file: Path) -> None:
            if database == self.database and key_file == self.new_key_file:
                raise DatabaseError("simulated post-rekey verification failure")

        with (
            patch.object(
                database_maintenance,
                "verify_database",
                side_effect=verification_failure,
            ),
            self.assertRaises(DatabaseError),
        ):
            database_maintenance.rotate_key(
                self.database, self.old_key_file, self.new_key_file
            )

        database_maintenance.verify_database(self.database, self.old_key_file)

    def test_backup_rejects_a_colliding_reserved_temporary_path(self) -> None:
        self.create_encrypted_database()
        sidecar = self.database.with_name(self.database.name + "-wal")
        sidecar.touch()
        with (
            patch.object(
                database_maintenance,
                "reserve_temporary_path",
                return_value=sidecar,
            ),
            self.assertRaises(DatabaseError),
        ):
            database_maintenance.create_backup(
                self.database,
                self.old_key_file,
                self.root / "collision-backup.sqlite3",
            )
        self.assertTrue(self.database.is_file())

    def test_recovery_operations_refuse_to_overwrite_existing_backups(self) -> None:
        fixed = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)
        self.create_encrypted_database()
        rekey_backup = self.database.with_name(
            f"{self.database.name}.pre-rekey-20260715T120000Z"
        )
        rekey_backup.touch()
        with (
            patch.object(database_maintenance, "datetime") as clock,
            self.assertRaises(DatabaseError),
        ):
            clock.now.return_value = fixed
            database_maintenance.rotate_key(
                self.database, self.old_key_file, self.new_key_file
            )

    def test_command_line_dispatch_and_error_status(self) -> None:
        commands = (
            (["maintain", "verify", "db", "key"], "verify_database"),
            (["maintain", "rekey", "db", "old", "new"], "rotate_key"),
            (["maintain", "backup", "db", "key", "output"], "create_backup"),
        )
        for arguments, target in commands:
            with (
                self.subTest(command=arguments[1]),
                patch.object(sys, "argv", arguments),
                patch.object(database_maintenance, target) as operation,
                redirect_stdout(io.StringIO()),
            ):
                if target == "rotate_key":
                    operation.return_value = Path("recovery")
                self.assertEqual(database_maintenance.main(), 0)
                operation.assert_called_once()

        with (
            patch.object(sys, "argv", ["maintain", "verify", "db", "key"]),
            patch.object(
                database_maintenance,
                "verify_database",
                side_effect=DatabaseError("expected failure"),
            ),
            redirect_stderr(io.StringIO()) as stderr,
        ):
            self.assertEqual(database_maintenance.main(), 1)
        self.assertIn("expected failure", stderr.getvalue())


class DemoSeedTests(AppTestCase):
    def test_seed_creates_data_once_and_requires_an_administrator(self) -> None:
        with patch.object(seed_demo_data, "create_app", return_value=self.app):
            self.assertEqual(seed_demo_data.main(), 0)
            self.assertEqual(seed_demo_data.main(), 0)
        with session_scope(self.app) as database:
            self.assertEqual(
                database.scalar(
                    select(func.count())
                    .select_from(Client)
                    .where(Client.name == "Pellera")
                ),
                1,
            )
            self.assertEqual(
                database.scalar(select(func.count()).select_from(TimeEntry)), 2
            )

        empty_root = self.root / "empty-app"
        empty_root.mkdir()
        empty_app = create_app(
            test_config(
                empty_root,
                SKIP_BOOTSTRAP=True,
            )
        )
        try:
            with (
                patch.object(seed_demo_data, "create_app", return_value=empty_app),
                self.assertRaises(RuntimeError),
            ):
                seed_demo_data.main()
        finally:
            dispose_app_database(empty_app)


class StructuredLoggingTests(unittest.TestCase):
    def test_json_formatter_includes_context_and_exception(self) -> None:
        formatter = JsonFormatter()
        token = "A" * 43
        try:
            raise ValueError(f"failure at /shared/reports/{token}")
        except ValueError:
            exception = sys.exc_info()
        record = logging.LogRecord(
            name="grayhaven_timetracker.test",
            level=logging.WARNING,
            pathname=__file__,
            lineno=1,
            msg="Rejected %s",
            args=(f"/shared/reports/{token}",),
            exc_info=exception,
        )
        record.event = "test_event"
        record.user_id = 7
        record.user_agent = "spoof\u202eagent"
        record.details = {"unsafe\u202ekey": f"/shared/reports/{token}"}
        payload = json.loads(formatter.format(record))
        self.assertEqual(payload["message"], "Rejected /shared/reports/[redacted]")
        self.assertEqual(payload["event"], "test_event")
        self.assertEqual(payload["user_id"], 7)
        self.assertEqual(payload["user_agent"], "spoof�agent")
        self.assertEqual(
            payload["details"], {"unsafe�key": "/shared/reports/[redacted]"}
        )
        self.assertIn(
            "ValueError: failure at /shared/reports/[redacted]",
            payload["exception"],
        )
        self.assertNotIn(token, json.dumps(payload))

        plain_record = logging.LogRecord(
            name="grayhaven_timetracker.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="ordinary event",
            args=(),
            exc_info=None,
        )
        self.assertNotIn("exception", json.loads(formatter.format(plain_record)))

    def test_configure_logging_installs_json_root_handler(self) -> None:
        root = logging.getLogger()
        prior_handlers = root.handlers[:]
        prior_level = root.level
        try:
            configure_logging()
            self.assertEqual(root.level, logging.INFO)
            self.assertEqual(len(root.handlers), 1)
            self.assertIsInstance(root.handlers[0].formatter, JsonFormatter)
        finally:
            root.handlers[:] = prior_handlers
            root.setLevel(prior_level)


if __name__ == "__main__":
    unittest.main()
