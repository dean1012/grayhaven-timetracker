#!/usr/bin/env python3
"""Offline SQLCipher verification, migration, and key rotation utility."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from sqlcipher3 import dbapi2 as sqlcipher

from grayhaven_timetracker.database import (
    SQLITE_HEADER,
    DatabaseError,
    connect_sqlcipher,
    database_is_encrypted,
    sql_literal,
)


def read_secret(path: Path) -> str:
    try:
        secret = path.read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as exc:
        raise DatabaseError(f"Unable to read secret file: {path}") from exc
    if len(secret) < 32:
        raise DatabaseError("SQLCipher passphrases must contain at least 32 characters")
    return secret


def require_regular_file(path: Path, label: str) -> None:
    """Reject missing, non-regular, and symbolic-link maintenance inputs."""
    if path.is_symlink() or not path.is_file():
        raise DatabaseError(f"{label} must be an existing regular file: {path}")


def resolved_path(path: Path) -> Path:
    """Return a normalized path for collision checks without requiring existence."""
    return path.resolve(strict=False)


def reserve_temporary_path(destination: Path) -> Path:
    """Reserve a private temporary file beside an atomic replacement target."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(name)
    os.chmod(temporary, 0o600)
    return temporary


def discard_database_file(path: Path) -> None:
    """Remove a temporary database and any SQLite sidecars it created."""
    path.unlink(missing_ok=True)
    remove_sidecars(path)


def verify_database(database: Path, key_file: Path) -> None:
    require_regular_file(database, "Database")
    passphrase = read_secret(key_file)
    connection = connect_sqlcipher(database, passphrase)
    try:
        cipher_errors = connection.execute("PRAGMA cipher_integrity_check").fetchall()
        sqlite_result = connection.execute("PRAGMA integrity_check").fetchone()
        if cipher_errors or not sqlite_result or sqlite_result[0] != "ok":
            raise DatabaseError("Database integrity validation failed")
    finally:
        connection.close()
    if not database_is_encrypted(database):
        raise DatabaseError("Database retains a plaintext SQLite header")


def remove_sidecars(database: Path) -> None:
    """Remove SQLite sidecars after an offline atomic replacement."""
    for suffix in ("-wal", "-shm"):
        database.with_name(database.name + suffix).unlink(missing_ok=True)


def restore_database(backup: Path, database: Path) -> None:
    """Atomically restore a checkpointed database without stale sidecars."""
    require_regular_file(backup, "Recovery backup")
    if resolved_path(backup) == resolved_path(database):
        raise DatabaseError("Recovery backup must differ from the database")
    temporary = reserve_temporary_path(database)
    try:
        shutil.copy2(backup, temporary)
        os.chmod(temporary, 0o600)
        remove_sidecars(database)
        os.replace(temporary, database)
    finally:
        discard_database_file(temporary)


def rotate_key(database: Path, old_key_file: Path, new_key_file: Path) -> Path:
    require_regular_file(database, "Database")
    if not database_is_encrypted(database):
        raise DatabaseError("Refusing to rekey a plaintext SQLite database")
    old_key = read_secret(old_key_file)
    new_key = read_secret(new_key_file)
    if old_key == new_key:
        raise DatabaseError("The old and new SQLCipher passphrases must differ")

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = database.with_name(f"{database.name}.pre-rekey-{timestamp}")
    if backup.exists() or backup.is_symlink():
        raise DatabaseError(f"Recovery backup already exists: {backup}")
    connection = connect_sqlcipher(database, old_key)
    rekey_started = False
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        connection.execute("PRAGMA journal_mode = DELETE").fetchone()
        temporary_backup = reserve_temporary_path(backup)
        try:
            shutil.copy2(database, temporary_backup)
            os.chmod(temporary_backup, 0o600)
            verify_database(temporary_backup, old_key_file)
            remove_sidecars(temporary_backup)
            os.replace(temporary_backup, backup)
        finally:
            discard_database_file(temporary_backup)
        rekey_started = True
        connection.execute(f"PRAGMA rekey = {sql_literal(new_key)}")
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
        if connection.execute("PRAGMA cipher_integrity_check").fetchall():
            raise DatabaseError("SQLCipher integrity failed after rekey")
        connection.close()
        verify_database(database, new_key_file)
    except Exception:
        with suppress(Exception):
            connection.close()
        if rekey_started and backup.is_file():
            restore_database(backup, database)
            verify_database(database, old_key_file)
        raise
    return backup


def encrypt_plaintext(database: Path, key_file: Path) -> Path:
    require_regular_file(database, "Database")
    with database.open("rb") as database_file:
        if database_file.read(len(SQLITE_HEADER)) != SQLITE_HEADER:
            raise DatabaseError("Source database is not plaintext SQLite")

    passphrase = read_secret(key_file)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = database.with_name(f"{database.name}.pre-migration-encrypted-{timestamp}")
    if backup.exists() or backup.is_symlink():
        raise DatabaseError(f"Recovery backup already exists: {backup}")
    temporary = database.with_name(f".{database.name}.encrypted.tmp")
    temporary.unlink(missing_ok=True)
    remove_sidecars(temporary)

    connection = sqlcipher.connect(str(database))
    try:
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
        connection.execute(
            f"ATTACH DATABASE {sql_literal(str(temporary))} "
            f"AS encrypted KEY {sql_literal(passphrase)}"
        )
        connection.execute("SELECT sqlcipher_export('encrypted')").fetchone()
        connection.execute("DETACH DATABASE encrypted")
    finally:
        connection.close()

    temporary_connection = connect_sqlcipher(temporary, passphrase)
    try:
        if temporary_connection.execute("PRAGMA cipher_integrity_check").fetchall():
            raise DatabaseError("Encrypted export failed integrity validation")
        temporary_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        temporary_connection.execute("PRAGMA journal_mode = DELETE").fetchone()
    finally:
        temporary_connection.close()

    shutil.copy2(temporary, backup)
    os.chmod(backup, 0o600)
    remove_sidecars(database)
    os.replace(temporary, database)
    os.chmod(database, 0o600)
    verify_database(database, key_file)
    return backup


def create_backup(database: Path, key_file: Path, output: Path) -> None:
    """Create a transactionally consistent encrypted online backup."""
    require_regular_file(database, "Database")
    if not database_is_encrypted(database):
        raise DatabaseError("Refusing to back up a plaintext SQLite database")
    if output.exists() or output.is_symlink():
        raise DatabaseError(f"Backup destination already exists: {output}")

    passphrase = read_secret(key_file)
    database_path = resolved_path(database)
    output_path = resolved_path(output)
    source_sidecars = {
        resolved_path(database.with_name(database.name + suffix))
        for suffix in ("-wal", "-shm")
    }
    if output_path == database_path:
        raise DatabaseError("Backup destination must differ from the database")
    if output_path in source_sidecars:
        raise DatabaseError("Backup destination uses a reserved database sidecar path")

    temporary = reserve_temporary_path(output)
    if resolved_path(temporary) in {database_path, *source_sidecars}:
        discard_database_file(temporary)
        raise DatabaseError("Backup temporary path collides with the source database")

    source = None
    destination = None
    try:
        source = connect_sqlcipher(database, passphrase)
        destination = connect_sqlcipher(temporary, passphrase)
        try:
            destination.execute("PRAGMA journal_mode = DELETE").fetchone()
            source.backup(destination)
            destination.commit()
            if destination.execute("PRAGMA cipher_integrity_check").fetchall():
                raise DatabaseError("Encrypted backup failed integrity validation")
        finally:
            if destination is not None:
                destination.close()
            if source is not None:
                source.close()

        verify_database(temporary, key_file)
        temporary_connection = connect_sqlcipher(temporary, passphrase)
        try:
            temporary_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
            temporary_connection.execute("PRAGMA journal_mode = DELETE").fetchone()
        finally:
            temporary_connection.close()
        remove_sidecars(temporary)
        os.replace(temporary, output)
        os.chmod(output, 0o600)
    finally:
        discard_database_file(temporary)


def parser() -> argparse.ArgumentParser:
    command_parser = argparse.ArgumentParser(
        description="Maintain the Grayhaven Time Tracker SQLCipher database"
    )
    subparsers = command_parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify", help="Verify encryption and integrity")
    verify.add_argument("database", type=Path)
    verify.add_argument("key_file", type=Path)

    migrate = subparsers.add_parser(
        "encrypt-plaintext", help="Convert an existing plaintext SQLite database"
    )
    migrate.add_argument("database", type=Path)
    migrate.add_argument("key_file", type=Path)

    rekey = subparsers.add_parser("rekey", help="Rotate an existing SQLCipher key")
    rekey.add_argument("database", type=Path)
    rekey.add_argument("old_key_file", type=Path)
    rekey.add_argument("new_key_file", type=Path)

    backup = subparsers.add_parser(
        "backup", help="Create a consistent encrypted online backup"
    )
    backup.add_argument("database", type=Path)
    backup.add_argument("key_file", type=Path)
    backup.add_argument("output", type=Path)
    return command_parser


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "verify":
            verify_database(arguments.database, arguments.key_file)
            print("SQLCipher encryption and integrity verified.")
        elif arguments.command == "encrypt-plaintext":
            backup = encrypt_plaintext(arguments.database, arguments.key_file)
            print(f"Encrypted recovery backup retained at {backup}")
        elif arguments.command == "rekey":
            backup = rotate_key(
                arguments.database,
                arguments.old_key_file,
                arguments.new_key_file,
            )
            print(f"Pre-rotation backup retained at {backup}")
        else:
            create_backup(arguments.database, arguments.key_file, arguments.output)
            print(f"Encrypted backup created at {arguments.output}")
    except (DatabaseError, OSError, sqlcipher.DatabaseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
