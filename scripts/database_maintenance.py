#!/usr/bin/env python3
"""Offline SQLCipher verification, migration, and key rotation utility."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
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


def verify_database(database: Path, key_file: Path) -> None:
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
    """Restore a checkpointed database file without retaining stale sidecars."""
    remove_sidecars(database)
    shutil.copy2(backup, database)
    os.chmod(database, 0o600)


def rotate_key(database: Path, old_key_file: Path, new_key_file: Path) -> Path:
    if not database_is_encrypted(database):
        raise DatabaseError("Refusing to rekey a plaintext SQLite database")
    old_key = read_secret(old_key_file)
    new_key = read_secret(new_key_file)
    if old_key == new_key:
        raise DatabaseError("The old and new SQLCipher passphrases must differ")

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = database.with_name(f"{database.name}.pre-rekey-{timestamp}")
    if backup.exists():
        raise DatabaseError(f"Recovery backup already exists: {backup}")
    connection = connect_sqlcipher(database, old_key)
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        connection.execute("PRAGMA journal_mode = DELETE").fetchone()
        shutil.copy2(database, backup)
        os.chmod(backup, 0o600)
        connection.execute(f"PRAGMA rekey = {sql_literal(new_key)}")
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
        if connection.execute("PRAGMA cipher_integrity_check").fetchall():
            raise DatabaseError("SQLCipher integrity failed after rekey")
        connection.close()
        verify_database(database, new_key_file)
    except Exception:
        with suppress(Exception):
            connection.close()
        if backup.is_file():
            restore_database(backup, database)
            verify_database(database, old_key_file)
        raise
    return backup


def encrypt_plaintext(database: Path, key_file: Path) -> Path:
    if not database.is_file():
        raise DatabaseError(f"Database does not exist: {database}")
    with database.open("rb") as database_file:
        if database_file.read(len(SQLITE_HEADER)) != SQLITE_HEADER:
            raise DatabaseError("Source database is not plaintext SQLite")

    passphrase = read_secret(key_file)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = database.with_name(f"{database.name}.pre-migration-encrypted-{timestamp}")
    if backup.exists():
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
    if not database_is_encrypted(database):
        raise DatabaseError("Refusing to back up a plaintext SQLite database")
    if output.exists():
        raise DatabaseError(f"Backup destination already exists: {output}")
    if output.resolve() == database.resolve():
        raise DatabaseError("Backup destination must differ from the database")

    passphrase = read_secret(key_file)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.unlink(missing_ok=True)
    remove_sidecars(temporary)

    source = connect_sqlcipher(database, passphrase)
    destination = connect_sqlcipher(temporary, passphrase)
    try:
        destination.execute("PRAGMA journal_mode = DELETE").fetchone()
        source.backup(destination)
        destination.commit()
        if destination.execute("PRAGMA cipher_integrity_check").fetchall():
            raise DatabaseError("Encrypted backup failed integrity validation")
    finally:
        destination.close()
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
