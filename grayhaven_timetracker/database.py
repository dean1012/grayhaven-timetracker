"""SQLAlchemy and SQLCipher database lifecycle management."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

from flask import Flask, g
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker
from sqlcipher3 import dbapi2 as sqlcipher

from .models import Base

SQLITE_HEADER = b"SQLite format 3\x00"
SCHEMA_VERSION = "1"


class DatabaseError(RuntimeError):
    """Raised when encrypted database initialization or validation fails."""


def sql_literal(value: str) -> str:
    """Return a safe single-quoted SQL literal for SQLCipher PRAGMAs."""
    if "\x00" in value:
        raise DatabaseError("SQLCipher keys cannot contain NUL bytes")
    return "'" + value.replace("'", "''") + "'"


def connect_sqlcipher(path: Path, passphrase: str) -> Any:
    """Open, key, and validate one SQLCipher connection."""
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlcipher.connect(
        str(path), timeout=30, check_same_thread=False, isolation_level="DEFERRED"
    )
    try:
        connection.execute(f"PRAGMA key = {sql_literal(passphrase)}")
        version = connection.execute("PRAGMA cipher_version").fetchone()
        if not version or not version[0]:
            raise DatabaseError("The active SQLite driver does not provide SQLCipher")
        connection.execute("PRAGMA cipher_memory_security = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
        connection.execute("PRAGMA journal_mode = WAL").fetchone()
    except Exception as exc:
        connection.close()
        if isinstance(exc, DatabaseError):
            raise
        raise DatabaseError(
            "Unable to unlock the SQLCipher database; verify the configured passphrase"
        ) from exc
    return connection


def build_engine(path: Path, passphrase: str) -> Engine:
    """Build a SQLAlchemy engine backed by keyed SQLCipher connections."""

    def creator() -> Any:
        return connect_sqlcipher(path, passphrase)

    engine = create_engine(
        "sqlite://",
        module=sqlcipher,
        creator=creator,
        hide_parameters=True,
        pool_pre_ping=True,
        future=True,
    )

    @event.listens_for(engine, "connect")
    def configure_connection(dbapi_connection: Any, _: Any) -> None:
        dbapi_connection.execute("PRAGMA foreign_keys = ON")
        dbapi_connection.execute("PRAGMA busy_timeout = 5000")
        dbapi_connection.execute("PRAGMA secure_delete = ON")
        dbapi_connection.execute("PRAGMA temp_store = MEMORY")
        dbapi_connection.execute("PRAGMA trusted_schema = OFF")

    return engine


def initialize_database(engine: Engine) -> None:
    """Create the initial schema and install database integrity guards."""
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS time_entry_subtask_insert_guard
                BEFORE INSERT ON time_entry
                WHEN NEW.subtask_id IS NOT NULL
                  AND NOT EXISTS (
                    SELECT 1 FROM subtask
                    WHERE id = NEW.subtask_id AND task_id = NEW.task_id
                  )
                BEGIN
                  SELECT RAISE(ABORT, 'subtask does not belong to task');
                END
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS enabled_admin_update_guard
                BEFORE UPDATE OF role, is_enabled ON user_account
                WHEN OLD.role = 'admin'
                  AND OLD.is_enabled = 1
                  AND (NEW.role != 'admin' OR NEW.is_enabled = 0)
                  AND NOT EXISTS (
                    SELECT 1 FROM user_account
                    WHERE id != OLD.id AND role = 'admin' AND is_enabled = 1
                  )
                BEGIN
                  SELECT RAISE(ABORT, 'at least one enabled administrator is required');
                END
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS time_entry_subtask_update_guard
                BEFORE UPDATE OF task_id, subtask_id ON time_entry
                WHEN NEW.subtask_id IS NOT NULL
                  AND NOT EXISTS (
                    SELECT 1 FROM subtask
                    WHERE id = NEW.subtask_id AND task_id = NEW.task_id
                  )
                BEGIN
                  SELECT RAISE(ABORT, 'subtask does not belong to task');
                END
                """
            )
        )
        connection.execute(
            text(
                "INSERT OR IGNORE INTO application_metadata (key, value) "
                "VALUES ('schema_version', :version)"
            ),
            {"version": SCHEMA_VERSION},
        )
        version = connection.execute(
            text("SELECT value FROM application_metadata WHERE key = 'schema_version'")
        ).scalar_one()
        if version != SCHEMA_VERSION:
            raise DatabaseError(
                f"Database schema {version} is not supported by schema {SCHEMA_VERSION}"
            )


def verify_cipher_integrity(engine: Engine) -> None:
    """Verify SQLCipher page authentication and SQLite logical integrity."""
    with engine.connect() as connection:
        cipher_errors = list(
            connection.exec_driver_sql("PRAGMA cipher_integrity_check")
        )
        if cipher_errors:
            raise DatabaseError("SQLCipher page integrity validation failed")
        sqlite_result = connection.exec_driver_sql(
            "PRAGMA integrity_check"
        ).scalar_one()
        if sqlite_result != "ok":
            raise DatabaseError("SQLite logical integrity validation failed")


def database_is_encrypted(path: Path) -> bool:
    """Return whether an existing database lacks the plaintext SQLite header."""
    if not path.exists() or path.stat().st_size < len(SQLITE_HEADER):
        return False
    with path.open("rb") as database_file:
        return database_file.read(len(SQLITE_HEADER)) != SQLITE_HEADER


def init_app(app: Flask) -> None:
    """Initialize the engine and request-scoped sessions for a Flask app."""
    path = Path(cast(str, app.config["DATABASE_PATH"]))
    passphrase = cast(str, app.config["SQLCIPHER_PASSPHRASE"])
    engine = build_engine(path, passphrase)
    initialize_database(engine)
    verify_cipher_integrity(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    app.extensions["database_engine"] = engine
    app.extensions["database_session_factory"] = factory

    @app.before_request
    def open_database_session() -> None:
        g.database_session = factory()

    @app.teardown_request
    def close_database_session(_: BaseException | None) -> None:
        session = g.pop("database_session", None)
        if session is not None:
            session.close()


def get_session() -> Session:
    """Return the active request-scoped database session."""
    return cast(Session, g.database_session)


def rollback_request_session() -> None:
    """Restore the request session after a failed database transaction."""
    session = getattr(g, "database_session", None)
    if session is not None:
        session.rollback()


@contextmanager
def session_scope(app: Flask) -> Iterator[Session]:
    """Provide a transaction-capable session outside a request."""
    factory = cast(sessionmaker[Session], app.extensions["database_session_factory"])
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def dispose_app_database(app: Flask) -> None:
    """Dispose an application's engine, primarily for tests and maintenance."""
    engine = cast(Engine, app.extensions["database_engine"])
    engine.dispose()


def health_check(app: Flask) -> None:
    """Verify the database can answer a minimal keyed query."""
    engine = cast(Engine, app.extensions["database_engine"])
    with engine.connect() as connection:
        connection.execute(text("SELECT 1")).scalar_one()
