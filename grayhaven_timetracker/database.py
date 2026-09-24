"""SQLAlchemy and SQLCipher database lifecycle management."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

from flask import Flask, g
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import ORMExecuteState, Session, sessionmaker, with_loader_criteria
from sqlcipher3 import dbapi2 as sqlcipher

from .models import Base, Client, Contract, Subtask, Task, TimeEntry

SQLITE_HEADER = b"SQLite format 3\x00"
CURRENT_SCHEMA_VERSION = 4
MINIMUM_MIGRATABLE_SCHEMA_VERSION = 2
SOFT_DELETABLE_MODELS = (Client, Contract, Task, Subtask, TimeEntry)


class ApplicationSession(Session):
    """Session that excludes soft-deleted business records by default."""


@event.listens_for(ApplicationSession, "do_orm_execute")
def exclude_soft_deleted_records(execute_state: ORMExecuteState) -> None:
    """Keep hidden records outside normal ORM reads and relationship loads."""
    if not execute_state.is_select or execute_state.execution_options.get(
        "include_hidden"
    ):
        return
    execute_state.statement = execute_state.statement.options(
        *(
            with_loader_criteria(
                model,
                lambda record: record.visible.is_(True),
                include_aliases=True,
            )
            for model in SOFT_DELETABLE_MODELS
        )
    )


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


def migrate_schema_2_to_3(connection: Any) -> None:
    """Add passkey identities, credentials, and single-use ceremony state."""
    statements = (
        """
        CREATE TABLE passkey_identity (
            user_id INTEGER NOT NULL PRIMARY KEY,
            user_handle BLOB NOT NULL UNIQUE,
            created_at DATETIME NOT NULL,
            FOREIGN KEY(user_id) REFERENCES user_account(id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE passkey_credential (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id BLOB NOT NULL UNIQUE,
            public_key BLOB NOT NULL,
            sign_count INTEGER NOT NULL CHECK (sign_count >= 0),
            device_type VARCHAR(32) NOT NULL,
            backed_up BOOLEAN NOT NULL,
            aaguid VARCHAR(36) NOT NULL,
            name VARCHAR(100) NOT NULL CHECK (length(trim(name)) > 0),
            rp_id VARCHAR(255) NOT NULL CHECK (length(trim(rp_id)) > 0),
            created_at DATETIME NOT NULL,
            last_used_at DATETIME,
            FOREIGN KEY(user_id) REFERENCES user_account(id) ON DELETE CASCADE
        )
        """,
        """
        CREATE INDEX ix_passkey_credential_user
        ON passkey_credential (user_id)
        """,
        """
        CREATE TABLE webauthn_challenge (
            id VARCHAR(64) NOT NULL PRIMARY KEY,
            challenge BLOB NOT NULL,
            ceremony VARCHAR(24) NOT NULL CHECK (
                ceremony IN ('registration', 'authentication', 'reauthentication')
            ),
            user_id INTEGER,
            session_binding_hash BLOB NOT NULL,
            action_context_hash BLOB,
            created_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            FOREIGN KEY(user_id) REFERENCES user_account(id) ON DELETE CASCADE
        )
        """,
        """
        CREATE INDEX ix_webauthn_challenge_expires
        ON webauthn_challenge (expires_at)
        """,
    )
    for statement in statements:
        connection.execute(text(statement))


def migrate_schema_3_to_4(connection: Any) -> None:
    """Add permanent invoice snapshots and current entry claims."""
    contract_columns = set(
        connection.execute(text("SELECT name FROM pragma_table_info('contract')"))
        .scalars()
        .all()
    )
    entry_columns = set(
        connection.execute(text("SELECT name FROM pragma_table_info('time_entry')"))
        .scalars()
        .all()
    )
    invoice_objects = set(
        connection.execute(
            text(
                "SELECT name FROM sqlite_master WHERE name IN "
                "('invoice', 'invoice_line', 'uq_invoice_number', "
                "'uq_invoice_contract_sequence', 'ix_invoice_contract_issued', "
                "'ix_invoice_line_invoice', 'ix_invoice_line_entry', "
                "'ix_time_entry_invoice_id')"
            )
        ).scalars()
    )
    expected_objects = {
        "invoice",
        "invoice_line",
        "uq_invoice_number",
        "uq_invoice_contract_sequence",
        "ix_invoice_contract_issued",
        "ix_invoice_line_invoice",
        "ix_invoice_line_entry",
        "ix_time_entry_invoice_id",
    }
    additions = (
        "payment_terms_days" in contract_columns,
        "invoice_id" in entry_columns,
        invoice_objects == expected_objects,
    )
    if all(additions):
        return
    if any(additions) or invoice_objects:
        raise DatabaseError("Schema 3 contains a partial invoice migration")
    statements = (
        """
        ALTER TABLE contract ADD COLUMN payment_terms_days INTEGER NOT NULL
        DEFAULT 30 CHECK (payment_terms_days IN (0, 7, 30))
        """,
        """
        CREATE TABLE invoice (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL CHECK (client_id BETWEEN 1 AND 999),
            contract_id INTEGER NOT NULL CHECK (contract_id BETWEEN 1 AND 999),
            project_sequence INTEGER NOT NULL
                CHECK (project_sequence BETWEEN 1 AND 999),
            invoice_number VARCHAR(32) NOT NULL,
            status VARCHAR(16) NOT NULL
                CHECK (status IN ('UNPAID', 'PAID', 'VOID')),
            issued_at DATETIME NOT NULL,
            range_start_utc DATETIME NOT NULL,
            range_end_utc DATETIME NOT NULL,
            timezone_name VARCHAR(100) NOT NULL,
            client_name VARCHAR(200) NOT NULL,
            project_name VARCHAR(200) NOT NULL,
            contact_name VARCHAR(200) NOT NULL,
            contact_email VARCHAR(255) NOT NULL,
            hourly_rate_cents INTEGER NOT NULL CHECK (hourly_rate_cents >= 0),
            payment_terms_days INTEGER NOT NULL
                CHECK (payment_terms_days IN (0, 7, 30)),
            total_seconds INTEGER NOT NULL CHECK (total_seconds >= 0),
            total_cents INTEGER NOT NULL CHECK (total_cents >= 0),
            due_date DATE NOT NULL,
            paid_date DATE,
            pdf_bytes BLOB NOT NULL,
            FOREIGN KEY(client_id) REFERENCES client(id) ON DELETE RESTRICT,
            FOREIGN KEY(contract_id) REFERENCES contract(id) ON DELETE RESTRICT,
            CONSTRAINT ck_invoice_range CHECK (range_end_utc > range_start_utc),
            CONSTRAINT ck_invoice_paid_date CHECK (
                (status = 'PAID' AND paid_date IS NOT NULL)
                OR (status != 'PAID' AND paid_date IS NULL)
            )
        )
        """,
        """
        CREATE UNIQUE INDEX uq_invoice_number ON invoice (invoice_number)
        """,
        """
        CREATE UNIQUE INDEX uq_invoice_contract_sequence
        ON invoice (contract_id, project_sequence)
        """,
        """
        CREATE INDEX ix_invoice_contract_issued
        ON invoice (contract_id, issued_at, id)
        """,
        """
        CREATE TABLE invoice_line (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            invoice_id INTEGER NOT NULL,
            time_entry_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            worker_name VARCHAR(201) NOT NULL,
            task_name VARCHAR(200) NOT NULL,
            subtask_name VARCHAR(200),
            started_at_utc DATETIME NOT NULL,
            stopped_at_utc DATETIME NOT NULL,
            total_seconds INTEGER NOT NULL CHECK (total_seconds >= 0),
            started_before_range BOOLEAN NOT NULL,
            FOREIGN KEY(invoice_id) REFERENCES invoice(id) ON DELETE RESTRICT,
            FOREIGN KEY(time_entry_id) REFERENCES time_entry(id) ON DELETE RESTRICT,
            FOREIGN KEY(user_id) REFERENCES user_account(id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE INDEX ix_invoice_line_invoice ON invoice_line (invoice_id, id)
        """,
        """
        CREATE INDEX ix_invoice_line_entry ON invoice_line (time_entry_id)
        """,
        """
        ALTER TABLE time_entry ADD COLUMN invoice_id INTEGER
        REFERENCES invoice(id) ON DELETE RESTRICT
        """,
        """
        CREATE INDEX ix_time_entry_invoice_id ON time_entry (invoice_id)
        """,
    )
    for statement in statements:
        connection.execute(text(statement))


MIGRATIONS: dict[int, Callable[[Any], None]] = {
    2: migrate_schema_2_to_3,
    3: migrate_schema_3_to_4,
}


def installed_schema_version(connection: Any) -> int | None:
    """Return the installed schema marker, or ``None`` for a new database."""
    has_marker = connection.execute(
        text(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name = 'schema_version'"
        )
    ).scalar_one_or_none()
    if has_marker is None:
        has_tables = connection.execute(
            text("SELECT 1 FROM sqlite_master WHERE type = 'table' LIMIT 1")
        ).scalar_one_or_none()
        if has_tables is not None:
            raise DatabaseError("Existing database has no schema version marker")
        return None
    value = connection.execute(
        text("SELECT version FROM schema_version WHERE id = 1")
    ).scalar_one_or_none()
    if value is None:
        raise DatabaseError("Database schema version marker is missing")
    if not isinstance(value, int):
        raise DatabaseError("Database schema version marker is invalid")
    return value


def migrate_database(engine: Engine, installed_version: int) -> None:
    """Apply each supported migration atomically and advance its marker last."""
    if (
        not MINIMUM_MIGRATABLE_SCHEMA_VERSION
        <= installed_version
        <= CURRENT_SCHEMA_VERSION
    ):
        raise DatabaseError(
            f"Unsupported database schema version {installed_version}; "
            f"supported versions are {MINIMUM_MIGRATABLE_SCHEMA_VERSION} "
            f"through {CURRENT_SCHEMA_VERSION}"
        )
    for version in range(installed_version, CURRENT_SCHEMA_VERSION):
        migration = MIGRATIONS.get(version)
        if migration is None:
            raise DatabaseError(
                f"No database migration is registered for schema {version}"
            )
        try:
            with engine.connect() as connection:
                # Python's SQLite legacy transaction mode does not begin a
                # transaction for DDL. Start one explicitly so schema changes
                # and the version marker always commit or roll back together.
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                current = installed_schema_version(connection)
                if current != version:
                    raise DatabaseError(
                        "Database schema changed while migrations were running"
                    )
                migration(connection)
                connection.execute(
                    text("UPDATE schema_version SET version = :version WHERE id = 1"),
                    {"version": version + 1},
                )
                connection.commit()
        except Exception as exc:
            if isinstance(exc, DatabaseError):
                raise
            raise DatabaseError(
                f"Database migration from schema {version} failed; "
                "the prior schema was retained"
            ) from exc


def initialize_database(engine: Engine) -> None:
    """Create or transactionally migrate the schema and install integrity guards."""
    with engine.connect() as connection:
        version = installed_schema_version(connection)
    if version is None:
        with engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            Base.metadata.create_all(connection)
            connection.execute(
                text("INSERT INTO schema_version (id, version) VALUES (1, :version)"),
                {"version": CURRENT_SCHEMA_VERSION},
            )
            connection.commit()
    else:
        migrate_database(engine, version)

    with engine.begin() as connection:
        triggers = (
            """
            CREATE TRIGGER IF NOT EXISTS time_entry_subtask_insert_guard
            BEFORE INSERT ON time_entry
            WHEN NEW.subtask_id IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM subtask WHERE id = NEW.subtask_id
                              AND task_id = NEW.task_id)
            BEGIN SELECT RAISE(ABORT, 'subtask does not belong to task'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS time_entry_subtask_update_guard
            BEFORE UPDATE OF task_id, subtask_id ON time_entry
            WHEN NEW.subtask_id IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM subtask WHERE id = NEW.subtask_id
                              AND task_id = NEW.task_id)
            BEGIN SELECT RAISE(ABORT, 'subtask does not belong to task'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS time_entry_overlap_insert_guard
            BEFORE INSERT ON time_entry
            WHEN EXISTS (
              SELECT 1 FROM time_entry AS existing
              WHERE existing.user_id = NEW.user_id
                AND existing.visible = 1
                AND NEW.started_at < COALESCE(
                    existing.stopped_at, '9999-12-31 23:59:59.999999'
                )
                AND COALESCE(
                    NEW.stopped_at, '9999-12-31 23:59:59.999999'
                ) > existing.started_at
            )
            BEGIN SELECT RAISE(ABORT, 'time entries for one user cannot overlap'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS time_entry_overlap_update_guard
            BEFORE UPDATE OF user_id, started_at, stopped_at ON time_entry
            WHEN EXISTS (
              SELECT 1 FROM time_entry AS existing
              WHERE existing.id != OLD.id AND existing.user_id = NEW.user_id
                AND existing.visible = 1
                AND NEW.started_at < COALESCE(
                    existing.stopped_at, '9999-12-31 23:59:59.999999'
                )
                AND COALESCE(
                    NEW.stopped_at, '9999-12-31 23:59:59.999999'
                ) > existing.started_at
            )
            BEGIN SELECT RAISE(ABORT, 'time entries for one user cannot overlap'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS enabled_admin_update_guard
            BEFORE UPDATE OF role, is_enabled ON user_account
            WHEN OLD.role = 'admin' AND OLD.is_enabled = 1
              AND (NEW.role != 'admin' OR NEW.is_enabled = 0)
              AND NOT EXISTS (SELECT 1 FROM user_account WHERE id != OLD.id
                              AND role = 'admin' AND is_enabled = 1)
            BEGIN
              SELECT RAISE(ABORT, 'at least one enabled administrator is required');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS client_report_password_version_insert_guard
            BEFORE INSERT ON client WHEN NEW.report_password_version < 1
            BEGIN SELECT RAISE(ABORT, 'report password version must be positive'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS client_report_password_version_update_guard
            BEFORE UPDATE OF report_password_version ON client
            WHEN NEW.report_password_version < 1
            BEGIN SELECT RAISE(ABORT, 'report password version must be positive'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS audit_event_update_guard
            BEFORE UPDATE ON audit_event
            BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS audit_event_delete_guard
            BEFORE DELETE ON audit_event
            BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS invoice_delete_guard
            BEFORE DELETE ON invoice
            BEGIN SELECT RAISE(ABORT, 'invoices are permanent'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS invoice_frozen_update_guard
            BEFORE UPDATE OF client_id, contract_id, project_sequence,
                invoice_number, issued_at, range_start_utc, range_end_utc,
                timezone_name, client_name, project_name, contact_name,
                contact_email, hourly_rate_cents, payment_terms_days,
                total_seconds, total_cents, due_date, pdf_bytes
            ON invoice
            BEGIN SELECT RAISE(ABORT, 'invoice snapshots are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS invoice_line_update_guard
            BEFORE UPDATE ON invoice_line
            BEGIN SELECT RAISE(ABORT, 'invoice lines are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS invoice_line_delete_guard
            BEFORE DELETE ON invoice_line
            BEGIN SELECT RAISE(ABORT, 'invoice lines are immutable'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS time_entry_invoice_insert_guard
            BEFORE INSERT ON time_entry
            WHEN NEW.invoice_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM invoice
                WHERE id = NEW.invoice_id
                  AND invoice_number = NEW.invoice_number
            )
            BEGIN SELECT RAISE(ABORT, 'entry invoice metadata is inconsistent'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS time_entry_invoice_update_guard
            BEFORE UPDATE OF invoice_id, invoice_number ON time_entry
            WHEN NEW.invoice_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM invoice
                WHERE id = NEW.invoice_id
                  AND invoice_number = NEW.invoice_number
            )
            BEGIN SELECT RAISE(ABORT, 'entry invoice metadata is inconsistent'); END
            """,
        )
        for trigger in triggers:
            connection.execute(text(trigger))


def verify_cipher_integrity(engine: Engine) -> None:
    """Verify SQLCipher page authentication and SQLite logical integrity."""
    with engine.connect() as connection:
        cipher_errors = list(
            connection.exec_driver_sql("PRAGMA cipher_integrity_check")
        )
        if cipher_errors:
            raise DatabaseError("SQLCipher page integrity validation failed")
        if connection.exec_driver_sql("PRAGMA integrity_check").scalar_one() != "ok":
            raise DatabaseError("SQLite logical integrity validation failed")


def database_is_encrypted(path: Path) -> bool:
    """Return whether an existing database lacks the plaintext SQLite header."""
    if not path.exists() or path.stat().st_size < len(SQLITE_HEADER):
        return False
    with path.open("rb") as database_file:
        return database_file.read(len(SQLITE_HEADER)) != SQLITE_HEADER


def init_app(app: Flask) -> None:
    """Initialize the engine and request-scoped sessions for a Flask app."""
    engine = build_engine(
        Path(cast(str, app.config["DATABASE_PATH"])),
        cast(str, app.config["SQLCIPHER_PASSPHRASE"]),
    )
    initialize_database(engine)
    verify_cipher_integrity(engine)
    factory = sessionmaker(
        bind=engine,
        class_=ApplicationSession,
        expire_on_commit=False,
        future=True,
    )
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
    cast(Engine, app.extensions["database_engine"]).dispose()


def health_check(app: Flask) -> None:
    """Verify the database can answer a minimal keyed query."""
    with cast(Engine, app.extensions["database_engine"]).connect() as connection:
        connection.execute(text("SELECT 1")).scalar_one()
