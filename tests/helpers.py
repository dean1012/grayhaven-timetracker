"""Shared encrypted application fixtures for unit and integration tests."""

from __future__ import annotations

import logging
import tempfile
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pyotp
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select

from grayhaven_timetracker import create_app, routes
from grayhaven_timetracker.auth import LoginLimiter, hash_password
from grayhaven_timetracker.database import dispose_app_database, session_scope
from grayhaven_timetracker.models import (
    Client,
    Contract,
    Subtask,
    Task,
    TimeEntry,
    User,
)

ADMIN_EMAIL = "admin@example.invalid"
ADMIN_FIRST_NAME = "Admin"
ADMIN_LAST_NAME = "Operator"
ADMIN_PASSWORD = "Administrative-Test-Password-0001!"
ADMIN_PASSWORD_HASH = hash_password(ADMIN_PASSWORD)
ADMIN_TOTP_SECRET = "JBSWY3DPEHPK3PXP"
SQLCIPHER_PASSPHRASE = "Test-SQLCipher-passphrase-with-32-characters!"


@dataclass(frozen=True)
class SeedData:
    """Identifiers for one representative contract work breakdown."""

    client_id: int
    contract_id: int
    task_id: int
    subtask_id: int
    other_task_id: int
    entry_id: int


def test_config(root: Path, **overrides: object) -> dict[str, object]:
    """Return a complete application configuration for a temporary test app."""
    config: dict[str, object] = {
        "APP_VERSION": "test-build",
        "BRANDING_PATH": str(root / "branding"),
        "CONTACT_URL": "https://example.invalid/contact",
        "DATABASE_PATH": str(root / "timetracker.sqlite3"),
        "DISPLAY_TIMEZONE": "America/Chicago",
        "INITIAL_ADMIN_EMAIL": ADMIN_EMAIL,
        "INITIAL_ADMIN_FIRST_NAME": ADMIN_FIRST_NAME,
        "INITIAL_ADMIN_LAST_NAME": ADMIN_LAST_NAME,
        "INITIAL_ADMIN_PASSWORD_HASH": ADMIN_PASSWORD_HASH,
        "INITIAL_ADMIN_TOTP_SECRET": ADMIN_TOTP_SECRET,
        "SECRET_KEY": "Test-Flask-secret-key-with-at-least-32-chars!",
        "SESSION_COOKIE_SECURE": False,
        "SKIP_BRANDING_VALIDATION": True,
        "SQLCIPHER_PASSPHRASE": SQLCIPHER_PASSPHRASE,
        "TESTING": True,
        "TRUSTED_PROXY_COUNT": 0,
        "WTF_CSRF_ENABLED": False,
    }
    config.update(overrides)
    return config


class AppTestCase(unittest.TestCase):
    """Create a clean SQLCipher-backed Flask application for each test."""

    app: Flask
    client: FlaskClient

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.app = create_app(test_config(self.root))
        logging.disable(logging.CRITICAL)
        routes.login_limiter = LoginLimiter()
        routes.login_ip_limiter = LoginLimiter(limit=50)
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        logging.disable(logging.NOTSET)
        dispose_app_database(self.app)
        self.temporary_directory.cleanup()

    def login(
        self,
        client: FlaskClient | None = None,
        *,
        email: str = ADMIN_EMAIL,
        password: str = ADMIN_PASSWORD,
        totp_secret: str = ADMIN_TOTP_SECRET,
    ) -> FlaskClient:
        """Authenticate a test client with password and TOTP."""
        selected = client or self.client
        response = selected.post(
            "/login",
            data={
                "email": email,
                "password": password,
                "totp": pyotp.TOTP(totp_secret).now(),
            },
        )
        self.assertEqual(response.status_code, 302)
        return selected

    def create_user(
        self,
        *,
        email: str = "user@example.invalid",
        first_name: str = "Standard",
        last_name: str = "User",
        password: str = "Standard-User-Test-Password-0001!",
        role: str = "user",
        enabled: bool = True,
        totp_secret: str = "KRSXG5DSNFXGOIDB",
    ) -> User:
        """Persist a representative user and return its detached values."""
        with session_scope(self.app) as database:
            user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                password_hash=hash_password(password),
                totp_secret=totp_secret,
                pending_totp_secret=None,
                role=role,
                is_enabled=enabled,
                session_version=1,
                created_at=datetime(2026, 7, 15, 12, 0, 0),
            )
            database.add(user)
            database.flush()
            database.expunge(user)
        return user

    def seed_contract(self, *, entry_user_id: int | None = None) -> SeedData:
        """Create one client, contract, tasks, subtask, and completed session."""
        with session_scope(self.app) as database:
            user = (
                database.get(User, entry_user_id)
                if entry_user_id is not None
                else database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            )
            assert user is not None
            client = Client(
                name="Pellera",
                contact_name="Alex Example",
                contact_email="alex@example.invalid",
            )
            contract = Contract(
                client=client,
                name="Hamilton Beach - Phase 1",
                contact_name="Morgan Example",
                contact_email="morgan@example.invalid",
                hourly_rate_cents=5500,
            )
            task = Task(contract=contract, name="Discovery")
            subtask = Subtask(task=task, name="Server 1")
            other_task = Task(contract=contract, name="Implementation")
            start = datetime(2026, 7, 15, 1, 30, 0)
            entry = TimeEntry(
                user=user,
                task=task,
                subtask=subtask,
                started_at=start,
                stopped_at=start + timedelta(hours=1, seconds=7),
            )
            database.add_all([client, contract, task, subtask, other_task, entry])
            database.flush()
            result = SeedData(
                client_id=client.id,
                contract_id=contract.id,
                task_id=task.id,
                subtask_id=subtask.id,
                other_task_id=other_task.id,
                entry_id=entry.id,
            )
        return result
