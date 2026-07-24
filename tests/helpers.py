"""Shared encrypted application fixtures for unit and integration tests."""

from __future__ import annotations

import json
import logging
import tempfile
import time
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pyotp
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select

from grayhaven_timetracker import create_app, routes
from grayhaven_timetracker.auth import (
    LoginLimiter,
    hash_password,
    reset_totp_replay_state,
)
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
        "BOOTSTRAP_USERS": json.dumps(
            [
                {
                    "email": ADMIN_EMAIL,
                    "first_name": ADMIN_FIRST_NAME,
                    "last_name": ADMIN_LAST_NAME,
                    "password_hash": ADMIN_PASSWORD_HASH,
                    "role": "admin",
                    "totp_secret": ADMIN_TOTP_SECRET,
                }
            ]
        ),
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
        logging.disable(logging.CRITICAL)
        self.app = create_app(test_config(self.root))
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.password_change_required = False
        routes.login_limiter = LoginLimiter()
        routes.login_ip_limiter = LoginLimiter(limit=50)
        routes.shared_report_limiter = LoginLimiter()
        routes.sensitive_action_limiter = LoginLimiter()
        routes.report_password_confirmation_store = (
            routes.ReportPasswordConfirmationStore()
        )
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
        totp_token: str | None = None,
    ) -> FlaskClient:
        """Authenticate a test client with password and TOTP."""
        selected = client or self.client
        response = selected.post(
            "/login",
            data={
                "email": email,
                "password": password,
            },
        )
        if totp_secret:
            self.assertEqual(response.location, "/login/authenticator")
            response = selected.post(
                "/login/authenticator",
                data={"totp_digit": list(totp_token or pyotp.TOTP(totp_secret).now())},
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

    def authorize_sensitive_action(
        self,
        path: str,
        client: FlaskClient | None = None,
        *,
        password: str = ADMIN_PASSWORD,
        totp_secret: str = ADMIN_TOTP_SECRET,
        totp_token: str | None = None,
    ) -> FlaskClient:
        """Complete the password and optional TOTP flow for one action path."""
        selected = client or self.client
        response = selected.get(path)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/reauthenticate?", response.location)
        authentication_url = response.location
        self.assertEqual(selected.get(authentication_url).status_code, 200)
        response = selected.post(authentication_url, data={"password": password})
        if totp_secret:
            self.assertEqual(response.location, "/reauthenticate/authenticator")
            self.assertEqual(
                selected.get("/reauthenticate/authenticator").status_code, 200
            )
            with selected.session_transaction() as browser_session:
                user_id = browser_session["user_id"]
            with session_scope(self.app) as database:
                reset_totp_replay_state(database, user_id)
            token = totp_token or pyotp.TOTP(totp_secret).generate_otp(
                int(time.time()) // 30
            )
            response = selected.post(
                "/reauthenticate/authenticator",
                data={"totp_digit": list(token)},
            )
        self.assertEqual(response.location, path)
        return selected

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
