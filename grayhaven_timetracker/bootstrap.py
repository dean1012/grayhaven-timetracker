"""One-time first-install administrator and user provisioning."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from argon2 import Type, extract_parameters
from flask import Flask
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import normalize_email, required_text, valid_totp_secret
from .config import ConfigurationError
from .models import User

BOOTSTRAP_USER_ALLOWED_FIELDS = frozenset(
    {
        "email",
        "enabled",
        "first_name",
        "last_name",
        "password_hash",
        "role",
        "totp_secret",
    }
)
BOOTSTRAP_USER_REQUIRED_FIELDS = frozenset(
    {"email", "first_name", "last_name", "password_hash", "role"}
)
BOOTSTRAP_USER_LIMIT = 1000


@dataclass(frozen=True)
class BootstrapUser:
    """Validated initial account state supplied by deployment automation."""

    email: str
    first_name: str
    last_name: str
    password_hash: str
    totp_secret: str | None
    role: str
    enabled: bool


@dataclass(frozen=True)
class BootstrapOutcome:
    """Safe audit information for one account created at first install."""

    user: User
    outcome: str
    details: dict[str, Any]


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def _audit_user_state(user: User) -> dict[str, str | bool]:
    """Return non-sensitive initial account state for the audit trail."""
    return {
        "Email": user.email,
        "First Name": user.first_name,
        "Last Name": user.last_name,
        "Role": "Administrator" if user.is_admin else "User",
        "Enabled": user.is_enabled,
        "Two-Factor Authentication": "Enabled" if user.totp_secret else "Disabled",
    }


def _validate_password_hash(value: str, label: str) -> None:
    try:
        parameters = extract_parameters(value)
    except Exception as exc:
        raise ConfigurationError(f"{label} must be a valid Argon2 hash") from exc
    if (
        parameters.type is not Type.ID
        or parameters.memory_cost < 65536
        or parameters.time_cost < 3
        or parameters.parallelism < 1
    ):
        raise ConfigurationError(f"{label} must use Argon2id with secure parameters")


def _manifest_user(value: Any, index: int) -> BootstrapUser:
    label = f"BOOTSTRAP_USERS entry {index}"
    if not isinstance(value, dict):
        raise ConfigurationError(f"{label} must be an object")
    fields = set(value)
    unknown = fields - BOOTSTRAP_USER_ALLOWED_FIELDS
    missing = BOOTSTRAP_USER_REQUIRED_FIELDS - fields
    if unknown:
        raise ConfigurationError(f"{label} contains unsupported fields")
    if missing:
        raise ConfigurationError(f"{label} is missing required fields")
    if any(
        not isinstance(value[field], str) for field in BOOTSTRAP_USER_REQUIRED_FIELDS
    ):
        raise ConfigurationError(f"{label} required fields must be strings")
    enabled = value.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigurationError(f"{label} enabled must be a boolean")
    role = cast(str, value["role"])
    if role not in {"admin", "user"}:
        raise ConfigurationError(f"{label} role must be admin or user")
    try:
        email = normalize_email(cast(str, value["email"]))
        first_name = required_text(
            cast(str, value["first_name"]), "First name", maximum=100
        )
        last_name = required_text(
            cast(str, value["last_name"]), "Last name", maximum=100
        )
    except ValueError as exc:
        raise ConfigurationError(f"{label} contains invalid identity data") from exc
    totp_secret = value.get("totp_secret")
    if totp_secret is not None and (
        not isinstance(totp_secret, str) or not valid_totp_secret(totp_secret)
    ):
        raise ConfigurationError(f"{label} totp_secret must be valid Base32")
    return BootstrapUser(
        email=email,
        first_name=first_name,
        last_name=last_name,
        password_hash=cast(str, value["password_hash"]),
        totp_secret=totp_secret,
        role=role,
        enabled=enabled,
    )


def configured_bootstrap_users(app: Flask) -> list[BootstrapUser]:
    """Parse and validate the one-time deployment manifest."""
    raw_manifest = cast(str | None, app.config.get("BOOTSTRAP_USERS"))
    if raw_manifest is None:
        raise ConfigurationError(
            "BOOTSTRAP_USERS or BOOTSTRAP_USERS_FILE is required for first install"
        )
    try:
        manifest = json.loads(raw_manifest)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ConfigurationError("BOOTSTRAP_USERS must contain valid JSON") from exc
    if not isinstance(manifest, list):
        raise ConfigurationError("BOOTSTRAP_USERS must contain a JSON list")
    if not manifest:
        raise ConfigurationError("At least one bootstrap user is required")
    if len(manifest) > BOOTSTRAP_USER_LIMIT:
        raise ConfigurationError(
            f"BOOTSTRAP_USERS cannot exceed {BOOTSTRAP_USER_LIMIT} entries"
        )
    users = [_manifest_user(value, index) for index, value in enumerate(manifest)]
    if len({user.email for user in users}) != len(users):
        raise ConfigurationError("Bootstrap user email addresses must be unique")
    if not any(user.role == "admin" and user.enabled for user in users):
        raise ConfigurationError(
            "At least one enabled bootstrap administrator is required"
        )
    return users


def reconcile_bootstrap_users(app: Flask, database: Session) -> list[BootstrapOutcome]:
    """Create initial users once; afterward, all user management is in-app."""
    if app.config.get("SKIP_BOOTSTRAP"):
        return []
    if database.scalar(select(User.id).limit(1)) is not None:
        return []
    specs = configured_bootstrap_users(app)
    outcomes: list[BootstrapOutcome] = []
    for spec in specs:
        _validate_password_hash(spec.password_hash, "Bootstrap user password_hash")
        user = User(
            email=spec.email,
            first_name=spec.first_name,
            last_name=spec.last_name,
            password_hash=spec.password_hash,
            totp_secret=spec.totp_secret,
            pending_totp_secret=None,
            role=spec.role,
            is_enabled=spec.enabled,
            password_change_required=True,
            session_version=1,
            created_at=_utc_now(),
        )
        database.add(user)
        outcomes.append(
            BootstrapOutcome(
                user=user,
                outcome="created",
                details={"initial_values": _audit_user_state(user)},
            )
        )
    database.flush()
    return outcomes
