"""Idempotent initial administrator reconciliation."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import cast

from argon2 import Type, extract_parameters
from flask import Flask
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import normalize_email, required_text, valid_totp_secret
from .config import ConfigurationError
from .models import ApplicationMetadata, User

BOOTSTRAP_EMAIL_KEY = "bootstrap_admin_email"
BOOTSTRAP_PASSWORD_KEY = "bootstrap_admin_password_fingerprint"  # noqa: S105
BOOTSTRAP_TOTP_KEY = "bootstrap_admin_totp_fingerprint"


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def _fingerprint(value: str) -> str:
    """Fingerprint configured values without persisting a second secret copy."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _metadata(database: Session, key: str) -> str | None:
    item = database.get(ApplicationMetadata, key)
    return item.value if item else None


def _set_metadata(database: Session, key: str, value: str) -> None:
    item = database.get(ApplicationMetadata, key)
    if item is None:
        database.add(ApplicationMetadata(key=key, value=value))
    else:
        item.value = value


def reconcile_initial_admin(app: Flask, database: Session) -> None:
    """Create or reconcile the configured administrator by normalized email."""
    if app.config.get("SKIP_BOOTSTRAP"):
        return
    try:
        email = normalize_email(cast(str, app.config["INITIAL_ADMIN_EMAIL"]))
        first_name = required_text(
            cast(str, app.config["INITIAL_ADMIN_FIRST_NAME"]),
            "Initial admin first name",
            maximum=100,
        )
        last_name = required_text(
            cast(str, app.config["INITIAL_ADMIN_LAST_NAME"]),
            "Initial admin last name",
            maximum=100,
        )
    except (KeyError, ValueError) as exc:
        raise ConfigurationError(
            "Initial administrator email, first name, and last name are required"
        ) from exc

    password_hash = cast(str | None, app.config.get("INITIAL_ADMIN_PASSWORD_HASH"))
    totp_secret = cast(str | None, app.config.get("INITIAL_ADMIN_TOTP_SECRET"))
    if not password_hash or not totp_secret:
        raise ConfigurationError(
            "Initial administrator password hash and TOTP secret are required"
        )
    try:
        parameters = extract_parameters(password_hash)
    except Exception as exc:
        raise ConfigurationError(
            "INITIAL_ADMIN_PASSWORD_HASH must be a valid Argon2 hash"
        ) from exc
    if (
        parameters.type is not Type.ID
        or parameters.memory_cost < 65536
        or parameters.time_cost < 3
        or parameters.parallelism < 1
    ):
        raise ConfigurationError(
            "INITIAL_ADMIN_PASSWORD_HASH must use Argon2id with secure parameters"
        )
    if not valid_totp_secret(totp_secret):
        raise ConfigurationError(
            "INITIAL_ADMIN_TOTP_SECRET must be a valid Base32 TOTP secret"
        )

    password_fingerprint = _fingerprint(password_hash)
    totp_fingerprint = _fingerprint(totp_secret)
    prior_bootstrap_email = _metadata(database, BOOTSTRAP_EMAIL_KEY)
    prior_password_fingerprint = _metadata(database, BOOTSTRAP_PASSWORD_KEY)
    prior_totp_fingerprint = _metadata(database, BOOTSTRAP_TOTP_KEY)

    user = database.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password_hash=password_hash,
            totp_secret=totp_secret,
            pending_totp_secret=None,
            role="admin",
            is_enabled=True,
            password_change_required=False,
            session_version=1,
            created_at=_utc_now(),
        )
        database.add(user)
    else:
        password_changed_in_config = (
            prior_bootstrap_email != email
            or prior_password_fingerprint != password_fingerprint
        )
        totp_changed_in_config = (
            prior_bootstrap_email != email or prior_totp_fingerprint != totp_fingerprint
        )
        authentication_changed = False
        if password_changed_in_config and user.password_hash != password_hash:
            user.password_hash = password_hash
            user.password_change_required = False
            authentication_changed = True
        if totp_changed_in_config and user.totp_secret != totp_secret:
            user.totp_secret = totp_secret
            user.pending_totp_secret = None
            authentication_changed = True
        if authentication_changed:
            user.session_version += 1

    user.first_name = first_name
    user.last_name = last_name
    user.role = "admin"
    user.is_enabled = True

    _set_metadata(database, BOOTSTRAP_EMAIL_KEY, email)
    _set_metadata(database, BOOTSTRAP_PASSWORD_KEY, password_fingerprint)
    _set_metadata(database, BOOTSTRAP_TOTP_KEY, totp_fingerprint)
