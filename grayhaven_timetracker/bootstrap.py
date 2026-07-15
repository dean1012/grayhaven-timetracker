"""Idempotent deployment-managed user reconciliation."""

from __future__ import annotations

import hashlib
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
from .models import ApplicationMetadata, TimeEntry, User

BOOTSTRAP_EMAIL_KEY = "bootstrap_admin_email"
BOOTSTRAP_PASSWORD_KEY = "bootstrap_admin_password_fingerprint"  # noqa: S105
BOOTSTRAP_TOTP_KEY = "bootstrap_admin_totp_fingerprint"
BOOTSTRAP_USER_KEY_PREFIX = "bootstrap_user_"
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
    """Validated desired state for one deployment-managed account."""

    email: str
    first_name: str
    last_name: str
    password_hash: str
    totp_secret: str | None
    role: str
    enabled: bool
    metadata_key: str | None = None


@dataclass(frozen=True)
class BootstrapOutcome:
    """Safe audit information for one reconciled account."""

    user: User
    outcome: str


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def _fingerprint(value: str) -> str:
    """Fingerprint configured values without persisting a second secret copy."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _managed_user_key(email: str) -> str:
    return f"{BOOTSTRAP_USER_KEY_PREFIX}{_fingerprint(email)}"


def _metadata(database: Session, key: str) -> str | None:
    item = database.get(ApplicationMetadata, key)
    return item.value if item else None


def _set_metadata(database: Session, key: str, value: str) -> None:
    item = database.get(ApplicationMetadata, key)
    if item is None:
        database.add(ApplicationMetadata(key=key, value=value))
    else:
        item.value = value


def _delete_metadata(database: Session, key: str) -> None:
    item = database.get(ApplicationMetadata, key)
    if item is not None:
        database.delete(item)


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


def _legacy_initial_admin(app: Flask) -> BootstrapUser | None:
    password_hash = cast(str | None, app.config.get("INITIAL_ADMIN_PASSWORD_HASH"))
    totp_secret = cast(str | None, app.config.get("INITIAL_ADMIN_TOTP_SECRET"))
    if password_hash is None:
        if totp_secret is not None:
            raise ConfigurationError(
                "INITIAL_ADMIN_TOTP_SECRET requires INITIAL_ADMIN_PASSWORD_HASH"
            )
        return None
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
    _validate_password_hash(password_hash, "INITIAL_ADMIN_PASSWORD_HASH")
    if totp_secret is not None and not valid_totp_secret(totp_secret):
        raise ConfigurationError(
            "INITIAL_ADMIN_TOTP_SECRET must be a valid Base32 TOTP secret"
        )
    return BootstrapUser(
        email=email,
        first_name=first_name,
        last_name=last_name,
        password_hash=password_hash,
        totp_secret=totp_secret,
        role="admin",
        enabled=True,
    )


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
    password_hash = cast(str, value["password_hash"])
    _validate_password_hash(password_hash, f"{label} password_hash")
    totp_secret = value.get("totp_secret")
    if totp_secret is not None and (
        not isinstance(totp_secret, str) or not valid_totp_secret(totp_secret)
    ):
        raise ConfigurationError(f"{label} totp_secret must be valid Base32")
    return BootstrapUser(
        email=email,
        first_name=first_name,
        last_name=last_name,
        password_hash=password_hash,
        totp_secret=totp_secret,
        role=role,
        enabled=enabled,
        metadata_key=_managed_user_key(email),
    )


def configured_bootstrap_users(app: Flask) -> list[BootstrapUser]:
    """Parse and validate legacy and manifest-based bootstrap users."""
    users: list[BootstrapUser] = []
    legacy = _legacy_initial_admin(app)
    if legacy is not None:
        users.append(legacy)

    raw_manifest = cast(str | None, app.config.get("BOOTSTRAP_USERS"))
    if raw_manifest is not None:
        try:
            manifest = json.loads(raw_manifest)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ConfigurationError("BOOTSTRAP_USERS must contain valid JSON") from exc
        if not isinstance(manifest, list):
            raise ConfigurationError("BOOTSTRAP_USERS must contain a JSON list")
        if len(manifest) > BOOTSTRAP_USER_LIMIT:
            raise ConfigurationError(
                f"BOOTSTRAP_USERS cannot exceed {BOOTSTRAP_USER_LIMIT} entries"
            )
        users.extend(
            _manifest_user(value, index) for index, value in enumerate(manifest)
        )

    if not users:
        raise ConfigurationError("At least one bootstrap user is required")
    emails = [user.email for user in users]
    if len(emails) != len(set(emails)):
        raise ConfigurationError("Bootstrap user email addresses must be unique")
    if not any(user.role == "admin" and user.enabled for user in users):
        raise ConfigurationError(
            "At least one enabled bootstrap administrator is required"
        )
    return users


def _prior_fingerprints(
    database: Session, spec: BootstrapUser
) -> tuple[str | None, str | None]:
    if spec.metadata_key is None:
        return (
            _metadata(database, BOOTSTRAP_PASSWORD_KEY),
            _metadata(database, BOOTSTRAP_TOTP_KEY),
        )
    raw = _metadata(database, spec.metadata_key)
    if raw is None:
        return None, None
    try:
        stored = json.loads(raw)
    except json.JSONDecodeError:
        return None, None
    if not isinstance(stored, dict):
        return None, None
    password = stored.get("password")
    totp = stored.get("totp")
    return (
        password if isinstance(password, str) else None,
        totp if isinstance(totp, str) else None,
    )


def _store_fingerprints(database: Session, spec: BootstrapUser) -> None:
    password = _fingerprint(spec.password_hash)
    totp = _fingerprint(spec.totp_secret) if spec.totp_secret is not None else None
    if spec.metadata_key is None:
        _set_metadata(database, BOOTSTRAP_EMAIL_KEY, spec.email)
        _set_metadata(database, BOOTSTRAP_PASSWORD_KEY, password)
        if totp is None:
            _delete_metadata(database, BOOTSTRAP_TOTP_KEY)
        else:
            _set_metadata(database, BOOTSTRAP_TOTP_KEY, totp)
        return
    _set_metadata(
        database,
        spec.metadata_key,
        json.dumps(
            {"email": spec.email, "password": password, "totp": totp},
            separators=(",", ":"),
            sort_keys=True,
        ),
    )


def _apply_identity_and_authentication(
    user: User, spec: BootstrapUser, prior_password: str | None, prior_totp: str | None
) -> bool:
    changed = user.first_name != spec.first_name or user.last_name != spec.last_name
    user.first_name = spec.first_name
    user.last_name = spec.last_name
    authentication_changed = False
    password_fingerprint = _fingerprint(spec.password_hash)
    if (
        prior_password != password_fingerprint
        and user.password_hash != spec.password_hash
    ):
        user.password_hash = spec.password_hash
        user.password_change_required = False
        authentication_changed = True
    if spec.totp_secret is not None:
        totp_fingerprint = _fingerprint(spec.totp_secret)
        if prior_totp != totp_fingerprint and user.totp_secret != spec.totp_secret:
            user.totp_secret = spec.totp_secret
            user.pending_totp_secret = None
            authentication_changed = True
    if authentication_changed:
        user.session_version += 1
    return changed or authentication_changed


def _stop_active_timer(database: Session, user: User) -> None:
    stopped_at = _utc_now()
    for entry in database.scalars(
        select(TimeEntry).where(
            TimeEntry.user_id == user.id,
            TimeEntry.stopped_at.is_(None),
        )
    ):
        entry.stopped_at = max(stopped_at, entry.started_at)


def reconcile_bootstrap_users(app: Flask, database: Session) -> list[BootstrapOutcome]:
    """Create or reconcile every deployment-managed user."""
    if app.config.get("SKIP_BOOTSTRAP"):
        return []
    specs = configured_bootstrap_users(app)
    records: list[tuple[BootstrapUser, User, bool]] = []
    changed_by_email: dict[str, bool] = {}

    for spec in specs:
        user = database.scalar(select(User).where(User.email == spec.email))
        created = user is None
        if user is None:
            user = User(
                email=spec.email,
                first_name=spec.first_name,
                last_name=spec.last_name,
                password_hash=spec.password_hash,
                totp_secret=spec.totp_secret,
                pending_totp_secret=None,
                role=spec.role,
                is_enabled=spec.enabled,
                password_change_required=False,
                session_version=1,
                created_at=_utc_now(),
            )
            database.add(user)
            changed_by_email[spec.email] = True
        else:
            prior_password, prior_totp = _prior_fingerprints(database, spec)
            changed_by_email[spec.email] = _apply_identity_and_authentication(
                user, spec, prior_password, prior_totp
            )
            if spec.role == "admin" and spec.enabled:
                changed_by_email[spec.email] = changed_by_email[spec.email] or (
                    user.role != "admin" or not user.is_enabled
                )
                user.role = "admin"
                user.is_enabled = True
        _store_fingerprints(database, spec)
        records.append((spec, user, created))

    # Promote or enable desired administrators before demoting or disabling any
    # existing administrator so the database's last-admin guard remains valid.
    database.flush()
    for spec, user, created in records:
        if not created and (spec.role != "admin" or not spec.enabled):
            role_or_state_changed = (
                user.role != spec.role or user.is_enabled != spec.enabled
            )
            if user.is_enabled and not spec.enabled:
                _stop_active_timer(database, user)
            user.role = spec.role
            user.is_enabled = spec.enabled
            changed_by_email[spec.email] = (
                changed_by_email[spec.email] or role_or_state_changed
            )
    database.flush()

    configured_manifest_keys = {
        spec.metadata_key for spec in specs if spec.metadata_key is not None
    }
    stale_items = database.scalars(
        select(ApplicationMetadata).where(
            ApplicationMetadata.key.startswith(BOOTSTRAP_USER_KEY_PREFIX)
        )
    ).all()
    for item in stale_items:
        if item.key not in configured_manifest_keys:
            database.delete(item)

    return [
        BootstrapOutcome(
            user=user,
            outcome=(
                "created"
                if created
                else "updated"
                if changed_by_email[spec.email]
                else "unchanged"
            ),
        )
        for spec, user, created in records
    ]


def is_deployment_managed_user(database: Session, email: str) -> bool:
    """Return whether deployment configuration owns an account identity."""
    legacy_email = _metadata(database, BOOTSTRAP_EMAIL_KEY)
    return (
        legacy_email == email
        or database.get(ApplicationMetadata, _managed_user_key(email)) is not None
    )
