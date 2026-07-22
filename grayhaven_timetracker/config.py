"""Application configuration and secret loading."""

from __future__ import annotations

import os
import unicodedata
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class ConfigurationError(RuntimeError):
    """Raised when required application configuration is invalid."""


DEFAULT_CONTACT_URL = (
    "https://calendar.proton.me/bookings#HmPL_I2j-XCVf8y4lj2ikbmIGhzdlHxXJ7MnBngp-i8="
)


def _contains_control(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def _read_secret(
    name: str, *, required: bool = True, allow_missing_file: bool = False
) -> str | None:
    """Read a secret from ``NAME_FILE`` or ``NAME`` without logging it."""
    file_value = os.environ.get(f"{name}_FILE")
    direct_value = os.environ.get(name)
    if file_value and direct_value:
        raise ConfigurationError(f"Set only one of {name} and {name}_FILE")
    value: str | None
    if file_value:
        try:
            value = Path(file_value).read_text(encoding="utf-8").rstrip("\r\n")
        except FileNotFoundError as exc:
            if allow_missing_file:
                return None
            raise ConfigurationError(f"Unable to read {name}_FILE") from exc
        except OSError as exc:
            raise ConfigurationError(f"Unable to read {name}_FILE") from exc
    else:
        value = direct_value
    if required and not value:
        raise ConfigurationError(f"{name} or {name}_FILE is required")
    return value


def _read_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be a boolean value")


def _read_int(name: str, default: int, *, minimum: int = 0) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ConfigurationError(f"{name} must be at least {minimum}")
    return value


def _read_trusted_hosts() -> list[str]:
    """Parse the explicit browser Host allowlist used by Flask."""
    raw = os.environ.get("TRUSTED_HOSTS", "localhost,127.0.0.1")
    hosts = [host.strip() for host in raw.split(",") if host.strip()]
    if not hosts or any(
        host == "*"
        or "://" in host
        or any(character in "/@?#\\" for character in host)
        or any(character.isspace() for character in host)
        or _contains_control(host)
        for host in hosts
    ):
        raise ConfigurationError(
            "TRUSTED_HOSTS must contain comma-separated hostnames without URLs"
        )
    return hosts


def environment_config() -> dict[str, Any]:
    """Build runtime configuration from the process environment."""
    database_path = Path(
        os.environ.get("DATABASE_PATH", "/app/data/timetracker.sqlite3")
    ).resolve()
    sqlcipher_passphrase = _read_secret("SQLCIPHER_PASSPHRASE")
    if sqlcipher_passphrase is not None and len(sqlcipher_passphrase) < 32:
        raise ConfigurationError(
            "SQLCIPHER_PASSPHRASE must contain at least 32 characters"
        )
    if sqlcipher_passphrase is not None and "\x00" in sqlcipher_passphrase:
        raise ConfigurationError("SQLCIPHER_PASSPHRASE cannot contain NUL bytes")

    secret_key = _read_secret("SECRET_KEY")
    if secret_key is not None and len(secret_key) < 32:
        raise ConfigurationError("SECRET_KEY must contain at least 32 characters")

    skip_bootstrap = _read_bool("SKIP_BOOTSTRAP", False)
    bootstrap_users = (
        None
        if skip_bootstrap
        else _read_secret("BOOTSTRAP_USERS", required=False, allow_missing_file=True)
    )

    return {
        "APP_VERSION": os.environ.get("APP_VERSION", "unversioned"),
        "BRANDING_PATH": str(
            Path(os.environ.get("BRANDING_PATH", "/app/branding")).resolve()
        ),
        "BOOTSTRAP_USERS": bootstrap_users,
        "CONTACT_URL": os.environ.get(
            "CONTACT_URL",
            DEFAULT_CONTACT_URL,
        ),
        "DATABASE_PATH": str(database_path),
        "DISPLAY_TIMEZONE": os.environ.get("TZ", "America/Chicago"),
        "MAX_CONTENT_LENGTH": 1024 * 1024,
        "PUBLIC_BASE_URL": os.environ.get("PUBLIC_BASE_URL", "").rstrip("/") or None,
        "SECRET_KEY": secret_key,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_NAME": "grayhaven_timetracker_session",
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_SECURE": _read_bool("SESSION_COOKIE_SECURE", False),
        "SKIP_BOOTSTRAP": skip_bootstrap,
        "SQLCIPHER_PASSPHRASE": sqlcipher_passphrase,
        "TRUSTED_PROXY_COUNT": _read_int("TRUSTED_PROXY_COUNT", 0),
        "TRUSTED_HOSTS": _read_trusted_hosts(),
        "WTF_CSRF_TIME_LIMIT": 3600,
    }


def validate_timezone(name: str) -> None:
    """Validate an IANA timezone name without retaining global state."""
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    try:
        ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        raise ConfigurationError(f"Unknown TZ value: {name}") from exc


def validate_branding(path: str) -> None:
    """Fail fast when required proprietary runtime assets are unavailable."""
    branding_path = Path(path)
    required_assets = (
        "grayhaven-logo-wordmark-dark.svg",
        "favicon.ico",
        "favicon-16.png",
        "favicon-32.png",
        "apple-touch-icon.png",
        "fonts/inter-400.ttf",
        "fonts/inter-500.ttf",
        "fonts/inter-600.ttf",
        "fonts/inter-700.ttf",
    )
    missing = [
        asset for asset in required_assets if not (branding_path / asset).is_file()
    ]
    if missing:
        raise ConfigurationError(
            "Required runtime branding assets are missing: " + ", ".join(missing)
        )


def validate_contact_url(value: str) -> None:
    """Require a complete HTTPS contact link for live reports."""
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise ConfigurationError("CONTACT_URL must be an absolute HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "\\" in value
        or _contains_control(value)
    ):
        raise ConfigurationError("CONTACT_URL must be an absolute HTTPS URL")


def validate_public_base_url(value: str | None) -> None:
    """Require a canonical HTTPS origin when an external base URL is set."""
    if value is None:
        return
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise ConfigurationError("PUBLIC_BASE_URL must be an HTTPS origin") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or _contains_control(value)
    ):
        raise ConfigurationError("PUBLIC_BASE_URL must be an HTTPS origin")


def validate_public_deployment(
    public_base_url: str | None,
    session_cookie_secure: bool,
    trusted_hosts: list[str] | None,
) -> None:
    """Fail closed when an external origin lacks matching browser protections."""
    if public_base_url is None:
        return
    if not session_cookie_secure:
        raise ConfigurationError(
            "SESSION_COOKIE_SECURE must be enabled when PUBLIC_BASE_URL is set"
        )
    hostname = urlsplit(public_base_url).hostname
    if hostname is None:
        raise ConfigurationError("PUBLIC_BASE_URL must be an HTTPS origin")
    matches_host = any(
        hostname == pattern
        or (
            pattern.startswith(".")
            and (hostname == pattern[1:] or hostname.endswith(pattern))
        )
        for pattern in trusted_hosts or []
    )
    if not matches_host:
        raise ConfigurationError(
            "PUBLIC_BASE_URL hostname must be included in TRUSTED_HOSTS"
        )
