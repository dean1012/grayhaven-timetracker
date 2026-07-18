"""Authentication, password, TOTP, and login-abuse helpers."""

from __future__ import annotations

import base64
import io
import re
import secrets
import string
import threading
import time
import unicodedata
from collections import OrderedDict, deque
from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, TypeVar, cast
from urllib.parse import unquote, urlsplit

import pyotp
import qrcode
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import current_app, g, redirect, request, session, url_for
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .database import get_session
from .models import ApplicationMetadata, User

PASSWORD_MIN_LENGTH = 32
PASSWORD_MAX_LENGTH = 1024
TEMPORARY_PASSWORD_LENGTH = 40
TEMPORARY_PASSWORD_SPECIALS = "!#$%&*+-=?@^_"  # noqa: S105
TOTP_REPLAY_KEY_PREFIX = "totp_last_counter:"
SESSION_NOTICE_KEY_PREFIX = "session_invalidation_notice:"
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
dummy_password_hash = password_hasher.hash("Grayhaven-Dummy-Password-Hash-Only-000000!")

P = ParamSpec("P")
R = TypeVar("R")


def now_utc_timestamp() -> float:
    return time.time()


def normalize_email(value: str) -> str:
    email = value.strip().lower()
    if (
        len(email) > 255
        or any(unicodedata.category(character).startswith("C") for character in email)
        or not EMAIL_PATTERN.fullmatch(email)
    ):
        raise ValueError("Enter a valid email address.")
    return email


def required_text(value: str, label: str, *, maximum: int) -> str:
    normalized = " ".join(value.split())
    if not normalized:
        raise ValueError(f"{label} is required.")
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        raise ValueError(f"{label} contains unsupported control characters.")
    if len(normalized) > maximum:
        raise ValueError(f"{label} cannot exceed {maximum} characters.")
    return normalized


def password_error(password: str) -> str | None:
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"Password must contain at least {PASSWORD_MIN_LENGTH} characters."
    if len(password) > PASSWORD_MAX_LENGTH:
        return f"Password cannot exceed {PASSWORD_MAX_LENGTH} characters."
    if not any(character.isupper() for character in password):
        return "Password must contain an uppercase letter."
    if not any(character.islower() for character in password):
        return "Password must contain a lowercase letter."
    if not any(character.isdigit() for character in password):
        return "Password must contain a number."
    if not any(
        not character.isalnum() and not character.isspace() for character in password
    ):
        return "Password must contain a special character."
    return None


def hash_password(password: str) -> str:
    error = password_error(password)
    if error:
        raise ValueError(error)
    return password_hasher.hash(password)


def generate_temporary_password() -> str:
    """Generate a policy-compliant credential suitable for one-time delivery."""
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(TEMPORARY_PASSWORD_SPECIALS),
    ]
    alphabet = (
        string.ascii_uppercase
        + string.ascii_lowercase
        + string.digits
        + TEMPORARY_PASSWORD_SPECIALS
    )
    required.extend(
        secrets.choice(alphabet)
        for _ in range(TEMPORARY_PASSWORD_LENGTH - len(required))
    )
    secrets.SystemRandom().shuffle(required)
    return "".join(required)


def verify_password(password_hash: str, password: str) -> bool:
    if len(password) > PASSWORD_MAX_LENGTH:
        return False
    try:
        return password_hasher.verify(password_hash, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False


def verify_password_constant_time(user: User | None, password: str) -> bool:
    return verify_password(
        user.password_hash if user else dummy_password_hash, password
    )


def valid_totp_secret(secret: str) -> bool:
    try:
        decoded = base64.b32decode(secret.upper(), casefold=True)
    except (ValueError, TypeError):
        return False
    return len(decoded) >= 10


def matching_totp_counter(secret: str, token: str) -> int | None:
    """Return the accepted TOTP counter without persisting the secret or token."""
    normalized = token.replace(" ", "").strip()
    if not normalized.isdigit() or len(normalized) != 6:
        return None
    totp = pyotp.TOTP(secret)
    current_counter = int(now_utc_timestamp()) // totp.interval
    for counter in range(current_counter - 1, current_counter + 2):
        if secrets.compare_digest(totp.generate_otp(counter), normalized):
            return counter
    return None


def verify_totp(secret: str, token: str) -> bool:
    return matching_totp_counter(secret, token) is not None


def consume_totp(user: User, token: str, *, secret: str | None = None) -> bool:
    """Atomically accept a valid TOTP counter no more than once per account."""
    selected_secret = secret or user.totp_secret
    if not selected_secret:
        return False
    counter = matching_totp_counter(selected_secret, token)
    if counter is None:
        return False
    result = get_session().execute(
        text(
            "INSERT INTO application_metadata (key, value) VALUES (:key, :counter) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value "
            "WHERE CAST(application_metadata.value AS INTEGER) "
            "< CAST(excluded.value AS INTEGER) RETURNING value"
        ),
        {
            "key": f"{TOTP_REPLAY_KEY_PREFIX}{user.id}",
            "counter": str(counter),
        },
    )
    return result.scalar_one_or_none() is not None


def reset_totp_replay_state(database: Session, user_id: int) -> None:
    """Forget a prior factor's counters when that factor is removed or replaced."""
    database.execute(
        text("DELETE FROM application_metadata WHERE key = :key"),
        {"key": f"{TOTP_REPLAY_KEY_PREFIX}{user_id}"},
    )


def provisioning_uri(user: User, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(
        name=user.email, issuer_name="Grayhaven Systems LLC Time Tracker"
    )


def qr_data_uri(uri: str) -> str:
    image = qrcode.make(uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def current_user() -> User | None:
    return cast(User | None, getattr(g, "current_user", None))


def set_session_invalidation_notice(user: User, notice: str) -> None:
    """Persist a safe reason for invalidating a user's current session."""
    key = f"{SESSION_NOTICE_KEY_PREFIX}{user.id}:{user.session_version}"
    database = get_session()
    item = database.get(ApplicationMetadata, key)
    if item is None:
        database.add(ApplicationMetadata(key=key, value=notice))
    else:
        item.value = notice


def load_current_user() -> None:
    if request.endpoint in {"main.shared_report", "main.shared_report_live"}:
        g.current_user = None
        return
    user_id = session.get("user_id")
    if not isinstance(user_id, int):
        g.current_user = None
        return
    authenticated_at = session.get("authenticated_at")
    now = now_utc_timestamp()
    maximum_age = current_app.permanent_session_lifetime.total_seconds()
    user = get_session().get(User, user_id)
    invalidation_notice = None
    if user is not None and session.get("session_version") != user.session_version:
        notice = get_session().get(
            ApplicationMetadata,
            f"{SESSION_NOTICE_KEY_PREFIX}{user.id}:{user.session_version}",
        )
        invalidation_notice = notice.value if notice is not None else None
    privileges_updated = (
        user is not None
        and session.get("session_version") != user.session_version
        and session.get("user_role") != user.role
    )
    account_disabled = user is not None and not user.is_enabled
    if (
        user is None
        or not user.is_enabled
        or not isinstance(authenticated_at, (int, float))
        or authenticated_at > now + 60
        or now - authenticated_at > maximum_age
        or session.get("session_version") != user.session_version
    ):
        session.clear()
        if account_disabled:
            session["auth_notice"] = "account_disabled"
        elif invalidation_notice:
            session["auth_notice"] = invalidation_notice
        elif privileges_updated:
            session["auth_notice"] = "privileges_updated"
        g.current_user = None
        return
    g.current_user = user


def login_required(view: Callable[P, R]) -> Callable[P, R]:  # noqa: UP047
    @wraps(view)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        if current_user() is None:
            next_path = request.full_path.rstrip("?")
            return cast(R, redirect(url_for("main.login", next=next_path)))
        return view(*args, **kwargs)

    return wrapped


def safe_next_url(value: str | None) -> str | None:
    """Accept only local absolute paths for post-action redirects."""
    if not value:
        return None
    decoded = unquote(value)
    parsed = urlsplit(value)
    if (
        parsed.scheme
        or parsed.netloc
        or not value.startswith("/")
        or decoded.startswith("//")
        or "\\" in decoded
        or any(ord(character) < 32 for character in decoded)
    ):
        return None
    return value


class LoginLimiter:
    """Small single-process guard suitable for the one-worker deployment."""

    def __init__(
        self,
        limit: int = 10,
        window_seconds: int = 300,
        *,
        maximum_keys: int = 10_000,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.maximum_keys = maximum_keys
        self._attempts: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def _prune(self, current: float) -> None:
        cutoff = current - self.window_seconds
        for key in list(self._attempts):
            attempts = self._attempts[key]
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if not attempts:
                del self._attempts[key]
        while len(self._attempts) > self.maximum_keys:
            self._attempts.popitem(last=False)

    def blocked(self, key: str, now: float | None = None) -> bool:
        current = now if now is not None else now_utc_timestamp()
        with self._lock:
            self._prune(current)
            attempts = self._attempts.get(key)
            if attempts is None:
                return False
            self._attempts.move_to_end(key)
            return len(attempts) >= self.limit

    def record_failure(self, key: str, now: float | None = None) -> None:
        current = now if now is not None else now_utc_timestamp()
        with self._lock:
            self._prune(current)
            attempts = self._attempts.setdefault(key, deque())
            attempts.append(current)
            self._attempts.move_to_end(key)
            while len(self._attempts) > self.maximum_keys:
                self._attempts.popitem(last=False)

    def clear(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)


def find_user_by_email(email: str) -> User | None:
    return get_session().scalar(select(User).where(User.email == email))
