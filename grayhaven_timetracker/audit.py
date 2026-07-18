"""Append-only application audit recording and structured log emission."""

from __future__ import annotations

import json
import logging
import unicodedata
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy.orm import Session

from .logging_config import redact_log_text
from .models import AuditEvent, User

logger = logging.getLogger("grayhaven_timetracker.audit")

SENSITIVE_KEY_FRAGMENTS = frozenset(
    {
        "authorization",
        "cookie",
        "credential",
        "hash",
        "passphrase",
        "password",
        "secret",
        "session",
        "token",
    }
)


def safe_audit_path(path: str | None) -> str | None:
    """Redact share credentials and bound a request path for storage."""
    if path is None:
        return None
    return safe_audit_text(redact_log_text(path), maximum=512)


def safe_audit_text(value: str, *, maximum: int) -> str:
    """Replace Unicode controls that could spoof logs or the admin display."""
    return "".join(
        "�" if unicodedata.category(character).startswith("C") else character
        for character in value[:maximum]
    )


def _safe_detail_value(value: Any, *, depth: int = 0) -> Any:
    """Return bounded JSON-safe audit detail data without credential material."""
    if depth >= 4:
        return safe_audit_text(str(value), maximum=512)
    if value is None or isinstance(value, (str, int, float, bool)):
        return safe_audit_text(value, maximum=512) if isinstance(value, str) else value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        details: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = safe_audit_text(str(key), maximum=100)
            if any(
                fragment in normalized_key.lower()
                for fragment in SENSITIVE_KEY_FRAGMENTS
            ):
                continue
            details[normalized_key] = _safe_detail_value(item, depth=depth + 1)
        return details
    if isinstance(value, (list, tuple)):
        return [_safe_detail_value(item, depth=depth + 1) for item in value[:100]]
    return safe_audit_text(str(value), maximum=512)


def safe_audit_details(fields: dict[str, Any]) -> dict[str, Any]:
    """Keep primitive, bounded metadata while dropping credential-like fields."""
    details: dict[str, Any] = {}
    for key, value in fields.items():
        normalized_key = safe_audit_text(str(key), maximum=100)
        lowered = normalized_key.lower()
        if any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS):
            continue
        details[normalized_key] = _safe_detail_value(value)
    return details


def record_audit_event(
    database: Session,
    event: str,
    *,
    source: str,
    actor: User | None = None,
    ip_address: str | None = None,
    method: str | None = None,
    path: str | None = None,
    status_code: int | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Stage one canonical audit event and emit its Loki-ready JSON record."""
    safe_details = safe_audit_details(details or {})
    occurred_at = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
    item = AuditEvent(
        occurred_at=occurred_at,
        event=safe_audit_text(event, maximum=100),
        source=source,
        actor_user_id=actor.id if actor else None,
        actor_email=safe_audit_text(actor.email, maximum=255) if actor else None,
        actor_name=safe_audit_text(actor.full_name, maximum=201) if actor else None,
        actor_role=("Administrator" if actor.is_admin else "User") if actor else None,
        ip_address=safe_audit_text(ip_address, maximum=64) if ip_address else None,
        method=safe_audit_text(method, maximum=8) if method else None,
        path=safe_audit_path(path),
        status_code=status_code,
        user_agent=(safe_audit_text(user_agent, maximum=512) if user_agent else None),
        details_json=json.dumps(
            safe_details, separators=(",", ":"), sort_keys=True, ensure_ascii=False
        ),
    )
    database.add(item)
    logger.info(
        event.replace("_", " "),
        extra={
            "event": event,
            "source": source,
            "actor_id": actor.id if actor else None,
            "actor_email": item.actor_email,
            "actor_role": item.actor_role,
            "ip": item.ip_address,
            "method": item.method,
            "path": item.path,
            "status": status_code,
            "details": safe_details,
        },
    )
    return item
