"""Structured logging suitable for container collection and Loki ingestion."""

from __future__ import annotations

import json
import logging
import re
import unicodedata
from datetime import UTC, datetime
from typing import Any

SHARED_REPORT_PATH = re.compile(r"/shared/reports/[A-Za-z0-9_-]{32,128}")


def redact_log_text(value: str) -> str:
    """Remove report tokens and Unicode controls from log text."""
    redacted = SHARED_REPORT_PATH.sub("/shared/reports/[redacted]", value)
    return "".join(
        "�" if unicodedata.category(character).startswith("C") else character
        for character in redacted
    )


def safe_log_value(value: Any) -> Any:
    """Recursively sanitize strings in structured logging fields."""
    if isinstance(value, str):
        return redact_log_text(value)
    if isinstance(value, dict):
        return {
            redact_log_text(str(key)): safe_log_value(item)
            for key, item in value.items()
        }
    return value


class JsonFormatter(logging.Formatter):
    """Serialize approved log context as one compact JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": redact_log_text(record.getMessage()),
        }
        for field in (
            "event",
            "source",
            "user_id",
            "actor_id",
            "actor_email",
            "actor_role",
            "client_id",
            "contract_id",
            "task_id",
            "subtask_id",
            "time_entry_id",
            "email",
            "ip",
            "reason",
            "method",
            "path",
            "status",
            "duration_us",
            "user_agent",
            "details",
        ):
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = safe_log_value(value)
        if record.exc_info:
            payload["exception"] = redact_log_text(
                self.formatException(record.exc_info)
            )
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def configure_logging() -> None:
    """Install the process-wide structured standard-error handler."""
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
