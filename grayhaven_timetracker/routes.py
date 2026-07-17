"""Server-rendered application routes."""

from __future__ import annotations

import logging
import hashlib
import re
import secrets
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from html import escape
from pathlib import Path
from threading import Lock, Timer
from typing import Any, cast
from urllib.parse import quote
from zoneinfo import ZoneInfo

import pyotp
from flask import (
    Blueprint,
    Flask,
    Response,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from .audit import record_audit_event
from .auth import (
    LoginLimiter,
    consume_totp,
    current_user,
    find_user_by_email,
    generate_temporary_password,
    hash_password,
    load_current_user,
    login_required,
    normalize_email,
    now_utc_timestamp,
    password_error,
    password_hasher,
    provisioning_uri,
    qr_data_uri,
    required_text,
    reset_totp_replay_state,
    safe_next_url,
    verify_password,
    verify_password_constant_time,
)
from .bootstrap import is_deployment_managed_user
from .database import get_session, health_check
from .models import (
    AuditEvent,
    Client,
    Contract,
    Subtask,
    Task,
    TimeEntry,
    User,
)
from .permissions import (
    AUDIT_VIEW,
    CLIENT_ADD,
    CLIENT_DELETE,
    CLIENT_EDIT,
    CLIENT_VIEW,
    CONTRACT_ADD,
    CONTRACT_DELETE,
    CONTRACT_EDIT,
    CONTRACT_VIEW,
    REPORT_SHARE,
    REPORT_VIEW,
    TASK_ADD,
    TASK_DELETE,
    TASK_EDIT,
    TIME_ENTRY_ADD_ANY,
    TIME_ENTRY_ADD_OWN,
    TIME_ENTRY_DELETE_ANY,
    TIME_ENTRY_EDIT_ANY,
    TIME_ENTRY_VIEW_ANY,
    TIME_ENTRY_VIEW_OWN,
    TIMER_START,
    TIMER_STOP,
    USER_ADD,
    USER_EDIT,
    USER_PASSWORD_RESET,
    USER_VIEW,
    can,
    permission_required,
)
from .reports import (
    ClientReport,
    ContractReport,
    build_client_report,
    duration_seconds,
    format_datetime,
    format_duration,
    format_money,
    report_state_etag,
)

main = Blueprint("main", __name__)
logger = logging.getLogger("grayhaven_timetracker.audit")
login_limiter = LoginLimiter()
login_ip_limiter = LoginLimiter(limit=50)
shared_report_limiter = LoginLimiter()
sensitive_action_limiter = LoginLimiter()
REPORT_PASSWORD_CONFIRMATION_TTL_SECONDS = 120
AUDIT_SOURCES = frozenset({"admin", "user", "public", "system"})
AUDIT_PAGE_SIZE = 50
HIDDEN_AUDIT_EVENTS = frozenset(
    {"audit_log_viewed", "bootstrap_user_reconciled", "http_request"}
)
PENDING_LOGIN_TTL_SECONDS = 300
PENDING_LOGIN_SESSION_KEYS = (
    "pending_login_expires_at",
    "pending_login_next",
    "pending_login_session_version",
    "pending_login_user_id",
)
SHARED_REPORT_COOKIE_PREFIX = "grayhaven_timetracker_report_"
SHARED_REPORT_COOKIE_PATH = "/shared/reports/"
SHARED_REPORT_COOKIE_SALT = "shared-report-session-v1"
REPORT_PASSWORD_CONFIRMATION_SESSION_KEYS = (
    "report_password_confirmation_client_id",
    "report_password_confirmation_token",
)


@dataclass(frozen=True)
class ReportPasswordConfirmation:
    """One short-lived report password awaiting its one permitted display."""

    actor_user_id: int
    client_id: int
    expires_at: float
    report_password: str


class ReportPasswordConfirmationStore:
    """Bounded, thread-safe, one-time storage for report password displays."""

    def __init__(
        self,
        ttl_seconds: int = REPORT_PASSWORD_CONFIRMATION_TTL_SECONDS,
        maximum_items: int = 1_000,
    ) -> None:
        if ttl_seconds <= 0 or maximum_items <= 0:
            raise ValueError("Confirmation store limits must be positive")
        self.ttl_seconds = ttl_seconds
        self.maximum_items = maximum_items
        self._items: OrderedDict[str, ReportPasswordConfirmation] = OrderedDict()
        self._lock = Lock()

    def _prune(self, current: float) -> None:
        for token, item in list(self._items.items()):
            if item.expires_at <= current:
                del self._items[token]
        while len(self._items) >= self.maximum_items:
            self._items.popitem(last=False)

    def _discard(self, token: str) -> None:
        """Remove an expired value even when no later request prunes the store."""
        with self._lock:
            self._items.pop(token, None)

    def issue(
        self,
        *,
        actor_user_id: int,
        client_id: int,
        report_password: str,
        now: float | None = None,
    ) -> str:
        """Store a password briefly and return an unrelated session nonce."""
        current = now if now is not None else now_utc_timestamp()
        with self._lock:
            self._prune(current)
            token = secrets.token_urlsafe(32)
            while token in self._items:
                token = secrets.token_urlsafe(32)
            self._items[token] = ReportPasswordConfirmation(
                actor_user_id=actor_user_id,
                client_id=client_id,
                expires_at=current + self.ttl_seconds,
                report_password=report_password,
            )
            expiration_timer = Timer(self.ttl_seconds, self._discard, args=(token,))
            expiration_timer.daemon = True
            expiration_timer.start()
            return token

    def consume(
        self,
        token: str,
        *,
        actor_user_id: int,
        client_id: int,
        now: float | None = None,
    ) -> ReportPasswordConfirmation | None:
        """Return and permanently remove one valid matching confirmation."""
        current = now if now is not None else now_utc_timestamp()
        with self._lock:
            self._prune(current)
            item = self._items.pop(token, None)
        if (
            item is None
            or item.actor_user_id != actor_user_id
            or item.client_id != client_id
        ):
            return None
        return item


report_password_confirmation_store = ReportPasswordConfirmationStore()


def now_utc() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def audit(event: str, **fields: Any) -> None:
    """Persist and emit a safe semantic event without disrupting its action."""
    if fields.get("changes") == {}:
        return
    database = get_session()
    actor = current_user()
    actor_id = fields.pop("actor_id", None)
    source_ip = fields.pop("source_ip", None)
    fields.pop("ip", None)
    if actor is None:
        candidate_id = actor_id if isinstance(actor_id, int) else fields.get("user_id")
        if isinstance(candidate_id, int):
            actor = database.get(User, candidate_id)
    label_fields = {
        "client_id": ("client", Client, "name"),
        "contract_id": ("contract", Contract, "name"),
        "previous_contract_id": ("previous_contract", Contract, "name"),
        "task_id": ("task", Task, "name"),
        "subtask_id": ("subtask", Subtask, "name"),
        "user_id": ("user", User, "full_name"),
        "time_entry_id": ("time_entry", TimeEntry, None),
    }
    for field, (label, model, attribute) in label_fields.items():
        identifier = fields.pop(field, None)
        if not isinstance(identifier, int):
            continue
        item = database.get(model, identifier)
        if item is None:
            fields[label] = f"Deleted record (ID: {identifier})"
        elif attribute is None:
            fields[label] = f"Time entry (ID: {identifier})"
        else:
            fields[label] = audit_object_label(getattr(item, attribute), identifier)
    fields.setdefault(
        "request_source",
        "Public Shared Report" if event.startswith("shared_report_") else "Web Application",
    )
    try:
        record_audit_event(
            database,
            event,
            source=actor.role if actor else "public",
            actor=actor,
            ip_address=source_ip,
            details=fields,
        )
        database.commit()
    except Exception:
        database.rollback()
        logger.exception(
            "audit persistence failed",
            extra={"event": "audit_persistence_failed"},
        )


def shared_report_cookie_name(client: Client) -> str:
    """Return the independent cookie name for one client's report session."""
    return f"{SHARED_REPORT_COOKIE_PREFIX}{client.id}"


def shared_report_serializer() -> URLSafeTimedSerializer:
    """Build the isolated signer for report authorization cookies."""
    return URLSafeTimedSerializer(
        current_app.secret_key,
        salt=SHARED_REPORT_COOKIE_SALT,
    )


def set_shared_report_cookie(response: Response, client: Client) -> Response:
    """Attach a signed report-only authorization cookie to a response."""
    value = shared_report_serializer().dumps(
        {
            "client_id": client.id,
            "password_version": client.report_password_version,
        }
    )
    response.set_cookie(
        shared_report_cookie_name(client),
        value,
        max_age=int(current_app.permanent_session_lifetime.total_seconds()),
        secure=bool(current_app.config["SESSION_COOKIE_SECURE"]),
        httponly=True,
        samesite="Lax",
        path=SHARED_REPORT_COOKIE_PATH,
    )
    return response


def shared_report_cookie_allowed(client: Client) -> bool:
    """Validate the independent signed cookie for one client report."""
    value = request.cookies.get(shared_report_cookie_name(client))
    if not value:
        return False
    try:
        payload = shared_report_serializer().loads(
            value,
            max_age=int(current_app.permanent_session_lifetime.total_seconds()),
        )
    except (BadSignature, SignatureExpired):
        return False
    return bool(
        isinstance(payload, dict)
        and payload.get("client_id") == client.id
        and payload.get("password_version") == client.report_password_version
    )


def shared_report_access_allowed(client: Client) -> bool:
    """Validate the isolated signed cookie for one client report."""
    return shared_report_cookie_allowed(client)


def get_shared_report_client(token: str) -> Client:
    """Resolve a permanent client report link without disclosing lookup details."""
    if (
        not 32 <= len(token) <= 128
        or not token.isascii()
        or any(not (character.isalnum() or character in "-_") for character in token)
    ):
        abort(404)
    client = get_session().scalar(
        select(Client)
        .where(Client.report_token == token)
        .options(selectinload(Client.contracts))
    )
    if client is None:
        abort(404)
    return client


def sensitive_action_credentials_valid(user: User) -> bool:
    """Reauthenticate an administrator before a credential rotation."""
    password_valid = verify_password(
        user.password_hash, request.form.get("current_password", "")
    )
    if not password_valid:
        return False
    return not user.totp_secret or consume_totp(user, request.form.get("totp", ""))


def sensitive_action_rate_key(user: User) -> str:
    """Scope administrator reauthentication limits to actor and source IP."""
    return f"{user.id}|{request.remote_addr or 'unknown'}"


def audit_object_label(name: str, identifier: int) -> str:
    """Render one deleted or affected object without requiring a follow-up lookup."""
    return f"{name} (ID: {identifier})"


def audit_changes(**values: tuple[Any, Any]) -> dict[str, dict[str, Any]]:
    """Return only meaningful non-sensitive before-and-after audit changes."""
    return {
        field.replace("_", " ").title(): {"from": previous, "to": current}
        for field, (previous, current) in values.items()
        if previous != current
    }


def audit_rate(hourly_rate_cents: int) -> str:
    """Format a contract rate for a human-readable audit event."""
    return f"{format_money(Decimal(hourly_rate_cents) / Decimal(100))} per hour"


def audit_time(value: datetime) -> str:
    """Render a stored timestamp in the configured audit timezone."""
    return format_datetime(
        value, ZoneInfo(cast(str, current_app.config["DISPLAY_TIMEZONE"]))
    )


def audit_time_entry_details(entry: TimeEntry) -> dict[str, str]:
    """Describe a session with its complete current assignment."""
    contract = entry.task.contract
    return {
        "client": audit_object_label(contract.client.name, contract.client_id),
        "contract": audit_object_label(contract.name, contract.id),
        "task": audit_object_label(entry.task.name, entry.task_id),
        "subtask": (
            audit_object_label(entry.subtask.name, entry.subtask_id)
            if entry.subtask is not None and entry.subtask_id is not None
            else "None"
        ),
        "user": audit_object_label(entry.user.full_name, entry.user_id),
        "time entry": f"Time entry (ID: {entry.id})",
    }


def sensitive_action_failure(
    actor: User,
    confirmation: dict[str, Any],
    event: str,
    **details: Any,
) -> Any | None:
    """Return a reauthentication failure response or clear a valid challenge."""
    rate_key = sensitive_action_rate_key(actor)
    if sensitive_action_limiter.blocked(rate_key):
        audit(f"{event}_rate_limited", actor_id=actor.id, **details)
        abort(429)
    if sensitive_action_credentials_valid(actor):
        sensitive_action_limiter.clear(rate_key)
        return None
    sensitive_action_limiter.record_failure(rate_key)
    audit(f"{event}_rejected", actor_id=actor.id, **details)
    flash("The administrator credentials were not accepted.", "error")
    return render_template("sensitive_action_form.html", **confirmation), 400


def purge_subtask_data(subtask_id: int) -> int:
    """Delete one subtask and its time records, never its audit history."""
    database = get_session()
    deleted_time = database.execute(
        delete(TimeEntry).where(TimeEntry.subtask_id == subtask_id)
    ).rowcount
    database.execute(delete(Subtask).where(Subtask.id == subtask_id))
    return deleted_time or 0


def purge_task_data(task_ids: Any) -> int:
    """Delete tasks, their subtasks, and their time records without audit loss."""
    database = get_session()
    deleted_time = database.execute(
        delete(TimeEntry).where(TimeEntry.task_id.in_(task_ids))
    ).rowcount
    database.execute(delete(Subtask).where(Subtask.task_id.in_(task_ids)))
    database.execute(delete(Task).where(Task.id.in_(task_ids)))
    return deleted_time or 0


def purge_contract_data(contract_ids: Any) -> int:
    """Delete contracts and dependent work data without deleting audit events."""
    database = get_session()
    task_ids = select(Task.id).where(Task.contract_id.in_(contract_ids))
    deleted_time = purge_task_data(task_ids)
    database.execute(delete(Contract).where(Contract.id.in_(contract_ids)))
    return deleted_time


def shared_report_url(token: str) -> str:
    """Build a share URL from the configured origin or a trusted request Host."""
    path = url_for("main.shared_report", token=token)
    public_base_url = current_app.config.get("PUBLIC_BASE_URL")
    if public_base_url:
        return f"{public_base_url}{path}"
    return url_for("main.shared_report", token=token, _external=True)


def ensure_client_report_token(client: Client) -> str:
    """Return the permanent client report token created with the client record."""
    return client.report_token


def report_mailto(client: Client, report_url: str) -> str:
    """Build the Proton-compatible HTML email without placing the password in it."""
    subject = f"Live time and cost report access for {client.name}"
    contact_name = escape(client.contact_name)
    escaped_report_url = escape(report_url, quote=True)
    body_lines = [
        f"{contact_name},",
        "",
        "Grayhaven Systems LLC is inviting you to view live time and cost tracking "
        "data for your contracts with us.",
        "",
        "Viewing your live report will require a password that will be securely "
        "shared with you separately from this message. You do not need to sign up "
        "for an account to view your report.",
        "",
        "\u200b<b>Your personalized live report is available here:</b>",
        f'<a href="{escaped_report_url}">{escaped_report_url}</a>',
        "",
        "<b>Please keep both your link and password confidential to protect your "
        "data.</b>",
        "",
        "If you have any questions, concerns, or problems, please let me know and I "
        "will be happy to assist you.",
        "",
        "",
    ]
    return (
        f"mailto:{quote(client.contact_email, safe='@')}?subject={quote(subject)}"
        f"&body={quote(chr(10).join(body_lines))}"
    )


def report_password_mailto(client: Client, report_password: str) -> str:
    """Build the Proton-compatible report-password reset email."""
    subject = (
        f"Your live time and cost report password for {client.name} has been reset"
    )
    contact_name = escape(client.contact_name)
    escaped_password = escape(report_password)
    body_lines = [
        f"{contact_name},",
        "",
        "Your personalized live time and cost tracking report password for "
        "Grayhaven Systems LLC has been reset. All previously open live report "
        "sessions will need to be reauthenticated.",
        "",
        f"<b>Your new password is:</b> {escaped_password}",
        "",
        "<b>Please save this password, as this email will expire in 48 hours.</b>",
        "",
        "<b>Please keep both your link and password confidential to protect your "
        "data.</b>",
        "",
        "If you have any questions, concerns, or problems, please let me know and I "
        "will be happy to assist you.",
        "",
        "",
    ]
    return (
        f"mailto:{quote(client.contact_email, safe='@')}?subject={quote(subject)}"
        f"&body={quote(chr(10).join(body_lines))}"
    )


def form_text(name: str, label: str, maximum: int) -> str:
    return required_text(request.form.get(name, ""), label, maximum=maximum)


def get_or_404(model: type[Any], identifier: int) -> Any:
    item = get_session().get(model, identifier)
    if item is None:
        abort(404)
    return item


def deleted_resource_parent_id(
    events: tuple[str, ...], child_key: str, child_id: int, parent_key: str
) -> int | None:
    """Recover a deleted resource's still-readable parent from immutable audit data."""
    statement = (
        select(AuditEvent)
        .where(AuditEvent.event.in_(events))
        .order_by(AuditEvent.id.desc())
    )
    for event in get_session().scalars(statement):
        details = event.details
        child_label = details.get(child_key)
        parent_label = details.get(parent_key)
        if not isinstance(child_label, str) or not isinstance(parent_label, str):
            continue
        if f"(ID: {child_id})" not in child_label:
            continue
        match = re.search(r"\(ID:\s*(\d+)\)", parent_label)
        if match:
            return int(match.group(1))
    return None


def created_resource_parent_id(
    child_key: str, child_id: int, parent_key: str
) -> int | None:
    """Recover a session's original parent from its creation audit event."""
    statement = (
        select(AuditEvent)
        .where(AuditEvent.event == "time_entry_created")
        .order_by(AuditEvent.id)
    )
    for event in get_session().scalars(statement):
        details = event.details
        child_label = details.get(child_key)
        parent_label = details.get(parent_key)
        if not isinstance(child_label, str) or not isinstance(parent_label, str):
            continue
        if f"(ID: {child_id})" not in child_label:
            continue
        match = re.search(r"\(ID:\s*(\d+)\)", parent_label)
        if match:
            return int(match.group(1))
    return None


def stale_resource_redirect(endpoint: str, notice: str, **values: Any) -> Any:
    """Redirect with a short-lived destination notice for a stale page."""
    return redirect(url_for(endpoint, **values, stale=notice))


def time_entry_allowed(
    entry: TimeEntry, own_permission: str, any_permission: str
) -> bool:
    """Authorize a time entry using the future-facing own/any permission split."""
    user = cast(User, current_user())
    return can(any_permission) or (entry.user_id == user.id and can(own_permission))


def time_entry_overlaps(
    user_id: int,
    started_at: datetime,
    stopped_at: datetime,
    *,
    exclude_entry_id: int | None = None,
) -> bool:
    """Return whether a completed interval conflicts with the user's time."""
    statement = select(func.count(TimeEntry.id)).where(
        TimeEntry.user_id == user_id,
        TimeEntry.started_at < stopped_at,
        or_(TimeEntry.stopped_at.is_(None), TimeEntry.stopped_at > started_at),
    )
    if exclude_entry_id is not None:
        statement = statement.where(TimeEntry.id != exclude_entry_id)
    return bool(get_session().scalar(statement))


def active_time_entry_for_current_user() -> TimeEntry | None:
    """Return the signed-in user's active timer with navigation relationships."""
    user = current_user()
    if user is None:
        return None
    return get_session().scalar(
        select(TimeEntry)
        .where(TimeEntry.user_id == user.id, TimeEntry.stopped_at.is_(None))
        .options(
            selectinload(TimeEntry.task)
            .selectinload(Task.contract)
            .selectinload(Contract.client),
            selectinload(TimeEntry.subtask),
        )
    )


def parse_assignment(value: str, contract_id: int) -> tuple[Task, Subtask | None]:
    """Resolve one task or subtask assignment constrained to a contract."""
    parts = value.split(":")
    if len(parts) not in {1, 2} or not all(part.isdigit() for part in parts):
        raise ValueError("Select a valid task or subtask.")
    task = get_session().get(Task, int(parts[0]))
    if task is None or task.contract_id != contract_id:
        raise ValueError("Select a valid task or subtask.")
    subtask: Subtask | None = None
    if len(parts) == 2:
        subtask = get_session().get(Subtask, int(parts[1]))
        if subtask is None or subtask.task_id != task.id:
            raise ValueError("Select a valid task or subtask.")
    return task, subtask


def local_datetime_to_utc(
    value: str,
    label: str,
    timezone_name: str,
    *,
    original_utc: datetime | None = None,
) -> datetime:
    """Parse a browser local datetime and reject DST gaps or ambiguities."""
    parsed: datetime | None = None
    for date_format in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            parsed = datetime.strptime(value, date_format)
            break
        except ValueError:
            continue
    if parsed is None:
        raise ValueError(f"{label} must include a valid date and time.")
    zone = ZoneInfo(timezone_name)
    candidates: list[datetime] = []
    for fold in (0, 1):
        local = parsed.replace(tzinfo=zone, fold=fold)
        utc_value = local.astimezone(UTC)
        round_trip = utc_value.astimezone(zone).replace(tzinfo=None)
        if round_trip == parsed and utc_value not in candidates:
            candidates.append(utc_value)
    if not candidates:
        raise ValueError(f"{label} does not exist because of daylight saving time.")
    if len(candidates) > 1:
        if original_utc is not None:
            original = original_utc.replace(tzinfo=UTC)
            if original in candidates:
                return original_utc.replace(microsecond=0)
        raise ValueError(
            f"{label} is ambiguous because of daylight saving time; "
            "choose a time outside the repeated hour."
        )
    return candidates[0].replace(tzinfo=None, microsecond=0)


def datetime_local_value(value: datetime, timezone_name: str) -> str:
    """Format a stored UTC timestamp for a datetime-local input."""
    return (
        value.replace(tzinfo=UTC)
        .astimezone(ZoneInfo(timezone_name))
        .strftime("%Y-%m-%dT%H:%M:%S")
    )


def register_routes(app: Flask) -> None:
    app.before_request(load_current_user)
    app.register_blueprint(main)

    @app.errorhandler(404)
    def redirect_missing_resource(error: Any) -> Any:
        """Send stale authenticated resource pages to their nearest live parent."""
        path = request.path
        if path.startswith("/api/") or request.method not in {"GET", "HEAD", "POST"}:
            return error

        client_match = re.fullmatch(
            r"/(?:clients|reports)/(\d+)(?:/.*)?", path
        )
        if client_match:
            return stale_resource_redirect("main.dashboard", "client_deleted")

        contract_match = re.fullmatch(r"/contracts/(\d+)(?:/.*)?", path)
        if contract_match:
            contract_id = int(contract_match.group(1))
            client_id = deleted_resource_parent_id(
                ("contract_deleted",), "contract", contract_id, "client"
            )
            if client_id is not None and get_session().get(Client, client_id):
                return stale_resource_redirect(
                    "main.client", "contract_deleted", client_id=client_id
                )
            return stale_resource_redirect("main.dashboard", "contract_deleted")

        task_match = re.fullmatch(r"/tasks/(\d+)(?:/.*)?", path)
        if task_match:
            task_id = int(task_match.group(1))
            contract_id = deleted_resource_parent_id(
                ("task_deleted",), "task", task_id, "contract"
            )
            if contract_id is not None and get_session().get(Contract, contract_id):
                return stale_resource_redirect(
                    "main.contract", "task_deleted", contract_id=contract_id
                )
            return stale_resource_redirect("main.dashboard", "task_deleted")

        subtask_match = re.fullmatch(r"/subtasks/(\d+)(?:/.*)?", path)
        if subtask_match:
            subtask_id = int(subtask_match.group(1))
            contract_id = deleted_resource_parent_id(
                ("subtask_deleted",), "subtask", subtask_id, "contract"
            )
            if contract_id is not None and get_session().get(Contract, contract_id):
                return stale_resource_redirect(
                    "main.contract", "subtask_deleted", contract_id=contract_id
                )
            return stale_resource_redirect("main.dashboard", "subtask_deleted")

        session_match = re.fullmatch(r"/sessions/(\d+)(?:/.*)?", path)
        if session_match:
            entry_id = int(session_match.group(1))
            contract_id = created_resource_parent_id(
                "time entry", entry_id, "contract"
            )
            if contract_id is not None and get_session().get(Contract, contract_id):
                return stale_resource_redirect(
                    "main.contract_sessions", "time_entry_deleted", contract_id=contract_id
                )
            return stale_resource_redirect("main.dashboard", "time_entry_deleted")

        return (
            render_template(
                "error.html", status=404, message="The requested page was not found."
            ),
            404,
        )

    def live_page_etag() -> str:
        """Fingerprint application state without volatile rendered markup."""
        revision = get_session().scalar(select(func.max(AuditEvent.id))) or 0
        actor = current_user()
        state = f"{actor.id if actor else 'public'}|{request.full_path}|{revision}"
        return hashlib.sha256(state.encode()).hexdigest()

    @app.before_request
    def enforce_required_password_change() -> Any:
        user = current_user()
        allowed_endpoints = {
            "main.branding_asset",
            "main.change_password",
            "main.logout",
            "main.required_password_change",
            "static",
        }
        if (
            user is not None
            and user.password_change_required
            and request.endpoint not in allowed_endpoints
        ):
            return redirect(url_for("main.required_password_change"))
        return None

    @app.after_request
    def conditional_live_page_response(response: Response) -> Response:
        """Return an inexpensive 304 response for unchanged live page fragments."""
        if (
            request.headers.get("X-Grayhaven-Live-Refresh") != "1"
            or request.method != "GET"
            or response.status_code != 200
            or response.mimetype != "text/html"
        ):
            return response
        etag = live_page_etag()
        response.set_etag(etag)
        if request.if_none_match.contains(etag):
            response.status_code = 304
            response.set_data(b"")
        return response

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        active_entry = active_time_entry_for_current_user()
        return {
            "app_version": app.config["APP_VERSION"],
            "can": can,
            "contact_url": app.config["CONTACT_URL"],
            "format_datetime": format_datetime,
            "format_duration": format_duration,
            "format_money": format_money,
            "logged_user": current_user(),
            "active_entry": active_entry,
            "active_elapsed_seconds": (
                duration_seconds(active_entry.started_at, now_utc())
                if active_entry
                else 0
            ),
            "live_page_etag": live_page_etag(),
        }


# ---------------------------------------------------------------------------
# Service and authentication routes
# ---------------------------------------------------------------------------


@main.get("/branding/<path:filename>")
def branding_asset(filename: str) -> Any:
    branding_path = Path(cast(str, current_app.config["BRANDING_PATH"])).resolve()
    requested = (branding_path / filename).resolve()
    if branding_path not in requested.parents or not requested.is_file():
        abort(404)
    return send_from_directory(branding_path, filename, max_age=86400)


@main.get("/health")
def health() -> tuple[dict[str, str], int] | dict[str, str]:
    try:
        health_check(current_app)
    except Exception:
        current_app.logger.exception("health check failed")
        return {"status": "error"}, 503
    return {"status": "ok"}


def clear_pending_login() -> None:
    """Remove an incomplete two-stage login without disturbing flash state."""
    for key in PENDING_LOGIN_SESSION_KEYS:
        session.pop(key, None)


def pending_login_user() -> User | None:
    """Return the account bound to a valid, short-lived TOTP challenge."""
    user_id = session.get("pending_login_user_id")
    session_version = session.get("pending_login_session_version")
    expires_at = session.get("pending_login_expires_at")
    if (
        not isinstance(user_id, int)
        or not isinstance(session_version, int)
        or not isinstance(expires_at, (int, float))
        or expires_at <= now_utc_timestamp()
    ):
        clear_pending_login()
        return None
    user = get_session().get(User, user_id)
    if (
        user is None
        or not user.is_enabled
        or not user.totp_secret
        or user.session_version != session_version
    ):
        clear_pending_login()
        return None
    return user


def complete_login(user: User, ip: str, next_url: str | None) -> Any:
    """Promote a fully authenticated account into the application session."""
    login_limiter.clear(f"{ip}|{user.email}")
    session.clear()
    session.permanent = True
    session["authenticated_at"] = now_utc_timestamp()
    session["user_id"] = user.id
    session["session_version"] = user.session_version
    audit("login_succeeded", user_id=user.id, source_ip=ip)
    if user.password_change_required:
        return redirect(url_for("main.required_password_change"))
    return redirect(next_url or url_for("main.dashboard"))


@main.route("/login", methods=["GET", "POST"])
def login() -> Any:
    if current_user() is not None:
        return redirect(url_for("main.dashboard"))
    if request.method != "POST":
        clear_pending_login()
        return render_template("login.html")

    raw_email = request.form.get("email", "")
    try:
        email = normalize_email(raw_email)
    except ValueError:
        email = raw_email.strip().lower()[:255]
    ip = request.remote_addr or "unknown"
    rate_key = f"{ip}|{email}"
    if login_limiter.blocked(rate_key) or login_ip_limiter.blocked(ip):
        audit("login_rate_limited", email=email, source_ip=ip)
        abort(429)

    user = find_user_by_email(email)
    password_valid = verify_password_constant_time(
        user, request.form.get("password", "")
    )
    if user is None or not user.is_enabled or not password_valid:
        login_limiter.record_failure(rate_key)
        login_ip_limiter.record_failure(ip)
        reason = (
            "disabled" if user is not None and not user.is_enabled else "credentials"
        )
        audit("login_rejected", email=email, source_ip=ip, reason=reason)
        flash("The sign-in information was not accepted.", "error")
        return render_template("login.html"), 401

    if password_hasher.check_needs_rehash(user.password_hash):
        user.password_hash = password_hasher.hash(request.form.get("password", ""))
        get_session().commit()
    next_url = safe_next_url(request.args.get("next"))
    if not user.totp_secret:
        return complete_login(user, ip, next_url)

    session.clear()
    session.permanent = False
    session["pending_login_user_id"] = user.id
    session["pending_login_session_version"] = user.session_version
    session["pending_login_expires_at"] = (
        now_utc_timestamp() + PENDING_LOGIN_TTL_SECONDS
    )
    if next_url:
        session["pending_login_next"] = next_url
    audit("login_password_accepted", user_id=user.id, source_ip=ip)
    return redirect(url_for("main.login_authenticator"))


@main.route("/login/authenticator", methods=["GET", "POST"])
def login_authenticator() -> Any:
    if current_user() is not None:
        return redirect(url_for("main.dashboard"))
    had_pending_login = any(key in session for key in PENDING_LOGIN_SESSION_KEYS)
    user = pending_login_user()
    if user is None:
        if had_pending_login:
            audit(
                "login_challenge_rejected",
                reason="expired_or_invalidated",
                source_ip=request.remote_addr,
            )
        flash("Your sign-in session expired. Please sign in again.", "error")
        return redirect(url_for("main.login"))
    if request.method != "POST":
        return render_template("login_authenticator.html")

    ip = request.remote_addr or "unknown"
    rate_key = f"{ip}|{user.email}"
    if login_limiter.blocked(rate_key) or login_ip_limiter.blocked(ip):
        audit(
            "login_rate_limited",
            email=user.email,
            source_ip=ip,
            stage="authenticator",
        )
        abort(429)
    digits = request.form.getlist("totp_digit")
    token = "".join(digit.strip() for digit in digits)
    if not consume_totp(user, token):
        login_limiter.record_failure(rate_key)
        login_ip_limiter.record_failure(ip)
        audit("login_rejected", email=user.email, source_ip=ip, reason="totp")
        flash("The authenticator code was not accepted.", "error")
        return render_template("login_authenticator.html"), 401

    get_session().commit()
    pending_next = session.get("pending_login_next")
    next_url = safe_next_url(pending_next if isinstance(pending_next, str) else None)
    return complete_login(user, ip, next_url)


@main.post("/logout")
@login_required
def logout() -> Any:
    user = current_user()
    audit("logout", user_id=user.id if user else None)
    session.clear()
    return redirect(url_for("main.login"))


# ---------------------------------------------------------------------------
# Client, contract, and task routes
# ---------------------------------------------------------------------------


@main.get("/")
@permission_required(CLIENT_VIEW)
def dashboard() -> str:
    clients = (
        get_session()
        .scalars(
            select(Client).options(selectinload(Client.contracts)).order_by(Client.name)
        )
        .all()
    )
    return render_template("dashboard.html", clients=clients)


@main.get("/clients/<int:client_id>")
@permission_required(CLIENT_VIEW)
def client(client_id: int) -> str:
    item = get_session().scalar(
        select(Client)
        .where(Client.id == client_id)
        .options(selectinload(Client.contracts))
    )
    if item is None:
        abort(404)
    report_token = ensure_client_report_token(item)
    return render_template(
        "client.html",
        client=item,
        report_url=shared_report_url(report_token),
        report_mailto=report_mailto(item, shared_report_url(report_token)),
    )


@main.route("/clients/new", methods=["GET", "POST"])
@permission_required(CLIENT_ADD)
def new_client() -> Any:
    if request.method != "POST":
        return render_template("client_form.html")
    try:
        name = form_text("name", "Client Name", 200)
        if get_session().scalar(
            select(Client.id).where(func.lower(Client.name) == name.lower())
        ):
            raise ValueError("A client with that name already exists.")
        item = Client(
            name=name,
            contact_name=form_text("contact_name", "Contact Name", 200),
            contact_email=normalize_email(request.form.get("contact_email", "")),
            report_token=secrets.token_urlsafe(32),
            report_password_version=1,
        )
    except ValueError as exc:
        flash(str(exc), "error")
        return render_template("client_form.html"), 400
    get_session().add(item)
    try:
        get_session().commit()
    except IntegrityError:
        get_session().rollback()
        flash("A client with that name already exists.", "error")
        return render_template("client_form.html"), 409
    audit(
        "client_created",
        actor_id=cast(User, current_user()).id,
        client_id=item.id,
        initial_values={
            "Client Name": item.name,
            "Contact Name": item.contact_name,
            "Contact Email": item.contact_email,
            "Live Report Access": "Link provisioned; password not generated",
        },
    )
    flash("The client was created successfully.", "success")
    return redirect(url_for("main.client", client_id=item.id))


@main.route("/clients/<int:client_id>/edit", methods=["GET", "POST"])
@permission_required(CLIENT_EDIT)
def edit_client(client_id: int) -> Any:
    item = cast(Client, get_or_404(Client, client_id))
    if request.method != "POST":
        return render_template("client_form.html", client=item)
    previous_values = {
        "client_name": item.name,
        "contact_name": item.contact_name,
        "contact_email": item.contact_email,
    }
    try:
        name = form_text("name", "Client Name", 200)
        if get_session().scalar(
            select(Client.id).where(
                Client.id != item.id,
                func.lower(Client.name) == name.lower(),
            )
        ):
            raise ValueError("A client with that name already exists.")
        item.name = name
        item.contact_name = form_text("contact_name", "Contact Name", 200)
        item.contact_email = normalize_email(request.form.get("contact_email", ""))
    except ValueError as exc:
        flash(str(exc), "error")
        return render_template("client_form.html", client=item), 400
    try:
        get_session().commit()
    except IntegrityError:
        get_session().rollback()
        flash("A client with that name already exists.", "error")
        return render_template("client_form.html", client=item), 409
    audit(
        "client_updated",
        actor_id=cast(User, current_user()).id,
        client_id=item.id,
        changes=audit_changes(
            client_name=(previous_values["client_name"], item.name),
            contact_name=(previous_values["contact_name"], item.contact_name),
            contact_email=(previous_values["contact_email"], item.contact_email),
        ),
    )
    flash("Client details updated.", "success")
    return redirect(url_for("main.client", client_id=item.id))


@main.route("/clients/<int:client_id>/delete", methods=["GET", "POST"])
@permission_required(CLIENT_DELETE)
def delete_client(client_id: int) -> Any:
    """Delete a client and dependent work data after administrator reauthentication."""
    database = get_session()
    item = cast(Client, get_or_404(Client, client_id))
    actor = cast(User, current_user())
    confirmation = {
        "eyebrow": "DELETE CLIENT",
        "title": item.name,
        "description": (
            "Delete this client, all contracts, tasks, subtasks, and recorded "
            "time. Audit history is retained. This cannot be undone."
        ),
        "submit_label": "Delete Client",
        "cancel_url": url_for("main.client", client_id=item.id),
        "breadcrumb_parent_label": item.name,
        "breadcrumb_parent_url": url_for("main.client", client_id=item.id),
        "breadcrumb_label": "Delete Client",
        "totp_required": bool(actor.totp_secret),
    }
    if request.method != "POST":
        return render_template("sensitive_action_form.html", **confirmation)
    client_label = audit_object_label(item.name, item.id)
    failure = sensitive_action_failure(
        actor, confirmation, "client_delete", client=client_label
    )
    if failure is not None:
        return failure
    deleted_time = purge_contract_data(
        select(Contract.id).where(Contract.client_id == item.id)
    )
    database.execute(delete(Client).where(Client.id == item.id))
    database.commit()
    audit(
        "client_deleted",
        actor_id=actor.id,
        client=client_label,
        deleted_time_entries=deleted_time,
    )
    flash("Client and associated work data deleted.", "success")
    return redirect(url_for("main.dashboard"))


@main.route("/clients/<int:client_id>/report-password/reset", methods=["GET", "POST"])
@permission_required(REPORT_SHARE)
def reset_client_report_password(client_id: int) -> Any:
    item = cast(Client, get_or_404(Client, client_id))
    actor = cast(User, current_user())
    confirmation = {
        "eyebrow": "GENERATE REPORT PASSWORD",
        "title": item.name,
        "description": (
            "Generate a new client report password and immediately invalidate "
            "existing report sessions across this client's contracts."
        ),
        "submit_label": "Generate Password",
        "cancel_url": url_for("main.client", client_id=item.id),
        "breadcrumb_parent_label": item.name,
        "breadcrumb_parent_url": url_for("main.client", client_id=item.id),
        "breadcrumb_label": "Generate Report Password",
        "totp_required": bool(actor.totp_secret),
    }
    if request.method != "POST":
        return render_template("sensitive_action_form.html", **confirmation)
    rate_key = sensitive_action_rate_key(actor)
    if sensitive_action_limiter.blocked(rate_key):
        audit(
            "client_report_password_reset_rate_limited",
            actor_id=actor.id,
            client_id=item.id,
            source_ip=request.remote_addr,
        )
        abort(429)
    if not sensitive_action_credentials_valid(actor):
        sensitive_action_limiter.record_failure(rate_key)
        audit(
            "client_report_password_reset_rejected",
            actor_id=actor.id,
            client_id=item.id,
            source_ip=request.remote_addr,
        )
        flash("The administrator credentials were not accepted.", "error")
        return render_template("sensitive_action_form.html", **confirmation), 400
    sensitive_action_limiter.clear(rate_key)
    report_password = generate_temporary_password()
    item.report_password_hash = hash_password(report_password)
    item.report_password_version += 1
    get_session().commit()
    audit(
        "client_report_password_reset",
        actor_id=actor.id,
        client_id=item.id,
        source_ip=request.remote_addr,
        changes=audit_changes(
            report_access_version=(
                item.report_password_version - 1,
                item.report_password_version,
            )
        ),
        shared_report_sessions_invalidated=True,
    )
    confirmation_token = report_password_confirmation_store.issue(
        actor_user_id=actor.id,
        client_id=item.id,
        report_password=report_password,
    )
    for key in REPORT_PASSWORD_CONFIRMATION_SESSION_KEYS:
        session.pop(key, None)
    session["report_password_confirmation_client_id"] = item.id
    session["report_password_confirmation_token"] = confirmation_token
    return redirect(
        url_for("main.client_report_password_confirmation", client_id=item.id)
    )


@main.get("/clients/<int:client_id>/report-password/confirmation")
@permission_required(REPORT_SHARE)
def client_report_password_confirmation(client_id: int) -> Any:
    item = cast(Client, get_or_404(Client, client_id))
    actor = cast(User, current_user())
    next_url = url_for("main.client", client_id=item.id)
    confirmation_client_id = session.pop("report_password_confirmation_client_id", None)
    confirmation_token = session.pop("report_password_confirmation_token", None)
    if confirmation_client_id != item.id or not isinstance(confirmation_token, str):
        return redirect(next_url)
    confirmation = report_password_confirmation_store.consume(
        confirmation_token,
        actor_user_id=actor.id,
        client_id=item.id,
    )
    if confirmation is None:
        return redirect(next_url)
    audit(
        "client_report_password_confirmation_viewed",
        actor_id=actor.id,
        client_id=item.id,
    )
    return render_template(
        "client_report_password_created.html",
        client=item,
        confirmation_ttl_seconds=REPORT_PASSWORD_CONFIRMATION_TTL_SECONDS,
        report_password=confirmation.report_password,
        mailto=report_password_mailto(item, confirmation.report_password),
        next_url=next_url,
    )


@main.route("/contracts/new/<int:client_id>", methods=["GET", "POST"])
@permission_required(CONTRACT_ADD)
def new_contract(client_id: int) -> Any:
    client_item = cast(Client, get_or_404(Client, client_id))
    if request.method != "POST":
        return render_template("contract_form.html", client=client_item)
    try:
        rate = Decimal(request.form.get("hourly_rate", "")).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        if rate < 0 or rate > Decimal("1000000"):
            raise ValueError("Hourly rate must be between $0.00 and $1,000,000.00.")
        name = form_text("name", "Contract", 200)
        if get_session().scalar(
            select(Contract.id).where(
                Contract.client_id == client_item.id,
                func.lower(Contract.name) == name.lower(),
            )
        ):
            raise ValueError(
                "A contract with that name already exists for this client."
            )
        contract_item = Contract(
            client=client_item,
            name=name,
            contact_name=form_text("contact_name", "Contact Name", 200),
            contact_email=normalize_email(request.form.get("contact_email", "")),
            hourly_rate_cents=int(rate * 100),
            created_at=now_utc(),
        )
    except (InvalidOperation, ValueError) as exc:
        message = str(exc) or "Enter a valid hourly rate."
        flash(message, "error")
        return render_template("contract_form.html", client=client_item), 400
    get_session().add(contract_item)
    try:
        get_session().commit()
    except IntegrityError:
        get_session().rollback()
        flash("A contract with that name already exists for this client.", "error")
        return render_template("contract_form.html", client=client_item), 409
    audit(
        "contract_created",
        actor_id=cast(User, current_user()).id,
        client_id=client_item.id,
        contract_id=contract_item.id,
        initial_values={
            "Contract": contract_item.name,
            "Contact Name": contract_item.contact_name,
            "Contact Email": contract_item.contact_email,
            "Billable Rate": audit_rate(contract_item.hourly_rate_cents),
        },
    )
    return redirect(url_for("main.contract", contract_id=contract_item.id))


@main.route("/contracts/<int:contract_id>/edit", methods=["GET", "POST"])
@permission_required(CONTRACT_EDIT)
def edit_contract(contract_id: int) -> Any:
    item = cast(Contract, get_or_404(Contract, contract_id))
    if request.method != "POST":
        return render_template("contract_form.html", client=item.client, contract=item)
    previous_values = {
        "contract": item.name,
        "contact_name": item.contact_name,
        "contact_email": item.contact_email,
    }
    try:
        name = form_text("name", "Contract", 200)
        if get_session().scalar(
            select(Contract.id).where(
                Contract.id != item.id,
                Contract.client_id == item.client_id,
                func.lower(Contract.name) == name.lower(),
            )
        ):
            raise ValueError(
                "A contract with that name already exists for this client."
            )
        item.name = name
        item.contact_name = form_text("contact_name", "Contact Name", 200)
        item.contact_email = normalize_email(request.form.get("contact_email", ""))
    except ValueError as exc:
        flash(str(exc), "error")
        return render_template(
            "contract_form.html", client=item.client, contract=item
        ), 400
    try:
        get_session().commit()
    except IntegrityError:
        get_session().rollback()
        flash("A contract with that name already exists for this client.", "error")
        return render_template(
            "contract_form.html", client=item.client, contract=item
        ), 409
    audit(
        "contract_updated",
        actor_id=cast(User, current_user()).id,
        client_id=item.client_id,
        contract_id=item.id,
        changes=audit_changes(
            contract=(previous_values["contract"], item.name),
            contact_name=(previous_values["contact_name"], item.contact_name),
            contact_email=(previous_values["contact_email"], item.contact_email),
        ),
    )
    flash("Contract details updated. The billable rate was not changed.", "success")
    return redirect(url_for("main.contract", contract_id=item.id))


@main.route("/contracts/<int:contract_id>/delete", methods=["GET", "POST"])
@permission_required(CONTRACT_DELETE)
def delete_contract(contract_id: int) -> Any:
    """Delete a contract and its work data after administrator reauthentication."""
    database = get_session()
    item = cast(Contract, get_or_404(Contract, contract_id))
    actor = cast(User, current_user())
    client_id = item.client_id
    client_name = item.client.name
    contract_name = item.name
    confirmation = {
        "eyebrow": "DELETE CONTRACT",
        "title": item.name,
        "description": (
            "Delete this contract, all tasks, subtasks, and recorded time. Audit "
            "history is retained. This cannot be undone."
        ),
        "submit_label": "Delete Contract",
        "cancel_url": url_for("main.contract", contract_id=item.id),
        "breadcrumb_parent_label": client_name,
        "breadcrumb_parent_url": url_for("main.client", client_id=client_id),
        "breadcrumb_label": "Delete Contract",
        "totp_required": bool(actor.totp_secret),
    }
    if request.method != "POST":
        return render_template("sensitive_action_form.html", **confirmation)
    client_label = audit_object_label(client_name, client_id)
    contract_label = audit_object_label(contract_name, item.id)
    failure = sensitive_action_failure(
        actor,
        confirmation,
        "contract_delete",
        client=client_label,
        contract=contract_label,
    )
    if failure is not None:
        return failure
    deleted_time = purge_contract_data(
        select(Contract.id).where(Contract.id == item.id)
    )
    database.commit()
    audit(
        "contract_deleted",
        actor_id=actor.id,
        client=client_label,
        contract=contract_label,
        deleted_time_entries=deleted_time,
    )
    flash("Contract and associated work data deleted.", "success")
    return redirect(url_for("main.client", client_id=client_id))


@main.get("/contracts/<int:contract_id>")
@permission_required(CONTRACT_VIEW)
def contract(contract_id: int) -> str:
    item = get_session().scalar(
        select(Contract)
        .where(Contract.id == contract_id)
        .options(
            selectinload(Contract.client),
            selectinload(Contract.tasks).selectinload(Task.subtasks),
            selectinload(Contract.tasks)
            .selectinload(Task.subtasks)
            .selectinload(Subtask.time_entries),
            selectinload(Contract.tasks).selectinload(Task.time_entries),
        )
    )
    if item is None:
        abort(404)
    return render_template("contract.html", contract=item)


@main.post("/tasks/<int:contract_id>/new")
@permission_required(TASK_ADD)
def new_task(contract_id: int) -> Any:
    contract_item = cast(Contract, get_or_404(Contract, contract_id))
    try:
        name = form_text("name", "Task Name", 200)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        if get_session().scalar(
            select(Task.id).where(
                Task.contract_id == contract_item.id,
                func.lower(Task.name) == name.lower(),
            )
        ):
            flash("A task with that name already exists for this contract.", "error")
            return redirect(url_for("main.contract", contract_id=contract_id))
        task = Task(contract=contract_item, name=name)
        get_session().add(task)
        try:
            get_session().commit()
        except IntegrityError:
            get_session().rollback()
            flash("A task with that name already exists for this contract.", "error")
            return redirect(url_for("main.contract", contract_id=contract_id))
        audit(
            "task_created",
            actor_id=cast(User, current_user()).id,
            contract_id=contract_id,
            task_id=task.id,
            initial_values={"Task Name": task.name},
        )
        flash("Task added.", "success")
    return redirect(url_for("main.contract", contract_id=contract_id))


@main.post("/subtasks/<int:task_id>/new")
@permission_required(TASK_ADD)
def new_subtask(task_id: int) -> Any:
    task = cast(Task, get_or_404(Task, task_id))
    try:
        name = form_text("name", "Subtask Name", 200)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        if get_session().scalar(
            select(Subtask.id).where(
                Subtask.task_id == task.id,
                func.lower(Subtask.name) == name.lower(),
            )
        ):
            flash("A subtask with that name already exists for this task.", "error")
            return redirect(url_for("main.contract", contract_id=task.contract_id))
        subtask = Subtask(task=task, name=name)
        get_session().add(subtask)
        try:
            get_session().commit()
        except IntegrityError:
            get_session().rollback()
            flash("A subtask with that name already exists for this task.", "error")
            return redirect(url_for("main.contract", contract_id=task.contract_id))
        audit(
            "subtask_created",
            actor_id=cast(User, current_user()).id,
            contract_id=task.contract_id,
            task_id=task.id,
            subtask_id=subtask.id,
            initial_values={"Subtask Name": subtask.name},
        )
        flash("Subtask added.", "success")
    return redirect(url_for("main.contract", contract_id=task.contract_id))


@main.post("/tasks/<int:task_id>/rename")
@permission_required(TASK_EDIT)
def rename_task(task_id: int) -> Any:
    task = cast(Task, get_or_404(Task, task_id))
    previous_name = task.name
    try:
        name = form_text("name", "Task Name", 200)
        duplicate = get_session().scalar(
            select(Task.id).where(
                Task.id != task.id,
                Task.contract_id == task.contract_id,
                func.lower(Task.name) == name.lower(),
            )
        )
        if duplicate:
            raise ValueError("A task with that name already exists for this contract.")
        task.name = name
        get_session().commit()
    except (IntegrityError, ValueError) as exc:
        get_session().rollback()
        flash(str(exc), "error")
    else:
        audit(
            "task_renamed",
            actor_id=cast(User, current_user()).id,
            contract_id=task.contract_id,
            task_id=task.id,
            changes=audit_changes(task_name=(previous_name, task.name)),
        )
        flash("Task renamed.", "success")
    return redirect(url_for("main.contract", contract_id=task.contract_id))


@main.post("/subtasks/<int:subtask_id>/rename")
@permission_required(TASK_EDIT)
def rename_subtask(subtask_id: int) -> Any:
    subtask = cast(Subtask, get_or_404(Subtask, subtask_id))
    previous_name = subtask.name
    try:
        name = form_text("name", "Subtask Name", 200)
        duplicate = get_session().scalar(
            select(Subtask.id).where(
                Subtask.id != subtask.id,
                Subtask.task_id == subtask.task_id,
                func.lower(Subtask.name) == name.lower(),
            )
        )
        if duplicate:
            raise ValueError("A subtask with that name already exists for this task.")
        subtask.name = name
        get_session().commit()
    except (IntegrityError, ValueError) as exc:
        get_session().rollback()
        flash(str(exc), "error")
    else:
        audit(
            "subtask_renamed",
            actor_id=cast(User, current_user()).id,
            contract_id=subtask.task.contract_id,
            task_id=subtask.task_id,
            subtask_id=subtask.id,
            changes=audit_changes(subtask_name=(previous_name, subtask.name)),
        )
        flash("Subtask renamed.", "success")
    return redirect(url_for("main.contract", contract_id=subtask.task.contract_id))


@main.route("/tasks/<int:task_id>/delete", methods=["GET", "POST"])
@permission_required(TASK_DELETE)
def delete_task(task_id: int) -> Any:
    database = get_session()
    task = cast(Task, get_or_404(Task, task_id))
    actor = cast(User, current_user())
    if not actor.is_admin:
        abort(403)
    client_name = task.contract.client.name
    contract_name = task.contract.name
    contract_id = task.contract_id
    task_label = audit_object_label(task.name, task.id)
    contract_label = audit_object_label(contract_name, contract_id)
    client_label = audit_object_label(client_name, task.contract.client_id)
    confirmation = {
        "eyebrow": "DELETE TASK",
        "title": task.name,
        "description": (
            "Delete this task, all subtasks, and recorded time. Audit history is "
            "retained. This cannot be undone."
        ),
        "submit_label": "Delete Task",
        "cancel_url": url_for("main.contract", contract_id=task.contract_id),
        "breadcrumb_parent_label": task.contract.name,
        "breadcrumb_parent_url": url_for("main.contract", contract_id=task.contract_id),
        "breadcrumb_label": "Delete Task",
        "totp_required": bool(actor.totp_secret),
    }
    if request.method != "POST":
        return render_template("sensitive_action_form.html", **confirmation)
    failure = sensitive_action_failure(
        actor,
        confirmation,
        "task_delete",
        client=client_label,
        contract=contract_label,
        task=task_label,
    )
    if failure is not None:
        return failure
    deleted_time = purge_task_data(select(Task.id).where(Task.id == task.id))
    database.commit()
    audit(
        "task_deleted",
        actor_id=actor.id,
        client=client_label,
        contract=contract_label,
        task=task_label,
        deleted_time_entries=deleted_time,
    )
    flash("Task deleted.", "success")
    return redirect(url_for("main.contract", contract_id=contract_id))


@main.route("/subtasks/<int:subtask_id>/delete", methods=["GET", "POST"])
@permission_required(TASK_DELETE)
def delete_subtask(subtask_id: int) -> Any:
    database = get_session()
    subtask = cast(Subtask, get_or_404(Subtask, subtask_id))
    actor = cast(User, current_user())
    if not actor.is_admin:
        abort(403)
    contract_id = subtask.task.contract_id
    client_name = subtask.task.contract.client.name
    contract_name = subtask.task.contract.name
    task_name = subtask.task.name
    client_label = audit_object_label(client_name, subtask.task.contract.client_id)
    contract_label = audit_object_label(contract_name, contract_id)
    task_label = audit_object_label(task_name, subtask.task_id)
    subtask_label = audit_object_label(subtask.name, subtask.id)
    confirmation = {
        "eyebrow": "DELETE SUBTASK",
        "title": subtask.name,
        "description": (
            "Delete this subtask and recorded time. Audit history is retained. "
            "This cannot be undone."
        ),
        "submit_label": "Delete Subtask",
        "cancel_url": url_for("main.contract", contract_id=contract_id),
        "breadcrumb_parent_label": subtask.task.contract.name,
        "breadcrumb_parent_url": url_for("main.contract", contract_id=contract_id),
        "breadcrumb_label": "Delete Subtask",
        "totp_required": bool(actor.totp_secret),
    }
    if request.method != "POST":
        return render_template("sensitive_action_form.html", **confirmation)
    failure = sensitive_action_failure(
        actor,
        confirmation,
        "subtask_delete",
        client=client_label,
        contract=contract_label,
        task=task_label,
        subtask=subtask_label,
    )
    if failure is not None:
        return failure
    deleted_time = purge_subtask_data(subtask.id)
    database.commit()
    audit(
        "subtask_deleted",
        actor_id=actor.id,
        client=client_label,
        contract=contract_label,
        task=task_label,
        subtask=subtask_label,
        deleted_time_entries=deleted_time,
    )
    flash("Subtask deleted.", "success")
    return redirect(url_for("main.contract", contract_id=contract_id))


# ---------------------------------------------------------------------------
# Timer and session routes
# ---------------------------------------------------------------------------


@main.post("/timer/start")
@permission_required(TIMER_START)
def start_timer() -> Any:
    database = get_session()
    user = cast(User, current_user())
    try:
        task_id = int(request.form.get("task_id", ""))
    except ValueError:
        abort(400)
    task = cast(Task, get_or_404(Task, task_id))
    subtask: Subtask | None = None
    raw_subtask_id = request.form.get("subtask_id", "")
    if raw_subtask_id:
        try:
            subtask = cast(Subtask, get_or_404(Subtask, int(raw_subtask_id)))
        except ValueError:
            abort(400)
        if subtask.task_id != task.id:
            abort(400, "The selected subtask does not belong to the selected task.")
    entry = TimeEntry(
        user=user,
        task=task,
        subtask=subtask,
        started_at=now_utc(),
        stopped_at=None,
    )
    database.add(entry)
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        flash("Stop your active timer before starting another.", "error")
        return redirect(
            url_for("main.contract", contract_id=task.contract_id), code=303
        )
    audit(
        "timer_started",
        **audit_time_entry_details(entry),
        initial_values={"Start Time": audit_time(entry.started_at)},
    )
    return redirect(url_for("main.contract", contract_id=task.contract_id))


@main.post("/timer/stop/<int:entry_id>")
@permission_required(TIMER_STOP)
def stop_timer(entry_id: int) -> Any:
    database = get_session()
    entry = cast(TimeEntry, get_or_404(TimeEntry, entry_id))
    user = cast(User, current_user())
    if entry.user_id != user.id or entry.stopped_at is not None:
        abort(403)
    entry.stopped_at = max(now_utc(), entry.started_at)
    database.commit()
    audit(
        "timer_stopped",
        **audit_time_entry_details(entry),
        end_time=audit_time(entry.stopped_at),
        duration=format_duration(duration_seconds(entry.started_at, entry.stopped_at)),
        billable_rate=audit_rate(entry.task.contract.hourly_rate_cents),
    )
    destination = safe_next_url(request.form.get("next"))
    return redirect(
        destination or url_for("main.contract", contract_id=entry.task.contract_id)
    )


@main.route("/contracts/<int:contract_id>/sessions/new", methods=["GET", "POST"])
@login_required
def new_time_entry(contract_id: int) -> Any:
    if not (can(TIME_ENTRY_ADD_OWN) or can(TIME_ENTRY_ADD_ANY)):
        abort(403)
    database = get_session()
    contract_item = database.scalar(
        select(Contract)
        .where(Contract.id == contract_id)
        .options(
            selectinload(Contract.client),
            selectinload(Contract.tasks).selectinload(Task.subtasks),
        )
    )
    if contract_item is None:
        abort(404)
    users = (
        database.scalars(select(User).order_by(User.last_name, User.first_name)).all()
        if can(TIME_ENTRY_ADD_ANY)
        else []
    )
    timezone_name = cast(str, current_app.config["DISPLAY_TIMEZONE"])
    default_end = now_utc()
    default_start = default_end - timedelta(hours=1)
    if request.method != "POST":
        return render_template(
            "session_create_form.html",
            contract=contract_item,
            tasks=contract_item.tasks,
            users=users,
            timezone_name=timezone_name,
            start_value=datetime_local_value(default_start, timezone_name),
            end_value=datetime_local_value(default_end, timezone_name),
        )
    actor = cast(User, current_user())
    try:
        entry_user = actor
        if can(TIME_ENTRY_ADD_ANY):
            raw_user_id = request.form.get("user_id", "")
            if not raw_user_id.isdigit():
                raise ValueError("Select a valid user.")
            selected_user = database.get(User, int(raw_user_id))
            if selected_user is None:
                raise ValueError("Select a valid user.")
            entry_user = selected_user
        task, subtask = parse_assignment(
            request.form.get("assignment", ""), contract_id
        )
        started_at = local_datetime_to_utc(
            request.form.get("started_at", ""), "Start time", timezone_name
        )
        stopped_at = local_datetime_to_utc(
            request.form.get("stopped_at", ""), "End time", timezone_name
        )
        if stopped_at < started_at:
            raise ValueError("End time cannot be earlier than start time.")
        if stopped_at > now_utc():
            raise ValueError("End time cannot be in the future.")
        if time_entry_overlaps(entry_user.id, started_at, stopped_at):
            raise ValueError("This time overlaps another session for the user.")
    except (OverflowError, ValueError) as exc:
        flash(str(exc), "error")
        return render_template(
            "session_create_form.html",
            contract=contract_item,
            tasks=contract_item.tasks,
            users=users,
            timezone_name=timezone_name,
            start_value=datetime_local_value(default_start, timezone_name),
            end_value=datetime_local_value(default_end, timezone_name),
        ), 400
    entry = TimeEntry(
        user=entry_user,
        task=task,
        subtask=subtask,
        started_at=started_at,
        stopped_at=stopped_at,
    )
    database.add(entry)
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        abort(409, "This time overlaps another session for the user.")
    audit(
        "time_entry_created",
        actor_id=actor.id,
        **audit_time_entry_details(entry),
        initial_values={
            "Start Time": audit_time(entry.started_at),
            "End Time": audit_time(entry.stopped_at),
            "Duration": format_duration(
                duration_seconds(entry.started_at, entry.stopped_at)
            ),
            "Billable Rate": audit_rate(entry.task.contract.hourly_rate_cents),
        },
    )
    flash("Time session added.", "success")
    return redirect(url_for("main.contract_sessions", contract_id=contract_id))


@main.get("/contracts/<int:contract_id>/sessions")
@login_required
def contract_sessions(contract_id: int) -> str:
    if not (can(TIME_ENTRY_VIEW_OWN) or can(TIME_ENTRY_VIEW_ANY)):
        abort(403)
    contract_item = get_session().scalar(
        select(Contract)
        .where(Contract.id == contract_id)
        .options(selectinload(Contract.client))
    )
    if contract_item is None:
        abort(404)
    statement = (
        select(TimeEntry)
        .join(TimeEntry.task)
        .where(Task.contract_id == contract_id)
        .options(
            selectinload(TimeEntry.user),
            selectinload(TimeEntry.task),
            selectinload(TimeEntry.subtask),
        )
        .order_by(TimeEntry.started_at.desc(), TimeEntry.id.desc())
    )
    if not can(TIME_ENTRY_VIEW_ANY):
        statement = statement.where(TimeEntry.user_id == cast(User, current_user()).id)
    entries = get_session().scalars(statement).all()
    snapshot_at = now_utc()
    session_rows = [
        {
            "entry": entry,
            "ended_at": entry.stopped_at or max(snapshot_at, entry.started_at),
            "seconds": duration_seconds(
                entry.started_at,
                entry.stopped_at or max(snapshot_at, entry.started_at),
            ),
            "can_edit": entry.stopped_at is not None and can(TIME_ENTRY_EDIT_ANY),
            "can_delete": entry.stopped_at is not None and can(TIME_ENTRY_DELETE_ANY),
        }
        for entry in entries
    ]
    return render_template(
        "sessions.html",
        contract=contract_item,
        session_rows=session_rows,
        show_users=can(TIME_ENTRY_VIEW_ANY),
        timezone_info=ZoneInfo(cast(str, current_app.config["DISPLAY_TIMEZONE"])),
    )


@main.get("/api/clients/<int:client_id>/contracts")
@permission_required(TIME_ENTRY_EDIT_ANY)
def session_client_contracts(client_id: int) -> Response:
    """Return contracts for the selected session client without inline script data."""
    contracts = (
        get_session()
        .scalars(
            select(Contract)
            .where(Contract.client_id == client_id)
            .order_by(Contract.name)
        )
        .all()
    )
    return jsonify(
        [{"id": contract.id, "name": contract.name} for contract in contracts]
    )


@main.get("/api/contracts/<int:contract_id>/assignments")
@permission_required(TIME_ENTRY_EDIT_ANY)
def session_contract_assignments(contract_id: int) -> Response:
    """Return task and subtask options for the selected session contract."""
    tasks = (
        get_session()
        .scalars(
            select(Task)
            .where(Task.contract_id == contract_id)
            .options(selectinload(Task.subtasks))
            .order_by(Task.name)
        )
        .all()
    )
    return jsonify(
        [
            {
                "id": task.id,
                "name": task.name,
                "subtasks": [
                    {"id": subtask.id, "name": subtask.name}
                    for subtask in task.subtasks
                ],
            }
            for task in tasks
        ]
    )


@main.route("/sessions/<int:entry_id>/edit", methods=["GET", "POST"])
@permission_required(TIME_ENTRY_EDIT_ANY)
def edit_time_entry(entry_id: int) -> Any:
    database = get_session()
    entry = database.scalar(
        select(TimeEntry)
        .where(TimeEntry.id == entry_id)
        .options(
            selectinload(TimeEntry.task).selectinload(Task.contract),
            selectinload(TimeEntry.subtask),
            selectinload(TimeEntry.user),
        )
    )
    if entry is None:
        abort(404)
    if entry.stopped_at is None:
        abort(409, "Stop an active timer before editing it.")
    contract_item = entry.task.contract
    original_contract_value = request.args.get("original_contract_id", "")
    if not original_contract_value:
        if request.method != "POST":
            return redirect(
                url_for(
                    "main.edit_time_entry",
                    entry_id=entry.id,
                    original_contract_id=contract_item.id,
                )
            )
        original_contract_id = contract_item.id
    elif original_contract_value.isdigit():
        original_contract_id = int(original_contract_value)
    else:
        abort(404)
    if original_contract_id != contract_item.id:
        notice = "time_entry_moved"
        if database.get(Contract, original_contract_id) is not None:
            return stale_resource_redirect(
                "main.contract_sessions", notice, contract_id=original_contract_id
            )
        return stale_resource_redirect("main.dashboard", notice)
    client_item = contract_item.client
    previous_details = audit_time_entry_details(entry)
    previous_started_at = entry.started_at
    previous_stopped_at = entry.stopped_at
    previous_rate = contract_item.hourly_rate_cents
    tasks = database.scalars(
        select(Task)
        .where(Task.contract_id == contract_item.id)
        .options(selectinload(Task.subtasks))
        .order_by(Task.name)
    ).all()
    clients = database.scalars(select(Client).order_by(Client.name)).all()
    users = database.scalars(
        select(User).order_by(User.last_name, User.first_name, User.email)
    ).all()
    timezone_name = cast(str, current_app.config["DISPLAY_TIMEZONE"])
    if request.method != "POST":
        return render_template(
            "session_form.html",
            entry=entry,
            client=client_item,
            contract=contract_item,
            clients=clients,
            users=users,
            tasks=tasks,
            timezone_name=timezone_name,
            start_value=datetime_local_value(entry.started_at, timezone_name),
            end_value=datetime_local_value(entry.stopped_at, timezone_name),
        )
    try:
        raw_user_id = request.form.get("user_id", "")
        raw_client_id = request.form.get("client_id", "")
        raw_contract_id = request.form.get("contract_id", "")
        if not all(
            value.isdigit() for value in (raw_user_id, raw_client_id, raw_contract_id)
        ):
            raise ValueError("Select a valid user, client, and contract.")
        entry_user = database.get(User, int(raw_user_id))
        selected_client = database.get(Client, int(raw_client_id))
        selected_contract = database.get(Contract, int(raw_contract_id))
        if (
            entry_user is None
            or not entry_user.is_enabled
            or selected_client is None
            or selected_contract is None
            or selected_contract.client_id != selected_client.id
        ):
            raise ValueError("Select a valid user, client, and contract.")
        task, subtask = parse_assignment(
            request.form.get("assignment", ""), selected_contract.id
        )
        started_at = local_datetime_to_utc(
            request.form.get("started_at", ""),
            "Start time",
            timezone_name,
            original_utc=entry.started_at,
        )
        stopped_at = local_datetime_to_utc(
            request.form.get("stopped_at", ""),
            "End time",
            timezone_name,
            original_utc=entry.stopped_at,
        )
        if stopped_at < started_at:
            raise ValueError("End time cannot be earlier than start time.")
        if stopped_at > now_utc():
            raise ValueError("End time cannot be in the future.")
        if time_entry_overlaps(
            entry_user.id,
            started_at,
            stopped_at,
            exclude_entry_id=entry.id,
        ):
            raise ValueError("This time overlaps another session for the user.")
    except (OverflowError, ValueError) as exc:
        flash(str(exc), "error")
        return render_template(
            "session_form.html",
            entry=entry,
            client=client_item,
            contract=contract_item,
            clients=clients,
            users=users,
            tasks=tasks,
            timezone_name=timezone_name,
            start_value=request.form.get(
                "started_at", datetime_local_value(entry.started_at, timezone_name)
            ),
            end_value=request.form.get(
                "stopped_at", datetime_local_value(entry.stopped_at, timezone_name)
            ),
        ), 400
    original_contract_id = entry.task.contract_id
    entry.user = entry_user
    entry.task = task
    entry.subtask = subtask
    entry.started_at = started_at
    entry.stopped_at = stopped_at
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        abort(409, "This time overlaps another session for the user.")
    audit(
        "time_entry_updated",
        actor_id=cast(User, current_user()).id,
        **audit_time_entry_details(entry),
        changes=audit_changes(
            client=(
                previous_details["client"],
                audit_object_label(selected_client.name, selected_client.id),
            ),
            contract=(
                previous_details["contract"],
                audit_object_label(selected_contract.name, selected_contract.id),
            ),
            task=(previous_details["task"], audit_object_label(task.name, task.id)),
            subtask=(
                previous_details["subtask"],
                audit_object_label(subtask.name, subtask.id)
                if subtask is not None
                else "None",
            ),
            user=(
                previous_details["user"], audit_object_label(entry_user.full_name, entry_user.id)
            ),
            start_time=(audit_time(previous_started_at), audit_time(started_at)),
            end_time=(audit_time(previous_stopped_at), audit_time(stopped_at)),
            duration=(
                format_duration(duration_seconds(previous_started_at, previous_stopped_at)),
                format_duration(duration_seconds(started_at, stopped_at)),
            ),
            billable_rate=(
                audit_rate(previous_rate), audit_rate(selected_contract.hourly_rate_cents)
            ),
        ),
    )
    flash("Time session updated.", "success")
    return redirect(url_for("main.contract_sessions", contract_id=original_contract_id))


@main.route("/sessions/<int:entry_id>/delete", methods=["GET", "POST"])
@permission_required(TIME_ENTRY_DELETE_ANY)
def delete_time_entry(entry_id: int) -> Any:
    database = get_session()
    entry = database.scalar(
        select(TimeEntry)
        .where(TimeEntry.id == entry_id)
        .options(selectinload(TimeEntry.task))
    )
    if entry is None:
        abort(404)
    if entry.stopped_at is None:
        abort(409, "Stop an active timer before deleting it.")
    contract_id = entry.task.contract_id
    client_label = audit_object_label(entry.task.contract.client.name, entry.task.contract.client_id)
    contract_label = audit_object_label(entry.task.contract.name, contract_id)
    task_label = audit_object_label(entry.task.name, entry.task_id)
    subtask_label = (
        audit_object_label(entry.subtask.name, entry.subtask_id)
        if entry.subtask is not None and entry.subtask_id is not None
        else None
    )
    user_label = audit_object_label(entry.user.full_name, entry.user_id)
    entry_label = f"Time entry (ID: {entry.id})"
    actor = cast(User, current_user())
    confirmation = {
        "eyebrow": "DELETE SESSION",
        "title": "Delete Time Session",
        "description": (
            "Delete this completed time session. Reports will no longer include it."
        ),
        "submit_label": "Delete Session",
        "cancel_url": url_for("main.contract_sessions", contract_id=contract_id),
        "breadcrumb_parent_label": entry.task.contract.name,
        "breadcrumb_parent_url": url_for(
            "main.contract_sessions", contract_id=contract_id
        ),
        "breadcrumb_label": "Delete Session",
        "totp_required": bool(actor.totp_secret),
    }
    if request.method != "POST":
        return render_template("sensitive_action_form.html", **confirmation)
    rate_key = sensitive_action_rate_key(actor)
    if sensitive_action_limiter.blocked(rate_key):
        abort(429)
    if not sensitive_action_credentials_valid(actor):
        sensitive_action_limiter.record_failure(rate_key)
        audit(
            "time_entry_delete_rejected",
            actor_id=actor.id,
            user=user_label,
            client=client_label,
            contract=contract_label,
            task=task_label,
            subtask=subtask_label,
            time_entry=entry_label,
        )
        flash("The administrator credentials were not accepted.", "error")
        return render_template("sensitive_action_form.html", **confirmation), 400
    sensitive_action_limiter.clear(rate_key)
    database.delete(entry)
    database.commit()
    audit(
        "time_entry_deleted",
        actor_id=actor.id,
        user=user_label,
        client=client_label,
        contract=contract_label,
        task=task_label,
        subtask=subtask_label,
        time_entry=entry_label,
        start_time=audit_time(entry.started_at),
        end_time=audit_time(entry.stopped_at),
        duration=format_duration(duration_seconds(entry.started_at, entry.stopped_at)),
        billable_rate=audit_rate(entry.task.contract.hourly_rate_cents),
    )
    flash("Time session deleted.", "success")
    return redirect(url_for("main.contract_sessions", contract_id=contract_id))


# ---------------------------------------------------------------------------
# Profile and user administration routes
# ---------------------------------------------------------------------------


@main.get("/profile")
@login_required
def profile() -> str:
    return render_template("profile.html", user=cast(User, current_user()))


@main.get("/profile/password/change-required")
@login_required
def required_password_change() -> Any:
    user = cast(User, current_user())
    if not user.password_change_required:
        return redirect(url_for("main.profile"))
    return render_template("password_change_required.html", user=user)


@main.post("/profile/name")
@login_required
def update_profile_name() -> Any:
    user = cast(User, current_user())
    previous_first_name = user.first_name
    previous_last_name = user.last_name
    try:
        user.first_name = form_text("first_name", "First Name", 100)
        user.last_name = form_text("last_name", "Last Name", 100)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        get_session().commit()
        audit(
            "profile_updated",
            user_id=user.id,
            changes=audit_changes(
                first_name=(previous_first_name, user.first_name),
                last_name=(previous_last_name, user.last_name),
            ),
        )
        flash("Profile updated.", "success")
    return redirect(url_for("main.profile"))


@main.post("/profile/password")
@login_required
def change_password() -> Any:
    user = cast(User, current_user())
    was_required = user.password_change_required
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirmation = request.form.get("confirm_password", "")
    if not verify_password(user.password_hash, current_password):
        flash("The current password was not accepted.", "error")
    elif verify_password(user.password_hash, new_password):
        flash("The new password must differ from the current password.", "error")
    elif new_password != confirmation:
        flash("The new password confirmation does not match.", "error")
    elif error := password_error(new_password):
        flash(error, "error")
    else:
        user.password_hash = hash_password(new_password)
        user.password_change_required = False
        user.session_version += 1
        get_session().commit()
        audit(
            "password_changed",
            user_id=user.id,
            source_ip=request.remote_addr,
            sessions_invalidated=True,
        )
        session.clear()
        flash("Password changed successfully. Please sign in again.", "success")
        return redirect(url_for("main.login"))
    return redirect(
        url_for("main.required_password_change" if was_required else "main.profile")
    )


@main.post("/profile/totp/setup")
@login_required
def setup_totp() -> str:
    user = cast(User, current_user())
    if user.totp_secret:
        abort(409, "Disable the active two-factor method before setting up a new one.")
    user.pending_totp_secret = pyotp.random_base32()
    get_session().commit()
    audit("totp_setup_started", user_id=user.id, source_ip=request.remote_addr)
    uri = provisioning_uri(user, user.pending_totp_secret)
    return render_template(
        "totp_setup.html",
        user=user,
        secret=user.pending_totp_secret,
        qr_code=qr_data_uri(uri),
    )


@main.post("/profile/totp/confirm")
@login_required
def confirm_totp() -> Any:
    user = cast(User, current_user())
    if user.totp_secret:
        abort(409, "Disable the active two-factor method before setting up a new one.")
    secret = user.pending_totp_secret
    if not secret or not consume_totp(
        user, request.form.get("totp", ""), secret=secret
    ):
        audit(
            "totp_setup_rejected",
            user_id=user.id,
            source_ip=request.remote_addr,
            reason="verification_code",
        )
        flash("The verification code was not accepted. Setup was not enabled.", "error")
        return redirect(url_for("main.profile")), 400
    user.totp_secret = secret
    user.pending_totp_secret = None
    user.session_version += 1
    get_session().commit()
    session["session_version"] = user.session_version
    audit(
        "totp_enabled",
        user_id=user.id,
        source_ip=request.remote_addr,
        sessions_invalidated=True,
    )
    flash("Two-factor authentication has been enabled.", "success")
    return redirect(url_for("main.profile"))


@main.post("/profile/totp/disable")
@login_required
def disable_totp() -> Any:
    user = cast(User, current_user())
    if not user.totp_secret:
        return redirect(url_for("main.profile"))
    if not verify_password(
        user.password_hash, request.form.get("current_password", "")
    ) or not consume_totp(user, request.form.get("totp", "")):
        audit(
            "totp_disable_rejected",
            user_id=user.id,
            source_ip=request.remote_addr,
            reason="reauthentication",
        )
        flash("The password or verification code was not accepted.", "error")
        return redirect(url_for("main.profile")), 400
    user.totp_secret = None
    user.pending_totp_secret = None
    reset_totp_replay_state(get_session(), user.id)
    user.session_version += 1
    get_session().commit()
    session["session_version"] = user.session_version
    audit(
        "totp_disabled",
        user_id=user.id,
        source_ip=request.remote_addr,
        sessions_invalidated=True,
    )
    flash("Two-factor authentication has been disabled.", "success")
    return redirect(url_for("main.profile"))


@main.get("/users")
@permission_required(USER_VIEW)
def users() -> str:
    user_list = (
        get_session()
        .scalars(select(User).order_by(User.last_name, User.first_name))
        .all()
    )
    return render_template("users.html", users=user_list)


@main.get("/audit")
@permission_required(AUDIT_VIEW)
def audit_log() -> str:
    """Render a filtered, paginated view of the immutable audit trail."""
    source_filter = request.args.get("source", "").strip()
    event_filter = request.args.get("event", "").strip()
    actor_filter = request.args.get("actor", "").strip()
    page_value = request.args.get("page", "1").strip()
    if source_filter and source_filter not in AUDIT_SOURCES:
        abort(400)
    if event_filter and (
        len(event_filter) > 100
        or not event_filter.isascii()
        or not event_filter.replace("_", "").isalnum()
    ):
        abort(400)
    try:
        page = int(page_value)
        actor_id = int(actor_filter) if actor_filter else None
    except ValueError:
        abort(400)
    if page < 1 or (actor_id is not None and actor_id < 1):
        abort(400)

    # Historical telemetry and reconciliation noise remain immutable in storage,
    # but only meaningful application actions belong in the audit experience.
    conditions = [AuditEvent.event.not_in(HIDDEN_AUDIT_EVENTS)]
    if source_filter:
        conditions.append(AuditEvent.source == source_filter)
    if event_filter:
        conditions.append(AuditEvent.event == event_filter)
    if actor_id is not None:
        conditions.append(AuditEvent.actor_user_id == actor_id)

    database = get_session()
    total = int(
        database.scalar(select(func.count(AuditEvent.id)).where(*conditions)) or 0
    )
    page_count = max(1, (total + AUDIT_PAGE_SIZE - 1) // AUDIT_PAGE_SIZE)
    if page > page_count:
        abort(404)
    events = database.scalars(
        select(AuditEvent.event)
        .where(AuditEvent.event.not_in(HIDDEN_AUDIT_EVENTS))
        .distinct()
        .order_by(AuditEvent.event)
    ).all()
    actors = database.scalars(
        select(User).order_by(User.last_name, User.first_name, User.id)
    ).all()
    items = database.scalars(
        select(AuditEvent)
        .where(*conditions)
        .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
        .offset((page - 1) * AUDIT_PAGE_SIZE)
        .limit(AUDIT_PAGE_SIZE)
    ).all()
    query_parameters: dict[str, Any] = {
        key: value
        for key, value in {
            "source": source_filter,
            "event": event_filter,
            "actor": actor_filter,
        }.items()
        if value
    }
    return render_template(
        "audit_log.html",
        items=items,
        events=events,
        actors=actors,
        source_filter=source_filter,
        event_filter=event_filter,
        actor_filter=actor_filter,
        page=page,
        page_count=page_count,
        total=total,
        timezone_info=ZoneInfo(cast(str, current_app.config["DISPLAY_TIMEZONE"])),
        previous_url=(
            url_for("main.audit_log", page=page - 1, **query_parameters)
            if page > 1
            else None
        ),
        next_url=(
            url_for("main.audit_log", page=page + 1, **query_parameters)
            if page < page_count
            else None
        ),
    )


@main.route("/users/new", methods=["GET", "POST"])
@permission_required(USER_ADD)
def new_user() -> Any:
    if request.method != "POST":
        return render_template("user_form.html")
    try:
        email = normalize_email(request.form.get("email", ""))
        if find_user_by_email(email):
            raise ValueError("A user with that email already exists.")
        temporary_password = generate_temporary_password()
        password_hash = hash_password(temporary_password)
        user = User(
            email=email,
            first_name=form_text("first_name", "First Name", 100),
            last_name=form_text("last_name", "Last Name", 100),
            password_hash=password_hash,
            totp_secret=None,
            pending_totp_secret=None,
            role="user",
            is_enabled=True,
            password_change_required=True,
            session_version=1,
            created_at=now_utc(),
        )
    except ValueError as exc:
        flash(str(exc), "error")
        return render_template("user_form.html"), 400
    get_session().add(user)
    try:
        get_session().commit()
    except IntegrityError:
        get_session().rollback()
        flash("A user with that email already exists.", "error")
        return render_template("user_form.html"), 409
    audit(
        "user_created",
        actor_id=cast(User, current_user()).id,
        user_id=user.id,
        initial_values={
            "Email": user.email,
            "First Name": user.first_name,
            "Last Name": user.last_name,
            "Role": user.role,
            "Enabled": user.is_enabled,
            "Two-Factor Authentication": "Not configured",
        },
    )
    return render_template(
        "user_created.html",
        user=user,
        temporary_password=temporary_password,
    )


@main.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@permission_required(USER_EDIT)
def edit_user(user_id: int) -> Any:
    database = get_session()
    actor = cast(User, current_user())
    user = cast(User, get_or_404(User, user_id))
    email_managed = is_deployment_managed_user(database, user.email)
    if request.method != "POST":
        return render_template(
            "user_edit_form.html", user=user, email_managed=email_managed
        )
    previous_values = {
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
    }
    try:
        email = normalize_email(request.form.get("email", ""))
        if email_managed and email != user.email:
            raise ValueError("A deployment-managed user email cannot be changed here.")
        existing = find_user_by_email(email)
        if existing is not None and existing.id != user.id:
            raise ValueError("A user with that email already exists.")
        first_name = form_text("first_name", "First Name", 100)
        last_name = form_text("last_name", "Last Name", 100)
    except ValueError as exc:
        flash(str(exc), "error")
        return render_template(
            "user_edit_form.html", user=user, email_managed=email_managed
        ), 400
    email_changed = user.email != email
    user.email = email
    user.first_name = first_name
    user.last_name = last_name
    if email_changed:
        user.session_version += 1
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        flash("A user with that email already exists.", "error")
        return render_template(
            "user_edit_form.html", user=user, email_managed=email_managed
        ), 409
    if user.id == actor.id and email_changed:
        session["session_version"] = user.session_version
    audit(
        "user_updated",
        actor_id=actor.id,
        user_id=user.id,
        changes=audit_changes(
            email=(previous_values["email"], user.email),
            first_name=(previous_values["first_name"], user.first_name),
            last_name=(previous_values["last_name"], user.last_name),
        ),
    )
    flash("User details updated.", "success")
    return redirect(url_for("main.users"))


@main.route("/users/<int:user_id>/reset-password", methods=["GET", "POST"])
@permission_required(USER_PASSWORD_RESET)
def reset_user_password(user_id: int) -> Any:
    actor = cast(User, current_user())
    user = cast(User, get_or_404(User, user_id))
    if user.id == actor.id:
        abort(409, "Use the profile page to change your current password.")
    confirmation = {
        "eyebrow": "PASSWORD RESET",
        "title": user.full_name,
        "description": (
            "Generate a temporary password, invalidate the user's existing "
            "sessions, and require a password change after sign-in."
        ),
        "submit_label": "Reset User Password",
        "cancel_url": url_for("main.users"),
        "breadcrumb_parent_label": "Users",
        "breadcrumb_parent_url": url_for("main.users"),
        "breadcrumb_label": "Reset User Password",
        "totp_required": bool(actor.totp_secret),
    }
    if request.method != "POST":
        return render_template("sensitive_action_form.html", **confirmation)
    rate_key = sensitive_action_rate_key(actor)
    if sensitive_action_limiter.blocked(rate_key):
        audit(
            "user_password_reset_rate_limited",
            actor_id=actor.id,
            user_id=user.id,
            source_ip=request.remote_addr,
        )
        abort(429)
    if not sensitive_action_credentials_valid(actor):
        sensitive_action_limiter.record_failure(rate_key)
        audit(
            "user_password_reset_rejected",
            actor_id=actor.id,
            user_id=user.id,
            source_ip=request.remote_addr,
        )
        flash("The administrator credentials were not accepted.", "error")
        return render_template("sensitive_action_form.html", **confirmation), 400
    sensitive_action_limiter.clear(rate_key)
    temporary_password = generate_temporary_password()
    user.password_hash = hash_password(temporary_password)
    user.password_change_required = True
    user.session_version += 1
    get_session().commit()
    audit(
        "user_password_reset",
        actor_id=actor.id,
        user_id=user.id,
        source_ip=request.remote_addr,
        sessions_invalidated=True,
        must_change_at_next_sign_in=True,
    )
    return render_template(
        "password_reset_created.html",
        user=user,
        temporary_password=temporary_password,
    )


@main.route("/users/<int:user_id>/toggle-enabled", methods=["GET", "POST"])
@permission_required(USER_EDIT)
def toggle_user_enabled(user_id: int) -> Any:
    database = get_session()
    actor = cast(User, current_user())
    user = cast(User, get_or_404(User, user_id))
    if user.id == actor.id:
        abort(409, "Administrators cannot disable their current account.")
    confirmation = {
        "eyebrow": "DISABLE USER" if user.is_enabled else "ENABLE USER",
        "title": user.full_name,
        "description": (
            "This will disable the user and stop any active timers immediately."
            if user.is_enabled
            else "This will enable the user immediately."
        ),
        "submit_label": "Disable User" if user.is_enabled else "Enable User",
        "submit_class": "button-stop" if user.is_enabled else "button-primary",
        "submit_icon": "fa-user-xmark" if user.is_enabled else "fa-user-check",
        "cancel_url": url_for("main.users"),
        "breadcrumb_parent_label": "Users",
        "breadcrumb_parent_url": url_for("main.users"),
        "breadcrumb_label": "Disable User" if user.is_enabled else "Enable User",
        "totp_required": bool(actor.totp_secret),
    }
    if request.method != "POST":
        return render_template("sensitive_action_form.html", **confirmation)
    rate_key = sensitive_action_rate_key(actor)
    if sensitive_action_limiter.blocked(rate_key):
        audit("user_enabled_change_rate_limited", actor_id=actor.id, user_id=user.id, source_ip=request.remote_addr)
        abort(429)
    if not sensitive_action_credentials_valid(actor):
        sensitive_action_limiter.record_failure(rate_key)
        audit("user_enabled_change_rejected", actor_id=actor.id, user_id=user.id, source_ip=request.remote_addr)
        flash("The administrator credentials were not accepted.", "error")
        return render_template("sensitive_action_form.html", **confirmation), 400
    sensitive_action_limiter.clear(rate_key)
    previous_enabled = user.is_enabled
    user.is_enabled = not user.is_enabled
    user.session_version += 1
    if not user.is_enabled:
        stopped_at = now_utc()
        for entry in database.scalars(
            select(TimeEntry).where(
                TimeEntry.user_id == user.id, TimeEntry.stopped_at.is_(None)
            )
        ):
            entry.stopped_at = max(stopped_at, entry.started_at)
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        abort(409, "At least one enabled administrator is required.")
    audit(
        "user_enabled" if user.is_enabled else "user_disabled",
        actor_id=actor.id,
        user_id=user.id,
        source_ip=request.remote_addr,
        changes=audit_changes(enabled=(previous_enabled, user.is_enabled)),
    )
    flash("User enabled." if user.is_enabled else "User disabled.", "success")
    return redirect(url_for("main.users"))


@main.route("/users/<int:user_id>/toggle-admin", methods=["GET", "POST"])
@permission_required(USER_EDIT)
def toggle_user_admin(user_id: int) -> Any:
    database = get_session()
    actor = cast(User, current_user())
    user = cast(User, get_or_404(User, user_id))
    if user.id == actor.id:
        abort(409, "Administrators cannot change their current role.")
    promoting = not user.is_admin
    confirmation = {
        "eyebrow": "PROMOTE USER" if promoting else "DEMOTE ADMINISTRATOR",
        "title": user.full_name,
        "description": (
            "This user will immediately become an administrator."
            if promoting
            else "This user will immediately lose administrator privileges."
        ),
        "submit_label": "Promote User" if promoting else "Demote Administrator",
        "submit_class": "button-stop" if promoting else "button-primary",
        "submit_icon": "fa-user-gear" if promoting else "fa-user",
        "cancel_url": url_for("main.users"),
        "breadcrumb_parent_label": "Users",
        "breadcrumb_parent_url": url_for("main.users"),
        "breadcrumb_label": "Promote User" if promoting else "Demote Administrator",
        "totp_required": bool(actor.totp_secret),
    }
    if request.method != "POST":
        return render_template("sensitive_action_form.html", **confirmation)
    rate_key = sensitive_action_rate_key(actor)
    if sensitive_action_limiter.blocked(rate_key):
        audit("user_role_change_rate_limited", actor_id=actor.id, user_id=user.id, source_ip=request.remote_addr)
        abort(429)
    if not sensitive_action_credentials_valid(actor):
        sensitive_action_limiter.record_failure(rate_key)
        audit("user_role_change_rejected", actor_id=actor.id, user_id=user.id, source_ip=request.remote_addr)
        flash("The administrator credentials were not accepted.", "error")
        return render_template("sensitive_action_form.html", **confirmation), 400
    sensitive_action_limiter.clear(rate_key)
    previous_role = user.role
    user.role = "user" if user.role == "admin" else "admin"
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        abort(409, "At least one enabled administrator is required.")
    audit(
        "user_role_changed",
        actor_id=actor.id,
        user_id=user.id,
        source_ip=request.remote_addr,
        changes=audit_changes(role=(previous_role, user.role)),
    )
    flash("User promoted to administrator." if user.is_admin else "User demoted to standard user.", "success")
    return redirect(url_for("main.users"))


# ---------------------------------------------------------------------------
# Reporting routes
# ---------------------------------------------------------------------------


def live_report_response(
    report: ContractReport | ClientReport,
    *,
    shared_report: bool,
    live_report_url: str,
) -> Any:
    """Return changed report markup or an inexpensive not-modified response."""
    etag = report_state_etag(report)
    if request.if_none_match.contains(etag):
        response = current_app.response_class(status=304)
    else:
        response = current_app.make_response(
            render_template(
                "_report_content.html",
                report=report,
                shared_report=shared_report,
                report_etag=etag,
                live_report_url=live_report_url,
            )
        )
    response.set_etag(etag)
    return response


@main.route("/shared/reports/<token>", methods=["GET", "POST"])
def shared_report(token: str) -> Any:
    client_item = get_shared_report_client(token)
    if not shared_report_access_allowed(client_item):
        if request.method != "POST":
            return render_template("shared_report_login.html", client=client_item)
        ip = request.remote_addr or "unknown"
        rate_key = f"{ip}|{client_item.id}"
        if shared_report_limiter.blocked(rate_key):
            audit(
                "shared_report_rate_limited",
                client_id=client_item.id,
                source_ip=ip,
            )
            abort(429)
        password_hash = client_item.report_password_hash
        if not password_hash or not verify_password(
            password_hash, request.form.get("report_password", "")
        ):
            shared_report_limiter.record_failure(rate_key)
            audit(
                "shared_report_rejected",
                client_id=client_item.id,
                source_ip=ip,
            )
            flash(
                "A report password has not been generated yet."
                if not password_hash
                else "The report password was not accepted.",
                "error",
            )
            return render_template("shared_report_login.html", client=client_item), 401
        shared_report_limiter.clear(rate_key)
        audit(
            "shared_report_access_granted",
            client_id=client_item.id,
            source_ip=ip,
        )
        return set_shared_report_cookie(
            redirect(url_for("main.shared_report", token=token)),
            client_item,
        )
    report = build_client_report(
        get_session(), client_item, cast(str, current_app.config["DISPLAY_TIMEZONE"])
    )
    audit(
        "shared_report_viewed",
        client_id=client_item.id,
        source_ip=request.remote_addr,
    )
    etag = report_state_etag(report)
    return render_template(
        "report.html",
        report=report,
        shared_report=True,
        report_etag=etag,
        live_report_url=url_for("main.shared_report_live", token=token),
    )


@main.get("/shared/reports/<token>/live")
def shared_report_live(token: str) -> Any:
    client_item = get_shared_report_client(token)
    if not shared_report_access_allowed(client_item):
        return redirect(url_for("main.shared_report", token=token))
    report = build_client_report(
        get_session(), client_item, cast(str, current_app.config["DISPLAY_TIMEZONE"])
    )
    return live_report_response(
        report,
        shared_report=True,
        live_report_url=url_for("main.shared_report_live", token=token),
    )


@main.get("/reports/<int:client_id>")
@permission_required(REPORT_VIEW)
def report_view(client_id: int) -> str:
    client_item = cast(Client, get_or_404(Client, client_id))
    report = build_client_report(
        get_session(),
        client_item,
        cast(str, current_app.config["DISPLAY_TIMEZONE"]),
    )
    audit(
        "report_viewed",
        user_id=cast(User, current_user()).id,
        client_id=client_item.id,
    )
    etag = report_state_etag(report)
    return render_template(
        "authenticated_report.html",
        report=report,
        shared_report=False,
        report_etag=etag,
        live_report_url=url_for("main.report_live", client_id=client_item.id),
    )


@main.get("/reports/<int:client_id>/live")
@permission_required(REPORT_VIEW)
def report_live(client_id: int) -> Any:
    client_item = cast(Client, get_or_404(Client, client_id))
    report = build_client_report(
        get_session(),
        client_item,
        cast(str, current_app.config["DISPLAY_TIMEZONE"]),
    )
    return live_report_response(
        report,
        shared_report=False,
        live_report_url=url_for("main.report_live", client_id=client_item.id),
    )
