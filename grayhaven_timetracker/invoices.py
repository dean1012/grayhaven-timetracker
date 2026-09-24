"""Invoice preview, generation, and payment-state domain operations."""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload, selectinload

from .audit import record_audit_event
from .invoice_pdf import render_invoice_pdf
from .invoice_summary import build_worker_summary_json
from .invoice_time import total_billable_hours, worker_daily_billable_hours
from .models import (
    Client,
    Contract,
    Disbursement,
    Invoice,
    InvoiceLine,
    Task,
    TimeEntry,
    User,
)


class InvoiceDomainError(ValueError):
    """Raised when an invoice action violates a business-state rule."""


@dataclass(frozen=True)
class InvoicePreviewEntry:
    """One entry exactly as it will appear on a generated invoice."""

    time_entry_id: int
    user_id: int
    worker_name: str
    task_name: str
    subtask_name: str | None
    started_at_utc: datetime
    stopped_at_utc: datetime
    total_seconds: int
    started_before_range: bool


@dataclass(frozen=True)
class InvoicePreview:
    """Stable, fingerprinted representation shown before invoice generation."""

    contract_id: int
    client_id: int
    client_name: str
    project_name: str
    contact_name: str
    contact_email: str
    hourly_rate_cents: int
    payment_terms_days: int
    timezone_name: str
    range_start_utc: datetime
    range_end_utc: datetime
    entries: tuple[InvoicePreviewEntry, ...]
    total_seconds: int
    total_cents: int
    fingerprint: str

    @property
    def billable_hours(self) -> Decimal:
        return total_billable_hours(self.entries, ZoneInfo(self.timezone_name))


def utc_now() -> datetime:
    """Return the actual current UTC instant in the database timestamp format."""
    return datetime.now(UTC).replace(tzinfo=None)


def _utc_timestamp(value: datetime, label: str) -> datetime:
    if value.tzinfo is None:
        return value
    try:
        return value.astimezone(UTC).replace(tzinfo=None)
    except (OverflowError, ValueError) as exc:
        raise InvoiceDomainError(f"{label} must be a valid UTC timestamp.") from exc


def _timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise InvoiceDomainError("The invoice timezone is invalid.") from exc


def _total_cents(billable_hours: Decimal, hourly_rate_cents: int) -> int:
    amount = billable_hours * Decimal(hourly_rate_cents)
    return int(amount.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def invoice_total_cents(
    lines: tuple[InvoicePreviewEntry, ...] | list[InvoiceLine],
    timezone: ZoneInfo,
    hourly_rate_cents: int,
) -> int:
    """Sum independently rounded worker amounts to preserve payout parity."""
    return sum(
        _total_cents(
            sum((hours for _, hours in days), Decimal("0.00")), hourly_rate_cents
        )
        for days in worker_daily_billable_hours(lines, timezone).values()
    )


# Validated against a legacy SQL export during upgrade testing.
def migrate_invoice_snapshots(
    database: Session, branding: Path
) -> int:  # pragma: no cover
    """Revise legacy invoice PDFs once after the structural schema upgrade."""
    legacy = database.scalars(
        select(Invoice)
        .where(Invoice.pdf_version == 1)
        .options(selectinload(Invoice.lines), selectinload(Invoice.current_entries))
        .order_by(Invoice.id)
    ).all()
    if not legacy:
        return 0
    logo = branding / "grayhaven-logo-wordmark-light.png"
    regular_font = branding / "fonts/inter-400.ttf"
    bold_font = branding / "fonts/inter-700.ttf"
    pdf_paths = (
        (logo, regular_font, bold_font)
        if all(path.is_file() for path in (logo, regular_font, bold_font))
        else (None, None, None)
    )
    admin_id = database.scalar(
        select(User.id).where(User.role == "admin").order_by(User.id).limit(1)
    )
    if admin_id is None:
        raise InvoiceDomainError("Invoice migration requires an administrator.")
    for invoice in legacy:
        timezone = _timezone(invoice.timezone_name)
        invoice.worker_summary_json = build_worker_summary_json(
            invoice, invoice.lines, timezone
        )
        invoice.total_cents = invoice_total_cents(
            invoice.lines, timezone, invoice.hourly_rate_cents
        )
        by_worker: dict[int, list[InvoiceLine]] = {}
        for line in invoice.lines:
            by_worker.setdefault(line.user_id, []).append(line)
        for user_id, lines in by_worker.items():
            entries = [
                entry for entry in invoice.current_entries if entry.user_id == user_id
            ]
            disbursed = [
                entry for entry in entries if entry.billing_status == "disbursed"
            ]
            if not disbursed:
                continue
            if len(disbursed) != len(entries) or len(entries) != len(lines):
                raise InvoiceDomainError(
                    "Legacy disbursement cannot be migrated automatically."
                )
            dates = {entry.disbursement_date for entry in disbursed}
            references = {entry.transaction_number for entry in disbursed}
            if len(dates) != 1 or len(references) != 1:
                raise InvoiceDomainError(
                    "Legacy disbursement has inconsistent transaction details."
                )
            disbursement_date = dates.pop()
            reference = references.pop()
            if disbursement_date is None or not reference:
                raise InvoiceDomainError("Legacy disbursement details are incomplete.")
            amount = invoice_total_cents(lines, timezone, invoice.hourly_rate_cents)
            if amount:
                database.add(
                    Disbursement(
                        user_id=user_id,
                        date=disbursement_date,
                        transaction_id=reference,
                        type="DISBURSEMENT",
                        amount_cents=amount,
                        notes=None,
                        archived_at=None,
                        archived_by_user_id=None,
                        created_at=utc_now(),
                        created_by_user_id=admin_id,
                    )
                )
            for entry in disbursed:
                entry.billing_status = "client_paid"
                entry.disbursement_date = None
                entry.transaction_number = None
        invoice.pdf_version = 2
        invoice.pdf_bytes = render_invoice_pdf(
            invoice,
            invoice.lines,
            logo_path=pdf_paths[0],
            font_regular_path=pdf_paths[1],
            font_bold_path=pdf_paths[2],
        )
        record_audit_event(
            database,
            "invoice_migrated",
            source="system",
            details={
                "invoice_number": invoice.invoice_number,
                "reason": "Updated invoice billing presentation and calculations",
            },
        )
    database.flush()
    return len(legacy)


def _observed_holidays(year: int) -> set[date]:
    holidays: set[date] = set()
    for holiday_year in range(year - 1, year + 2):
        for month, day in ((1, 1), (6, 19), (7, 4), (11, 11), (12, 25)):
            actual = date(holiday_year, month, day)
            holidays.add(actual)
            if actual.weekday() == 5:
                holidays.add(actual - timedelta(days=1))
            elif actual.weekday() == 6:
                holidays.add(actual + timedelta(days=1))
    return holidays


def calculate_due_date(issued_date: date, payment_terms_days: int) -> date:
    """Apply calendar-day terms, then move forward over weekends and holidays."""
    if payment_terms_days not in {0, 7, 30}:
        raise InvoiceDomainError("Payment terms must be 0, 7, or 30 days.")
    due_date = issued_date + timedelta(days=payment_terms_days)
    holidays = _observed_holidays(due_date.year)
    while due_date.weekday() >= 5 or due_date in holidays:
        due_date += timedelta(days=1)
    return due_date


def _resolve_range(
    database: Session,
    *,
    contract_id: int,
    range_start_utc: datetime | None,
    range_end_utc: datetime | None,
    now: datetime,
) -> tuple[datetime, datetime]:
    if (range_start_utc is None) != (range_end_utc is None):
        raise InvoiceDomainError("Provide both invoice range bounds or neither.")
    if range_start_utc is not None and range_end_utc is not None:
        start = _utc_timestamp(range_start_utc, "Range start")
        end = _utc_timestamp(range_end_utc, "Range end")
    else:
        end = now
        latest = database.scalar(
            select(Invoice)
            .where(Invoice.contract_id == contract_id, Invoice.status != "VOID")
            .order_by(Invoice.issued_at.desc(), Invoice.id.desc())
            .limit(1)
        )
        if latest is not None:
            start = latest.range_end_utc
        else:
            first_started = database.scalar(
                select(func.min(TimeEntry.started_at))
                .join(TimeEntry.task)
                .where(
                    Task.contract_id == contract_id,
                    TimeEntry.stopped_at.is_not(None),
                    TimeEntry.stopped_at < end,
                    TimeEntry.billing_status == "pending_invoice",
                )
            )
            if first_started is None:
                raise InvoiceDomainError("There are no eligible entries to invoice.")
            start = first_started
    if end <= start:
        raise InvoiceDomainError("Invoice range end must be after its start.")
    if end > now:
        raise InvoiceDomainError("Invoice range end cannot be in the future.")
    return start, end


def _preview_fingerprint(data: dict[str, object]) -> str:
    encoded = json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=lambda value: (
            value.isoformat() if isinstance(value, datetime) else value
        ),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _build_preview(
    database: Session,
    *,
    contract_id: int,
    range_start_utc: datetime | None,
    range_end_utc: datetime | None,
    timezone_name: str,
    now: datetime,
) -> InvoicePreview:
    _timezone(timezone_name)
    contract = database.scalar(
        select(Contract)
        .join(Contract.client)
        .where(Contract.id == contract_id)
        .options(joinedload(Contract.client))
    )
    if contract is None:
        raise InvoiceDomainError("The selected project does not exist.")
    if contract.archived_at is not None:
        raise InvoiceDomainError("An archived project cannot be invoiced.")
    if contract.payment_terms_days not in {0, 7, 30}:
        raise InvoiceDomainError("The project has invalid payment terms.")
    start, end = _resolve_range(
        database,
        contract_id=contract.id,
        range_start_utc=range_start_utc,
        range_end_utc=range_end_utc,
        now=now,
    )
    records = database.scalars(
        select(TimeEntry)
        .join(TimeEntry.task)
        .where(
            Task.contract_id == contract.id,
            TimeEntry.stopped_at.is_not(None),
            TimeEntry.stopped_at >= start,
            TimeEntry.stopped_at < end,
            TimeEntry.billing_status == "pending_invoice",
        )
        .options(
            joinedload(TimeEntry.user),
            joinedload(TimeEntry.task),
            joinedload(TimeEntry.subtask),
        )
        .order_by(TimeEntry.stopped_at, TimeEntry.id)
    ).all()
    entries = tuple(
        InvoicePreviewEntry(
            time_entry_id=entry.id,
            user_id=entry.user_id,
            worker_name=entry.user.full_name,
            task_name=entry.task.name,
            subtask_name=entry.subtask.name if entry.subtask else None,
            started_at_utc=entry.started_at,
            stopped_at_utc=entry.stopped_at,
            total_seconds=max(
                0, int((entry.stopped_at - entry.started_at).total_seconds())
            ),
            started_before_range=entry.started_at < start,
        )
        for entry in records
        if entry.stopped_at is not None
    )
    if not entries:
        raise InvoiceDomainError("There are no eligible entries to invoice.")
    total_seconds = sum(entry.total_seconds for entry in entries)
    fingerprint_data: dict[str, object] = {
        "billing_policy": "worker-daily-quarter-hour-half-up-v2",
        "contract_id": contract.id,
        "client_id": contract.client_id,
        "client_name": contract.client.name,
        "project_name": contract.name,
        "contact_name": contract.contact_name,
        "contact_email": contract.contact_email,
        "hourly_rate_cents": contract.hourly_rate_cents,
        "payment_terms_days": contract.payment_terms_days,
        "timezone_name": timezone_name,
        "range_start_utc": start,
        "range_end_utc": end,
        "entries": [asdict(entry) for entry in entries],
    }
    return InvoicePreview(
        contract_id=contract.id,
        client_id=contract.client_id,
        client_name=contract.client.name,
        project_name=contract.name,
        contact_name=contract.contact_name,
        contact_email=contract.contact_email,
        hourly_rate_cents=contract.hourly_rate_cents,
        payment_terms_days=contract.payment_terms_days,
        timezone_name=timezone_name,
        range_start_utc=start,
        range_end_utc=end,
        entries=entries,
        total_seconds=total_seconds,
        total_cents=invoice_total_cents(
            entries, _timezone(timezone_name), contract.hourly_rate_cents
        ),
        fingerprint=_preview_fingerprint(fingerprint_data),
    )


def preview_invoice(
    database: Session,
    *,
    contract_id: int,
    range_start_utc: datetime | None = None,
    range_end_utc: datetime | None = None,
    timezone_name: str,
) -> InvoicePreview:
    """Build the read-only invoice preview required before generation."""
    return _build_preview(
        database,
        contract_id=contract_id,
        range_start_utc=range_start_utc,
        range_end_utc=range_end_utc,
        timezone_name=timezone_name,
        now=utc_now(),
    )


@contextmanager
def _immediate_transaction(database: Session) -> Iterator[None]:
    if database.in_transaction():
        database.rollback()
    try:
        database.connection().exec_driver_sql("BEGIN IMMEDIATE")
        yield
    except Exception:
        database.rollback()
        raise


def create_invoice(
    database: Session,
    *,
    contract_id: int,
    range_start_utc: datetime | None = None,
    range_end_utc: datetime | None = None,
    timezone_name: str,
    expected_fingerprint: str,
    logo_path: Path | None = None,
    font_regular_path: Path | None = None,
    font_bold_path: Path | None = None,
) -> Invoice:
    """Claim previewed entries and persist their invoice and PDF atomically."""
    if not expected_fingerprint:
        raise InvoiceDomainError("Invoice generation requires a current preview.")
    with _immediate_transaction(database):
        issued_at = utc_now()
        preview = _build_preview(
            database,
            contract_id=contract_id,
            range_start_utc=range_start_utc,
            range_end_utc=range_end_utc,
            timezone_name=timezone_name,
            now=issued_at,
        )
        if not secrets.compare_digest(preview.fingerprint, expected_fingerprint):
            raise InvoiceDomainError(
                "Invoice details changed; review a fresh preview before generating."
            )
        sequence = (
            database.scalar(
                select(func.max(Invoice.project_sequence)).where(
                    Invoice.contract_id == contract_id
                )
            )
            or 0
        ) + 1
        if sequence > 999:
            raise InvoiceDomainError("This project has reached invoice sequence 999.")
        client = database.get(Client, preview.client_id)
        contract = database.get(Contract, preview.contract_id)
        if client is None or contract is None:
            raise InvoiceDomainError("The selected project does not exist.")
        invoice_number = (
            f"{client.public_number:03d}-{contract.public_number:03d}-{sequence:03d}"
        )
        issued_date = (
            issued_at.replace(tzinfo=UTC).astimezone(_timezone(timezone_name)).date()
        )
        invoice = Invoice(
            client_id=preview.client_id,
            contract_id=preview.contract_id,
            project_sequence=sequence,
            invoice_number=invoice_number,
            status="UNPAID",
            issued_at=issued_at,
            range_start_utc=preview.range_start_utc,
            range_end_utc=preview.range_end_utc,
            timezone_name=preview.timezone_name,
            client_name=preview.client_name,
            project_name=preview.project_name,
            contact_name=preview.contact_name,
            contact_email=preview.contact_email,
            hourly_rate_cents=preview.hourly_rate_cents,
            payment_terms_days=preview.payment_terms_days,
            total_seconds=preview.total_seconds,
            total_cents=preview.total_cents,
            due_date=calculate_due_date(issued_date, preview.payment_terms_days),
            paid_date=None,
            refunded=False,
            pdf_version=2,
            pdf_bytes=b"",
        )
        invoice.lines = [
            InvoiceLine(
                time_entry_id=entry.time_entry_id,
                user_id=entry.user_id,
                worker_name=entry.worker_name,
                task_name=entry.task_name,
                subtask_name=entry.subtask_name,
                started_at_utc=entry.started_at_utc,
                stopped_at_utc=entry.stopped_at_utc,
                total_seconds=entry.total_seconds,
                started_before_range=entry.started_before_range,
            )
            for entry in preview.entries
        ]
        invoice.worker_summary_json = build_worker_summary_json(
            invoice, invoice.lines, _timezone(timezone_name)
        )
        invoice.pdf_bytes = render_invoice_pdf(
            invoice,
            invoice.lines,
            logo_path=logo_path,
            font_regular_path=font_regular_path,
            font_bold_path=font_bold_path,
        )
        database.add(invoice)
        database.flush()
        entries_by_id = {
            entry.id: entry
            for entry in database.scalars(
                select(TimeEntry)
                .where(
                    TimeEntry.id.in_(item.time_entry_id for item in preview.entries),
                    TimeEntry.billing_status == "pending_invoice",
                )
                .execution_options(include_hidden=True)
            )
        }
        if len(entries_by_id) != len(preview.entries):
            raise InvoiceDomainError(
                "Invoice entries changed; review a fresh preview before generating."
            )
        for preview_entry in preview.entries:
            entry = entries_by_id[preview_entry.time_entry_id]
            entry.billing_status = "invoiced"
            entry.invoice_id = invoice.id
            entry.invoice_number = invoice.invoice_number
            entry.invoice_date = issued_date
            entry.client_paid_date = None
            entry.disbursement_date = None
            entry.transaction_number = None
        database.flush()
        return invoice


def _invoice(database: Session, invoice_id: int) -> Invoice:
    invoice = database.get(Invoice, invoice_id)
    if invoice is None:
        raise InvoiceDomainError("Invoice does not exist.")
    return invoice


def _claimed_entries(database: Session, invoice: Invoice) -> list[TimeEntry]:
    expected_ids = set(
        database.scalars(
            select(InvoiceLine.time_entry_id).where(
                InvoiceLine.invoice_id == invoice.id
            )
        )
    )
    entries = list(
        database.scalars(
            select(TimeEntry)
            .where(TimeEntry.invoice_id == invoice.id)
            .execution_options(include_hidden=True)
            .order_by(TimeEntry.id)
        )
    )
    if not expected_ids or {entry.id for entry in entries} != expected_ids:
        raise InvoiceDomainError("Invoice entry claims are inconsistent.")
    if any(entry.invoice_number != invoice.invoice_number for entry in entries):
        raise InvoiceDomainError("Invoice entry metadata is inconsistent.")
    return entries


def mark_invoice_paid(
    database: Session, invoice_id: int, paid_date: date | None = None
) -> Invoice:
    """Record client payment for one unpaid invoice."""
    with _immediate_transaction(database):
        invoice = _invoice(database, invoice_id)
        if invoice.status != "UNPAID":
            raise InvoiceDomainError("Only an unpaid invoice can be marked paid.")
        entries = _claimed_entries(database, invoice)
        if any(entry.billing_status != "invoiced" for entry in entries):
            raise InvoiceDomainError("Invoice entries are not awaiting client payment.")
        local_paid_date = (
            paid_date
            or utc_now()
            .replace(tzinfo=UTC)
            .astimezone(_timezone(invoice.timezone_name))
            .date()
        )
        today = (
            utc_now()
            .replace(tzinfo=UTC)
            .astimezone(_timezone(invoice.timezone_name))
            .date()
        )
        if local_paid_date > today:
            raise InvoiceDomainError("Payment date cannot be in the future.")
        invoice.status = "PAID"
        invoice.paid_date = local_paid_date
        for entry in entries:
            entry.billing_status = "client_paid"
            entry.client_paid_date = local_paid_date
        return invoice


def refund_invoice(database: Session, invoice_id: int) -> Invoice:
    """Mark a paid invoice refunded without changing worker entitlements."""
    with _immediate_transaction(database):
        invoice = _invoice(database, invoice_id)
        if invoice.status != "PAID" or invoice.refunded:
            raise InvoiceDomainError("Only a paid invoice can be refunded.")
        if any(
            entry.billing_status != "client_paid"
            for entry in _claimed_entries(database, invoice)
        ):
            raise InvoiceDomainError("Invoice entries have an invalid payment state.")
        invoice.refunded = True
        return invoice


def void_invoice(database: Session, invoice_id: int) -> Invoice:
    """Void an unpaid invoice and release its entries for later invoicing."""
    with _immediate_transaction(database):
        invoice = _invoice(database, invoice_id)
        if invoice.status != "UNPAID":
            raise InvoiceDomainError("Only an unpaid invoice can be voided.")
        entries = _claimed_entries(database, invoice)
        if any(entry.billing_status != "invoiced" for entry in entries):
            raise InvoiceDomainError("Invoice entries have an invalid payment state.")
        invoice.status = "VOID"
        invoice.paid_date = None
        for entry in entries:
            entry.billing_status = "pending_invoice"
            entry.invoice_id = None
            entry.invoice_number = None
            entry.invoice_date = None
            entry.client_paid_date = None
            entry.disbursement_date = None
            entry.transaction_number = None
        return invoice
