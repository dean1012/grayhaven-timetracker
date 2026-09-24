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
from sqlalchemy.orm import Session, joinedload

from .invoice_pdf import render_invoice_pdf
from .invoice_time import total_billable_hours
from .models import Contract, Invoice, InvoiceLine, Task, TimeEntry


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
        raise InvoiceDomainError(f"{label} must be a valid UTC timestamp") from exc


def _timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise InvoiceDomainError("The invoice timezone is invalid") from exc


def _total_cents(billable_hours: Decimal, hourly_rate_cents: int) -> int:
    amount = billable_hours * Decimal(hourly_rate_cents)
    return int(amount.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


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
        raise InvoiceDomainError("Payment terms must be 0, 7, or 30 days")
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
        raise InvoiceDomainError("Provide both invoice range bounds or neither")
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
                raise InvoiceDomainError("There are no eligible entries to invoice")
            start = first_started
    if end <= start:
        raise InvoiceDomainError("Invoice range end must be after its start")
    if end > now:
        raise InvoiceDomainError("Invoice range end cannot be in the future")
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
        raise InvoiceDomainError("The selected project does not exist")
    if contract.archived_at is not None:
        raise InvoiceDomainError("An archived project cannot be invoiced")
    if contract.payment_terms_days not in {0, 7, 30}:
        raise InvoiceDomainError("The project has invalid payment terms")
    if contract.client_id > 999 or contract.id > 999:
        raise InvoiceDomainError(
            "Invoice numbers support client and project IDs through 999"
        )
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
        raise InvoiceDomainError("There are no eligible entries to invoice")
    total_seconds = sum(entry.total_seconds for entry in entries)
    fingerprint_data: dict[str, object] = {
        "billing_policy": "daily-hundredth-half-up-v1",
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
        total_cents=_total_cents(
            total_billable_hours(entries, _timezone(timezone_name)),
            contract.hourly_rate_cents,
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
        raise InvoiceDomainError("Invoice generation requires a current preview")
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
                "Invoice details changed; review a fresh preview before generating"
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
            raise InvoiceDomainError("This project has reached invoice sequence 999")
        invoice_number = (
            f"{preview.client_id:03d}-{preview.contract_id:03d}-{sequence:03d}"
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
                "Invoice entries changed; review a fresh preview before generating"
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
        raise InvoiceDomainError("Invoice does not exist")
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
        raise InvoiceDomainError("Invoice entry claims are inconsistent")
    if any(entry.invoice_number != invoice.invoice_number for entry in entries):
        raise InvoiceDomainError("Invoice entry metadata is inconsistent")
    return entries


def mark_invoice_paid(
    database: Session, invoice_id: int, paid_date: date | None = None
) -> Invoice:
    """Record client payment for one unpaid invoice."""
    with _immediate_transaction(database):
        invoice = _invoice(database, invoice_id)
        if invoice.status != "UNPAID":
            raise InvoiceDomainError("Only an unpaid invoice can be marked paid")
        entries = _claimed_entries(database, invoice)
        if any(entry.billing_status != "invoiced" for entry in entries):
            raise InvoiceDomainError("Invoice entries are not awaiting client payment")
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
            raise InvoiceDomainError("Payment date cannot be in the future")
        invoice.status = "PAID"
        invoice.paid_date = local_paid_date
        for entry in entries:
            entry.billing_status = "client_paid"
            entry.client_paid_date = local_paid_date
        database.flush()
        return invoice


def mark_invoice_unpaid(database: Session, invoice_id: int) -> Invoice:
    """Reverse client payment when no invoice entry has been disbursed."""
    with _immediate_transaction(database):
        invoice = _invoice(database, invoice_id)
        if invoice.status != "PAID":
            raise InvoiceDomainError("Only a paid invoice can be marked unpaid")
        entries = _claimed_entries(database, invoice)
        if any(entry.billing_status == "disbursed" for entry in entries):
            raise InvoiceDomainError("A disbursed invoice cannot be marked unpaid")
        if any(entry.billing_status != "client_paid" for entry in entries):
            raise InvoiceDomainError("Invoice entries have an invalid payment state")
        invoice.status = "UNPAID"
        invoice.paid_date = None
        for entry in entries:
            entry.billing_status = "invoiced"
            entry.client_paid_date = None
        database.flush()
        return invoice


def void_invoice(database: Session, invoice_id: int) -> Invoice:
    """Void an unpaid invoice and release its entries for later invoicing."""
    with _immediate_transaction(database):
        invoice = _invoice(database, invoice_id)
        if invoice.status != "UNPAID":
            raise InvoiceDomainError("Only an unpaid invoice can be voided")
        entries = _claimed_entries(database, invoice)
        if any(entry.billing_status == "disbursed" for entry in entries):
            raise InvoiceDomainError("A disbursed invoice cannot be voided")
        if any(entry.billing_status != "invoiced" for entry in entries):
            raise InvoiceDomainError("Invoice entries have an invalid payment state")
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
        database.flush()
        return invoice


def disburse_invoice(
    database: Session,
    invoice_id: int,
    *,
    disbursement_date: date,
    reference: str,
    user_id: int | None = None,
) -> list[TimeEntry]:
    """Disburse all remaining invoice entries or those for one worker."""
    normalized_reference = reference.strip()
    if not normalized_reference:
        raise InvoiceDomainError("Disbursement reference is required")
    if len(normalized_reference) > 100:
        raise InvoiceDomainError("Disbursement reference is too long")
    with _immediate_transaction(database):
        invoice = _invoice(database, invoice_id)
        if invoice.status != "PAID":
            raise InvoiceDomainError("Only a paid invoice can be disbursed")
        today = (
            utc_now()
            .replace(tzinfo=UTC)
            .astimezone(_timezone(invoice.timezone_name))
            .date()
        )
        if invoice.paid_date is None or disbursement_date < invoice.paid_date:
            raise InvoiceDomainError(
                "Disbursement date cannot be before the invoice payment date"
            )
        if disbursement_date > today:
            raise InvoiceDomainError("Disbursement date cannot be in the future")
        claimed = _claimed_entries(database, invoice)
        selected = [
            entry
            for entry in claimed
            if entry.billing_status == "client_paid"
            and (user_id is None or entry.user_id == user_id)
        ]
        if not selected:
            raise InvoiceDomainError("There are no matching paid entries to disburse")
        for entry in selected:
            entry.billing_status = "disbursed"
            entry.disbursement_date = disbursement_date
            entry.transaction_number = normalized_reference
        database.flush()
        return selected


def undo_disbursement(
    database: Session, invoice_id: int, *, user_id: int
) -> list[TimeEntry]:
    """Undo a worker's disbursements while retaining the invoice payment."""
    with _immediate_transaction(database):
        invoice = _invoice(database, invoice_id)
        if invoice.status != "PAID":
            raise InvoiceDomainError("Only a paid invoice has disbursements")
        entries = [
            entry
            for entry in _claimed_entries(database, invoice)
            if entry.user_id == user_id and entry.billing_status == "disbursed"
        ]
        if not entries:
            raise InvoiceDomainError("The selected worker has no disbursed sessions")
        for entry in entries:
            entry.billing_status = "client_paid"
            entry.disbursement_date = None
            entry.transaction_number = None
        database.flush()
        return entries
