"""Independent worker balances and disbursement transactions."""

from __future__ import annotations

from datetime import date

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .invoice_summary import worker_snapshot_records
from .invoices import (
    InvoiceDomainError,
    _immediate_transaction,
    require_available_transaction_id,
    utc_now,
)
from .models import Disbursement, Invoice, InvoiceLine, User

TYPES = frozenset({"DISBURSEMENT", "IN_KIND", "RETAINED_EARNINGS"})


def paid_earnings_cents(database: Session, user_id: int) -> int:
    """Sum this worker's immutable share of paid invoice snapshots."""
    invoices = database.scalars(
        select(Invoice)
        .join(InvoiceLine, InvoiceLine.invoice_id == Invoice.id)
        .where(Invoice.status == "PAID", InvoiceLine.user_id == user_id)
        .distinct()
    ).all()
    return sum(
        int(record["amount_cents"])
        for invoice in invoices
        for record in worker_snapshot_records(invoice)
        if int(record["user_id"]) == user_id
    )


def outstanding_cents(database: Session, user_id: int) -> int:
    disbursed = database.scalar(
        select(func.coalesce(func.sum(Disbursement.amount_cents), 0)).where(
            Disbursement.user_id == user_id, Disbursement.archived_at.is_(None)
        )
    )
    return paid_earnings_cents(database, user_id) - int(disbursed or 0)


def _validated_values(
    user: User,
    *,
    kind: str,
    date_value: date,
    transaction_id: str | None,
    amount_cents: int,
    notes: str | None,
) -> tuple[str | None, str | None]:
    if kind not in TYPES:
        raise InvoiceDomainError("Select a valid disbursement type.")
    if kind in {"IN_KIND", "RETAINED_EARNINGS"} and user.user_type != "llc_member":
        raise InvoiceDomainError(
            "In-Kind Transactions and Retained Earnings are only for LLC Members."
        )
    if amount_cents <= 0:
        raise InvoiceDomainError("Amount must be greater than zero.")
    if date_value > date.today():
        raise InvoiceDomainError("Date cannot be in the future.")
    reference = (transaction_id or "").strip() or None
    if kind == "RETAINED_EARNINGS":
        if reference is not None:
            raise InvoiceDomainError("Retained Earnings cannot have a transaction ID.")
    elif reference is None:
        raise InvoiceDomainError("Transaction ID is required.")
    if reference is not None and len(reference) > 100:
        raise InvoiceDomainError("Transaction ID is too long.")
    normalized_notes = (notes or "").strip() or None
    if normalized_notes is not None and len(normalized_notes) > 2000:
        raise InvoiceDomainError("Notes are too long.")
    return reference, normalized_notes


def create_disbursement(
    database: Session,
    *,
    user_id: int,
    actor_id: int,
    kind: str,
    date_value: date,
    transaction_id: str | None,
    amount_cents: int,
    notes: str | None,
) -> Disbursement:
    with _immediate_transaction(database):
        user = database.get(User, user_id)
        if user is None:
            raise InvoiceDomainError("Worker does not exist.")
        reference, normalized_notes = _validated_values(
            user,
            kind=kind,
            date_value=date_value,
            transaction_id=transaction_id,
            amount_cents=amount_cents,
            notes=notes,
        )
        if amount_cents > outstanding_cents(database, user_id):
            raise InvoiceDomainError(
                "Amount exceeds the worker's pending disbursement."
            )
        if reference is not None:
            reference = require_available_transaction_id(database, reference)
        item = Disbursement(
            user_id=user_id,
            date=date_value,
            transaction_id=reference,
            type=kind,
            amount_cents=amount_cents,
            notes=normalized_notes,
            archived_at=None,
            archived_by_user_id=None,
            created_at=utc_now(),
            created_by_user_id=actor_id,
        )
        database.add(item)
        database.flush()
        return item
