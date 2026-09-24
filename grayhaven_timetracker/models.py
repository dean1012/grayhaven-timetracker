"""Relational models for application data and its append-only audit trail."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    event,
    func,
    select,
    text,
)
from sqlalchemy.engine import Connection
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all application models."""


class User(Base):
    __tablename__ = "user_account"
    __table_args__ = (
        CheckConstraint("role IN ('admin', 'user')", name="ck_user_role"),
        CheckConstraint(
            "user_type IN ('llc_member', 'subcontractor')", name="ck_user_type"
        ),
        CheckConstraint("length(trim(email)) > 3", name="ck_user_email"),
        CheckConstraint("length(trim(first_name)) > 0", name="ck_user_first_name"),
        CheckConstraint("length(trim(last_name)) > 0", name="ck_user_last_name"),
        CheckConstraint("session_version >= 1", name="ck_user_session_version"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(
        String(255, collation="NOCASE"), unique=True, index=True
    )
    first_name: Mapped[str] = mapped_column(String(100))
    last_name: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(String(512))
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pending_totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    role: Mapped[str] = mapped_column(String(16), default="user")
    user_type: Mapped[str] = mapped_column(
        String(16), default="subcontractor", server_default="subcontractor"
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    password_change_required: Mapped[bool] = mapped_column(Boolean, default=False)
    session_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime)

    time_entries: Mapped[list[TimeEntry]] = relationship(back_populates="user")
    passkey_identity: Mapped[PasskeyIdentity | None] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False
    )
    passkeys: Mapped[list[PasskeyCredential]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    disbursements: Mapped[list[Disbursement]] = relationship(
        back_populates="user", foreign_keys="Disbursement.user_id"
    )

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class Client(Base):
    __tablename__ = "client"
    __table_args__ = (
        CheckConstraint("length(trim(name)) > 0", name="ck_client_name"),
        CheckConstraint(
            "length(trim(contact_name)) > 0", name="ck_client_contact_name"
        ),
        CheckConstraint(
            "length(trim(contact_email)) > 3", name="ck_client_contact_email"
        ),
        CheckConstraint(
            "report_password_version >= 1",
            name="ck_client_report_password_version",
        ),
        Index("uq_client_name", "name", unique=True),
        Index("uq_client_public_number", "public_number", unique=True),
        Index("uq_client_report_token", "report_token", unique=True),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    public_number: Mapped[int] = mapped_column(
        Integer, CheckConstraint("public_number BETWEEN 1 AND 999"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200, collation="NOCASE"))
    contact_name: Mapped[str] = mapped_column(String(200))
    contact_email: Mapped[str] = mapped_column(String(255))
    report_password_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    report_password_version: Mapped[int] = mapped_column(Integer, default=1)
    visible: Mapped[bool] = mapped_column(Boolean, default=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    archived_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("user_account.id", ondelete="RESTRICT"), nullable=True
    )
    report_token: Mapped[str] = mapped_column(
        String(128), default=lambda: secrets.token_urlsafe(32)
    )

    contracts: Mapped[list[Contract]] = relationship(
        back_populates="client", order_by=lambda: Contract.id.desc()
    )
    invoices: Mapped[list[Invoice]] = relationship(back_populates="client")

    @property
    def display_number(self) -> str:
        return f"{self.public_number:03d}"


class Contract(Base):
    __tablename__ = "contract"
    __table_args__ = (
        CheckConstraint("length(trim(name)) > 0", name="ck_contract_name"),
        CheckConstraint(
            "length(trim(contact_name)) > 0", name="ck_contract_contact_name"
        ),
        CheckConstraint(
            "length(trim(contact_email)) > 3", name="ck_contract_contact_email"
        ),
        CheckConstraint(
            "hourly_rate_cents BETWEEN 0 AND 100000000",
            name="ck_contract_rate",
        ),
        CheckConstraint(
            "payment_terms_days IN (0, 7, 30)",
            name="ck_contract_payment_terms",
        ),
        Index("uq_contract_client_name", "client_id", "name", unique=True),
        Index(
            "uq_contract_client_public_number",
            "client_id",
            "public_number",
            unique=True,
        ),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    public_number: Mapped[int] = mapped_column(
        Integer, CheckConstraint("public_number BETWEEN 1 AND 999"), nullable=False
    )
    visible: Mapped[bool] = mapped_column(Boolean, default=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("client.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(200, collation="NOCASE"))
    contact_name: Mapped[str] = mapped_column(String(200))
    contact_email: Mapped[str] = mapped_column(String(255))
    hourly_rate_cents: Mapped[int] = mapped_column(Integer)
    payment_terms_days: Mapped[int] = mapped_column(
        Integer, default=30, server_default="30"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC).replace(tzinfo=None)
    )
    archived_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    archived_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("user_account.id", ondelete="RESTRICT"), nullable=True
    )
    client: Mapped[Client] = relationship(back_populates="contracts")
    tasks: Mapped[list[Task]] = relationship(
        back_populates="contract", order_by="Task.id"
    )
    invoices: Mapped[list[Invoice]] = relationship(back_populates="contract")

    @property
    def hourly_rate(self) -> Decimal:
        return Decimal(self.hourly_rate_cents) / Decimal(100)

    @property
    def public_ref(self) -> str:
        return f"{self.client.public_number:03d}-{self.public_number:03d}"


@event.listens_for(Client, "before_insert")
def assign_client_public_number(
    _mapper: Any, connection: Connection, client: Client
) -> None:
    if client.public_number is not None:
        return
    used = set(connection.execute(select(Client.public_number)).scalars())
    available = tuple(number for number in range(100, 1000) if number not in used)
    if not available:
        raise ValueError("No client numbers remain")
    client.public_number = secrets.choice(available)


@event.listens_for(Contract, "before_insert")
def assign_contract_public_number(
    _mapper: Any, connection: Connection, contract: Contract
) -> None:
    if contract.public_number is not None:
        return
    current = connection.execute(
        select(func.max(Contract.public_number)).where(
            Contract.client_id == contract.client_id
        )
    ).scalar()
    next_number = int(current or 0) + 1
    if next_number > 999:
        raise ValueError("No contract numbers remain for this client")
    contract.public_number = next_number


class Task(Base):
    __tablename__ = "task"
    __table_args__ = (
        CheckConstraint("length(trim(name)) > 0", name="ck_task_name"),
        Index("uq_task_contract_name", "contract_id", "name", unique=True),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    visible: Mapped[bool] = mapped_column(Boolean, default=True)
    contract_id: Mapped[int] = mapped_column(
        ForeignKey("contract.id", ondelete="RESTRICT"), index=True
    )
    name: Mapped[str] = mapped_column(String(200, collation="NOCASE"))

    contract: Mapped[Contract] = relationship(back_populates="tasks")
    subtasks: Mapped[list[Subtask]] = relationship(
        back_populates="task", cascade="all, delete-orphan", order_by="Subtask.id"
    )
    time_entries: Mapped[list[TimeEntry]] = relationship(back_populates="task")


class Subtask(Base):
    __tablename__ = "subtask"
    __table_args__ = (
        CheckConstraint("length(trim(name)) > 0", name="ck_subtask_name"),
        Index("uq_subtask_task_name", "task_id", "name", unique=True),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    visible: Mapped[bool] = mapped_column(Boolean, default=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("task.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200, collation="NOCASE"))

    task: Mapped[Task] = relationship(back_populates="subtasks")
    time_entries: Mapped[list[TimeEntry]] = relationship(back_populates="subtask")


class TimeEntry(Base):
    __tablename__ = "time_entry"
    __table_args__ = (
        CheckConstraint(
            "stopped_at IS NULL OR stopped_at >= started_at",
            name="ck_time_entry_order",
        ),
        CheckConstraint(
            "billing_status IN "
            "('pending_invoice', 'invoiced', 'client_paid', 'disbursed')",
            name="ck_time_entry_billing_status",
        ),
        CheckConstraint(
            "stopped_at IS NULL OR billing_status = 'pending_invoice' "
            "OR invoice_number IS NOT NULL",
            name="ck_time_entry_invoice_metadata",
        ),
        Index(
            "uq_active_timer_per_user",
            "user_id",
            unique=True,
            sqlite_where=text("stopped_at IS NULL AND visible = 1"),
        ),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    visible: Mapped[bool] = mapped_column(Boolean, default=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user_account.id", ondelete="RESTRICT"), index=True
    )
    task_id: Mapped[int] = mapped_column(
        ForeignKey("task.id", ondelete="RESTRICT"), index=True
    )
    subtask_id: Mapped[int | None] = mapped_column(
        ForeignKey("subtask.id", ondelete="RESTRICT"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    billing_status: Mapped[str] = mapped_column(
        String(32), default="pending_invoice", server_default="pending_invoice"
    )
    invoice_number: Mapped[str | None] = mapped_column(String(100), nullable=True)
    invoice_id: Mapped[int | None] = mapped_column(
        ForeignKey("invoice.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    invoice_date: Mapped[date | None] = mapped_column(nullable=True)
    client_paid_date: Mapped[date | None] = mapped_column(nullable=True)
    disbursement_date: Mapped[date | None] = mapped_column(nullable=True)
    transaction_number: Mapped[str | None] = mapped_column(String(100), nullable=True)

    user: Mapped[User] = relationship(back_populates="time_entries")
    task: Mapped[Task] = relationship(back_populates="time_entries")
    subtask: Mapped[Subtask | None] = relationship(back_populates="time_entries")
    invoice: Mapped[Invoice | None] = relationship(
        back_populates="current_entries", foreign_keys=[invoice_id]
    )
    invoice_lines: Mapped[list[InvoiceLine]] = relationship(back_populates="entry")

    @property
    def contract(self) -> Contract:
        return self.task.contract


class Invoice(Base):
    """Permanent invoice snapshot and its persisted PDF representation."""

    __tablename__ = "invoice"
    __table_args__ = (
        CheckConstraint("client_id BETWEEN 1 AND 999", name="ck_invoice_client_id"),
        CheckConstraint("contract_id BETWEEN 1 AND 999", name="ck_invoice_contract_id"),
        CheckConstraint(
            "project_sequence BETWEEN 1 AND 999", name="ck_invoice_sequence"
        ),
        CheckConstraint(
            "status IN ('UNPAID', 'PAID', 'VOID')", name="ck_invoice_status"
        ),
        CheckConstraint("range_end_utc > range_start_utc", name="ck_invoice_range"),
        CheckConstraint("hourly_rate_cents >= 0", name="ck_invoice_rate"),
        CheckConstraint("total_seconds >= 0", name="ck_invoice_total_seconds"),
        CheckConstraint("total_cents >= 0", name="ck_invoice_total_cents"),
        CheckConstraint(
            "(status = 'PAID' AND paid_date IS NOT NULL) OR "
            "(status != 'PAID' AND paid_date IS NULL)",
            name="ck_invoice_paid_date",
        ),
        Index("uq_invoice_number", "invoice_number", unique=True),
        Index(
            "uq_invoice_contract_sequence",
            "contract_id",
            "project_sequence",
            unique=True,
        ),
        Index("ix_invoice_contract_issued", "contract_id", "issued_at", "id"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("client.id", ondelete="RESTRICT"))
    contract_id: Mapped[int] = mapped_column(
        ForeignKey("contract.id", ondelete="RESTRICT")
    )
    project_sequence: Mapped[int] = mapped_column(Integer)
    invoice_number: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="UNPAID")
    issued_at: Mapped[datetime] = mapped_column(DateTime)
    range_start_utc: Mapped[datetime] = mapped_column(DateTime)
    range_end_utc: Mapped[datetime] = mapped_column(DateTime)
    timezone_name: Mapped[str] = mapped_column(String(100))
    client_name: Mapped[str] = mapped_column(String(200))
    project_name: Mapped[str] = mapped_column(String(200))
    contact_name: Mapped[str] = mapped_column(String(200))
    contact_email: Mapped[str] = mapped_column(String(255))
    hourly_rate_cents: Mapped[int] = mapped_column(Integer)
    payment_terms_days: Mapped[int] = mapped_column(Integer)
    total_seconds: Mapped[int] = mapped_column(Integer)
    total_cents: Mapped[int] = mapped_column(Integer)
    due_date: Mapped[date] = mapped_column()
    paid_date: Mapped[date | None] = mapped_column(nullable=True)
    refunded: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    pdf_version: Mapped[int] = mapped_column(Integer, default=2, server_default="2")
    worker_summary_json: Mapped[str] = mapped_column(
        Text, default="[]", server_default="[]"
    )
    pdf_bytes: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)

    client: Mapped[Client] = relationship(back_populates="invoices")
    contract: Mapped[Contract] = relationship(back_populates="invoices")
    lines: Mapped[list[InvoiceLine]] = relationship(
        back_populates="invoice", order_by="InvoiceLine.id"
    )
    current_entries: Mapped[list[TimeEntry]] = relationship(
        back_populates="invoice", foreign_keys=[TimeEntry.invoice_id]
    )

    @property
    def display_status(self) -> str:
        return "REFUNDED" if self.refunded else self.status


class InvoiceLine(Base):
    """Immutable time-entry details captured when an invoice is generated."""

    __tablename__ = "invoice_line"
    __table_args__ = (
        CheckConstraint("total_seconds >= 0", name="ck_invoice_line_seconds"),
        Index("ix_invoice_line_invoice", "invoice_id", "id"),
        Index("ix_invoice_line_entry", "time_entry_id"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    invoice_id: Mapped[int] = mapped_column(
        ForeignKey("invoice.id", ondelete="RESTRICT")
    )
    time_entry_id: Mapped[int] = mapped_column(
        ForeignKey("time_entry.id", ondelete="RESTRICT")
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user_account.id", ondelete="RESTRICT")
    )
    worker_name: Mapped[str] = mapped_column(String(201))
    task_name: Mapped[str] = mapped_column(String(200))
    subtask_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    started_at_utc: Mapped[datetime] = mapped_column(DateTime)
    stopped_at_utc: Mapped[datetime] = mapped_column(DateTime)
    total_seconds: Mapped[int] = mapped_column(Integer)
    started_before_range: Mapped[bool] = mapped_column(Boolean, default=False)

    invoice: Mapped[Invoice] = relationship(back_populates="lines")
    entry: Mapped[TimeEntry] = relationship(back_populates="invoice_lines")


class Disbursement(Base):
    """Independent worker balance transaction with reversible archival."""

    __tablename__ = "disbursement"
    __table_args__ = (
        CheckConstraint("amount_cents > 0", name="ck_disbursement_amount"),
        CheckConstraint(
            "type IN ('DISBURSEMENT', 'IN_KIND', 'RETAINED_EARNINGS')",
            name="ck_disbursement_type",
        ),
        CheckConstraint(
            "(type = 'RETAINED_EARNINGS' AND transaction_id IS NULL) OR "
            "(type != 'RETAINED_EARNINGS' AND transaction_id IS NOT NULL "
            "AND length(trim(transaction_id)) > 0)",
            name="ck_disbursement_transaction_id",
        ),
        Index("ix_disbursement_user_date", "user_id", "date", "id"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user_account.id", ondelete="RESTRICT")
    )
    date: Mapped[date] = mapped_column()
    transaction_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    type: Mapped[str] = mapped_column(String(24))
    amount_cents: Mapped[int] = mapped_column(Integer)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    archived_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("user_account.id", ondelete="RESTRICT"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime)
    created_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("user_account.id", ondelete="RESTRICT")
    )

    user: Mapped[User] = relationship(
        back_populates="disbursements", foreign_keys=[user_id]
    )


class ApplicationMetadata(Base):
    __tablename__ = "application_metadata"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class PasskeyIdentity(Base):
    """Stable random WebAuthn user handle isolated from account identifiers."""

    __tablename__ = "passkey_identity"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("user_account.id", ondelete="CASCADE"), primary_key=True
    )
    user_handle: Mapped[bytes] = mapped_column(LargeBinary(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)

    user: Mapped[User] = relationship(back_populates="passkey_identity")


class PasskeyCredential(Base):
    """One public WebAuthn credential registered by an application user."""

    __tablename__ = "passkey_credential"
    __table_args__ = (
        CheckConstraint("sign_count >= 0", name="ck_passkey_sign_count"),
        CheckConstraint("length(trim(name)) > 0", name="ck_passkey_name"),
        CheckConstraint("length(trim(rp_id)) > 0", name="ck_passkey_rp_id"),
        Index("ix_passkey_credential_user", "user_id"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user_account.id", ondelete="CASCADE")
    )
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    device_type: Mapped[str] = mapped_column(String(32))
    backed_up: Mapped[bool] = mapped_column(Boolean, default=False)
    aaguid: Mapped[str] = mapped_column(String(36))
    name: Mapped[str] = mapped_column(String(100))
    rp_id: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="passkeys")


class WebAuthnChallenge(Base):
    """Single-use, expiring, session-bound state for one WebAuthn ceremony."""

    __tablename__ = "webauthn_challenge"
    __table_args__ = (
        CheckConstraint(
            "ceremony IN ('registration', 'authentication', 'reauthentication')",
            name="ck_webauthn_challenge_ceremony",
        ),
        Index("ix_webauthn_challenge_expires", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    challenge: Mapped[bytes] = mapped_column(LargeBinary(64))
    ceremony: Mapped[str] = mapped_column(String(24))
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("user_account.id", ondelete="CASCADE"), nullable=True
    )
    session_binding_hash: Mapped[bytes] = mapped_column(LargeBinary(32))
    action_context_hash: Mapped[bytes | None] = mapped_column(
        LargeBinary(32), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class SchemaVersion(Base):
    """Singleton marker for the database schema used by this application build."""

    __tablename__ = "schema_version"
    __table_args__ = (CheckConstraint("id = 1", name="ck_schema_version_singleton"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    version: Mapped[int] = mapped_column(Integer, nullable=False)


class AuditEvent(Base):
    """Immutable, display-safe record of a user, public, or system action."""

    __tablename__ = "audit_event"
    __table_args__ = (
        CheckConstraint(
            "source IN ('admin', 'user', 'public', 'system')",
            name="ck_audit_event_source",
        ),
        CheckConstraint("length(trim(event)) > 0", name="ck_audit_event_name"),
        Index("ix_audit_event_occurred_id", "occurred_at", "id"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime)
    event: Mapped[str] = mapped_column(String(100), index=True)
    source: Mapped[str] = mapped_column(String(16), index=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True, index=True
    )
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_name: Mapped[str | None] = mapped_column(String(201), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    method: Mapped[str | None] = mapped_column(String(8), nullable=True)
    path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")

    @property
    def details(self) -> dict[str, Any]:
        """Return the validated structured details stored with the event."""
        try:
            value = json.loads(self.details_json)
        except (TypeError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}
