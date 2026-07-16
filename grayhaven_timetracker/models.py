"""Relational models for application data and its append-only audit trail."""

from __future__ import annotations

import json
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all application models."""


class User(Base):
    __tablename__ = "user_account"
    __table_args__ = (
        CheckConstraint("role IN ('admin', 'user')", name="ck_user_role"),
        CheckConstraint("length(trim(email)) > 3", name="ck_user_email"),
        CheckConstraint("length(trim(first_name)) > 0", name="ck_user_first_name"),
        CheckConstraint("length(trim(last_name)) > 0", name="ck_user_last_name"),
        CheckConstraint("session_version >= 1", name="ck_user_session_version"),
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
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    password_change_required: Mapped[bool] = mapped_column(Boolean, default=False)
    session_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime)

    time_entries: Mapped[list[TimeEntry]] = relationship(back_populates="user")

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
        Index(
            "uq_client_report_token_hash",
            "report_token_hash",
            unique=True,
            sqlite_where=text("report_token_hash IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    contact_name: Mapped[str] = mapped_column(String(200))
    contact_email: Mapped[str] = mapped_column(String(255))
    report_password_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    report_password_version: Mapped[int] = mapped_column(Integer, default=1)
    report_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    report_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    contracts: Mapped[list[Contract]] = relationship(
        back_populates="client", order_by=lambda: Contract.id.desc()
    )


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
        Index(
            "uq_contract_report_token_hash",
            "report_token_hash",
            unique=True,
            sqlite_where=text("report_token_hash IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("client.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(200))
    contact_name: Mapped[str] = mapped_column(String(200))
    contact_email: Mapped[str] = mapped_column(String(255))
    hourly_rate_cents: Mapped[int] = mapped_column(Integer)
    report_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    report_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    client: Mapped[Client] = relationship(back_populates="contracts")
    tasks: Mapped[list[Task]] = relationship(
        back_populates="contract", order_by="Task.id"
    )

    @property
    def hourly_rate(self) -> Decimal:
        return Decimal(self.hourly_rate_cents) / Decimal(100)


class Task(Base):
    __tablename__ = "task"
    __table_args__ = (CheckConstraint("length(trim(name)) > 0", name="ck_task_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    contract_id: Mapped[int] = mapped_column(
        ForeignKey("contract.id", ondelete="RESTRICT"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))

    contract: Mapped[Contract] = relationship(back_populates="tasks")
    subtasks: Mapped[list[Subtask]] = relationship(
        back_populates="task", cascade="all, delete-orphan", order_by="Subtask.id"
    )
    time_entries: Mapped[list[TimeEntry]] = relationship(back_populates="task")


class Subtask(Base):
    __tablename__ = "subtask"
    __table_args__ = (
        CheckConstraint("length(trim(name)) > 0", name="ck_subtask_name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("task.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))

    task: Mapped[Task] = relationship(back_populates="subtasks")
    time_entries: Mapped[list[TimeEntry]] = relationship(back_populates="subtask")


class TimeEntry(Base):
    __tablename__ = "time_entry"
    __table_args__ = (
        CheckConstraint(
            "stopped_at IS NULL OR stopped_at >= started_at",
            name="ck_time_entry_order",
        ),
        Index(
            "uq_active_timer_per_user",
            "user_id",
            unique=True,
            sqlite_where=text("stopped_at IS NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
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

    user: Mapped[User] = relationship(back_populates="time_entries")
    task: Mapped[Task] = relationship(back_populates="time_entries")
    subtask: Mapped[Subtask | None] = relationship(back_populates="time_entries")

    @property
    def contract(self) -> Contract:
        return self.task.contract


class ApplicationMetadata(Base):
    __tablename__ = "application_metadata"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


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
