"""Shared client report aggregation and display formatting."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Any
from zoneinfo import ZoneInfo

from markupsafe import Markup
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, joinedload, selectinload

from .invoices import invoice_total_cents
from .models import Client, Contract, Invoice, Task, TimeEntry

MONEY_QUANTUM = Decimal("0.01")


@dataclass(frozen=True)
class ReportSession:
    """One immutable session row at the report snapshot time."""

    user_name: str
    label: str
    started_at: datetime
    ended_at: datetime
    seconds: int
    cost: Decimal
    active: bool
    billing_status: str


@dataclass(frozen=True)
class ReportGroup:
    """Aggregated duration and cost for one task or subtask label."""

    label: str
    seconds: int
    cost: Decimal


@dataclass(frozen=True)
class ContractReport:
    """Complete contract report representation for live HTML output."""

    contract: Contract
    generated_at: datetime
    timezone: ZoneInfo
    sessions: tuple[ReportSession, ...]
    groups: tuple[ReportGroup, ...]
    total_seconds: int
    total_cost: Decimal


@dataclass(frozen=True)
class ClientReport:
    """Client-wide report composed of consistently ordered contract sections."""

    client: Client
    generated_at: datetime
    timezone: ZoneInfo
    contracts: tuple[ContractReport, ...]
    total_seconds: int
    total_cost: Decimal


def utc_now() -> datetime:
    """Return the current UTC instant as a naive, second-precision value."""
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def duration_seconds(started_at: datetime, ended_at: datetime) -> int:
    """Return a non-negative elapsed duration."""
    return max(0, int((ended_at - started_at).total_seconds()))


def calculate_cost(seconds: int, hourly_rate_cents: int) -> Decimal:
    """Calculate a rounded dollar cost for a duration at a contract rate."""
    dollars = Decimal(seconds * hourly_rate_cents) / Decimal(360000)
    return dollars.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def allocate_session_costs(
    durations: list[int], hourly_rate_cents: int
) -> tuple[Decimal, ...]:
    """Round each session independently, so grouping never changes its price."""
    return tuple(calculate_cost(seconds, hourly_rate_cents) for seconds in durations)


def invoice_entry_costs(database: Session, invoice_ids: set[int]) -> dict[int, Decimal]:
    """Allocate frozen invoice cents consistently across every claimed entry."""
    if not invoice_ids:
        return {}
    invoices = database.scalars(
        select(Invoice)
        .where(Invoice.id.in_(invoice_ids), Invoice.status != "VOID")
        .options(selectinload(Invoice.lines))
    ).all()
    result: dict[int, Decimal] = {}
    for invoice in invoices:
        by_worker: dict[int, list[Any]] = {}
        for line in invoice.lines:
            by_worker.setdefault(line.user_id, []).append(line)
        for worker_lines in by_worker.values():
            worker_seconds = sum(line.total_seconds for line in worker_lines)
            worker_cents = invoice_total_cents(
                worker_lines,
                ZoneInfo(invoice.timezone_name),
                invoice.hourly_rate_cents,
            )
            if worker_seconds == 0:
                result.update((line.time_entry_id, Decimal(0)) for line in worker_lines)
                continue
            amounts: dict[int, int] = {}
            remainders: list[tuple[int, int, int]] = []
            for line in worker_lines:
                cents, remainder = divmod(
                    worker_cents * line.total_seconds, worker_seconds
                )
                amounts[line.time_entry_id] = cents
                remainders.append((remainder, line.id, line.time_entry_id))
            residual = worker_cents - sum(amounts.values())
            for _, _, entry_id in sorted(remainders, key=lambda row: (-row[0], row[1]))[
                :residual
            ]:
                amounts[entry_id] += 1
            result.update(
                (entry_id, Decimal(cents) / 100) for entry_id, cents in amounts.items()
            )
    return result


def format_duration(seconds: int) -> str:
    """Format seconds as hours, minutes, and seconds."""
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}"


def format_datetime(value: datetime, display_timezone: ZoneInfo) -> str:
    """Format a stored UTC timestamp in the configured reporting timezone."""
    localized = value.replace(tzinfo=UTC).astimezone(display_timezone)
    return localized.strftime("%Y-%m-%d %I:%M:%S %p %Z")


def format_datetime_html(value: datetime, display_timezone: ZoneInfo) -> Markup:
    """Display the date above the time and timezone throughout HTML views."""
    date, time = format_datetime(value, display_timezone).split(" ", 1)
    return Markup(
        '<time class="display-datetime" datetime="{}">{}<br>{}</time>'
    ).format(value.replace(tzinfo=UTC).isoformat(), date, time)


def format_money(value: Decimal) -> str:
    """Format a dollar amount for the application UI and reports."""
    return f"${value:,.2f}"


def report_state_etag(report: ContractReport | ClientReport) -> str:
    """Fingerprint report structure while excluding a running timer's age."""
    sections = (report,) if isinstance(report, ContractReport) else report.contracts
    client = (
        report.contract.client if isinstance(report, ContractReport) else report.client
    )
    state = {
        "client": [client.id, client.name],
        "contracts": [
            {
                "contract": [
                    section.contract.id,
                    section.contract.name,
                    section.contract.hourly_rate_cents,
                ],
                "sessions": [
                    [
                        item.user_name,
                        item.label,
                        item.started_at.isoformat(),
                        None if item.active else item.ended_at.isoformat(),
                        item.billing_status,
                    ]
                    for item in section.sessions
                ],
            }
            for section in sections
        ],
    }
    return hashlib.sha256(
        json.dumps(
            state, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode()
    ).hexdigest()


def build_contract_report(
    database: Session,
    contract: Contract,
    display_timezone: str,
    *,
    snapshot_at: datetime | None = None,
) -> ContractReport:
    """Snapshot one contract's sessions and reconcile grouped billing totals."""
    generated_at = snapshot_at or utc_now()
    timezone_info = ZoneInfo(display_timezone)
    entries = database.scalars(
        select(TimeEntry)
        .join(TimeEntry.task)
        .where(
            Task.contract_id == contract.id,
            or_(
                TimeEntry.stopped_at.is_(None),
                TimeEntry.billing_status == "pending_invoice",
            ),
        )
        .options(
            joinedload(TimeEntry.user),
            joinedload(TimeEntry.task),
            joinedload(TimeEntry.subtask),
        )
        .order_by(TimeEntry.started_at, TimeEntry.id)
    ).all()
    group_seconds: dict[str, int] = {}
    group_session_indexes: dict[str, list[int]] = {}
    session_data: list[tuple[str, str, datetime, datetime, int, bool]] = []
    for entry in entries:
        ended_at = entry.stopped_at or max(generated_at, entry.started_at)
        seconds = duration_seconds(entry.started_at, ended_at)
        label = (
            f"{entry.task.name} → {entry.subtask.name}"
            if entry.subtask
            else entry.task.name
        )
        group_seconds[label] = group_seconds.get(label, 0) + seconds
        group_session_indexes.setdefault(label, []).append(len(session_data))
        session_data.append(
            (
                entry.user.full_name,
                label,
                entry.started_at,
                ended_at,
                seconds,
                entry.stopped_at is None,
            )
        )
    session_costs = [Decimal(0)] * len(session_data)
    for indexes in group_session_indexes.values():
        costs = allocate_session_costs(
            [session_data[index][4] for index in indexes],
            contract.hourly_rate_cents,
        )
        for index, cost in zip(indexes, costs, strict=True):
            session_costs[index] = cost
    sessions = tuple(
        ReportSession(
            user_name=item[0],
            label=item[1],
            started_at=item[2],
            ended_at=item[3],
            seconds=item[4],
            cost=session_costs[index],
            active=item[5],
            billing_status="pending_invoice",
        )
        for index, item in enumerate(session_data)
    )
    groups = tuple(
        ReportGroup(
            label=label,
            seconds=seconds,
            cost=sum(
                (session_costs[index] for index in group_session_indexes[label]),
                Decimal(0),
            ),
        )
        for label, seconds in group_seconds.items()
    )
    return ContractReport(
        contract=contract,
        generated_at=generated_at,
        timezone=timezone_info,
        sessions=sessions,
        groups=groups,
        total_seconds=sum(group.seconds for group in groups),
        total_cost=sum((group.cost for group in groups), Decimal(0)),
    )


def build_client_report(
    database: Session,
    client: Client,
    display_timezone: str,
    *,
    snapshot_at: datetime | None = None,
) -> ClientReport:
    """Build a client report ordered by active work, activity, then creation."""
    generated_at = snapshot_at or utc_now()
    contracts = database.scalars(
        select(Contract)
        .where(Contract.client_id == client.id, Contract.archived_at.is_(None))
        .options(joinedload(Contract.client))
        .order_by(Contract.created_at.desc(), Contract.id.desc())
    ).all()
    sections = [
        build_contract_report(
            database, contract, display_timezone, snapshot_at=generated_at
        )
        for contract in contracts
    ]
    sections = [section for section in sections if section.sessions]
    sections.sort(
        key=lambda section: (
            not any(session.active for session in section.sessions),
            -max(
                (
                    (
                        session.ended_at if not session.active else generated_at
                    ).timestamp()
                    for session in section.sessions
                ),
                default=float("-inf"),
            ),
            -(
                section.contract.created_at.timestamp()
                if section.contract.created_at is not None
                else float("-inf")
            ),
            -section.contract.id,
        )
    )
    return ClientReport(
        client=client,
        generated_at=generated_at,
        timezone=ZoneInfo(display_timezone),
        contracts=tuple(sections),
        total_seconds=sum(section.total_seconds for section in sections),
        total_cost=sum((section.total_cost for section in sections), Decimal(0)),
    )
