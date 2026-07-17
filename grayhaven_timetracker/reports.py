"""Shared client report aggregation and display formatting."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_FLOOR, ROUND_HALF_UP, Decimal
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .models import Client, Contract, Task, TimeEntry

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
    """Allocate cents so session costs reconcile to their containing group."""
    if not durations:
        return ()
    exact_cents = [
        Decimal(seconds * hourly_rate_cents) / Decimal(3600) for seconds in durations
    ]
    allocated_cents = [
        int(value.to_integral_value(rounding=ROUND_FLOOR)) for value in exact_cents
    ]
    target_cents = int(calculate_cost(sum(durations), hourly_rate_cents) * 100)
    priority = sorted(
        range(len(durations)),
        key=lambda index: (-(exact_cents[index] - allocated_cents[index]), index),
    )
    for index in priority[: target_cents - sum(allocated_cents)]:
        allocated_cents[index] += 1
    return tuple(Decimal(cents) / Decimal(100) for cents in allocated_cents)


def format_duration(seconds: int) -> str:
    """Format seconds as hours, minutes, and seconds."""
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}"


def format_datetime(value: datetime, display_timezone: ZoneInfo) -> str:
    """Format a stored UTC timestamp in the configured reporting timezone."""
    localized = value.replace(tzinfo=UTC).astimezone(display_timezone)
    return localized.strftime("%Y-%m-%d %I:%M:%S %p %Z")


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
        .where(Task.contract_id == contract.id)
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
        )
        for index, item in enumerate(session_data)
    )
    groups = tuple(
        ReportGroup(
            label=label,
            seconds=seconds,
            cost=calculate_cost(seconds, contract.hourly_rate_cents),
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
        .where(Contract.client_id == client.id)
        .options(joinedload(Contract.client))
        .order_by(Contract.created_at.desc(), Contract.id.desc())
    ).all()
    sections = [
        build_contract_report(
            database, contract, display_timezone, snapshot_at=generated_at
        )
        for contract in contracts
    ]
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


