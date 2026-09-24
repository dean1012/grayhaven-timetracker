"""Shared invoice calendar-day allocation and billable-hour rounding."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Protocol
from zoneinfo import ZoneInfo


@dataclass(frozen=True)
class TimeSpan:
    """An exact elapsed-time snapshot for calendar-day allocation."""

    started_at_utc: datetime
    stopped_at_utc: datetime
    total_seconds: int
    user_id: int = 0


class InvoiceTime(Protocol):
    @property
    def user_id(self) -> int: ...

    @property
    def started_at_utc(self) -> datetime: ...

    @property
    def stopped_at_utc(self) -> datetime: ...

    @property
    def total_seconds(self) -> int: ...


def daily_seconds(
    lines: Sequence[InvoiceTime], timezone: ZoneInfo
) -> list[tuple[date, int]]:
    totals: dict[date, int] = {}
    for line in lines:
        start = line.started_at_utc.replace(tzinfo=UTC)
        stop = line.stopped_at_utc.replace(tzinfo=UTC)
        cursor = start
        allocated = 0
        while cursor < stop:
            day = cursor.astimezone(timezone).date()
            midnight = datetime.combine(
                day + timedelta(days=1), time.min, tzinfo=timezone
            ).astimezone(UTC)
            end = min(midnight, stop)
            # Cumulative truncation preserves the single per-entry second floor.
            elapsed = min(line.total_seconds, int((end - start).total_seconds()))
            seconds = elapsed - allocated
            if seconds:
                totals[day] = totals.get(day, 0) + seconds
            allocated = elapsed
            cursor = end
    return sorted(totals.items())


def daily_billable_hours(
    lines: Sequence[InvoiceTime], timezone: ZoneInfo
) -> list[tuple[date, Decimal]]:
    return [
        (day, rounded_quarter_hours(seconds))
        for day, seconds in daily_seconds(lines, timezone)
    ]


def rounded_quarter_hours(seconds: int) -> Decimal:
    """Round elapsed seconds to the nearest quarter hour, with ties upward."""
    if seconds < 0:
        raise ValueError("Billable time cannot be negative")
    quarters = (Decimal(seconds) / Decimal(900)).quantize(
        Decimal("1"), rounding=ROUND_HALF_UP
    )
    return quarters / Decimal(4)


def worker_daily_billable_hours(
    lines: Sequence[InvoiceTime], timezone: ZoneInfo
) -> dict[int, list[tuple[date, Decimal]]]:
    """Round each worker's accumulated time for each local calendar day."""
    grouped: dict[int, list[InvoiceTime]] = {}
    for line in lines:
        grouped.setdefault(line.user_id, []).append(line)
    return {
        user_id: daily_billable_hours(worker_lines, timezone)
        for user_id, worker_lines in grouped.items()
    }


def total_billable_hours(lines: Sequence[InvoiceTime], timezone: ZoneInfo) -> Decimal:
    return sum(
        (
            hours
            for days in worker_daily_billable_hours(lines, timezone).values()
            for _, hours in days
        ),
        Decimal("0.00"),
    )
