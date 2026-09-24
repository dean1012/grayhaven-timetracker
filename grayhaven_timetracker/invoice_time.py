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


class InvoiceTime(Protocol):
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
        (
            day,
            (Decimal(seconds) / Decimal(3600)).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            ),
        )
        for day, seconds in daily_seconds(lines, timezone)
    ]


def total_billable_hours(lines: Sequence[InvoiceTime], timezone: ZoneInfo) -> Decimal:
    return sum(
        (hours for _, hours in daily_billable_hours(lines, timezone)), Decimal("0.00")
    )
