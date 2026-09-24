"""Shared presentation summaries for invoice snapshots and their PDFs."""

from collections.abc import Sequence
from datetime import UTC, date, timedelta
from decimal import ROUND_HALF_UP, Decimal
from zoneinfo import ZoneInfo

from .invoice_time import daily_billable_hours
from .models import Invoice, InvoiceLine


def daily_summary_rows(
    invoice: Invoice, lines: Sequence[InvoiceLine], timezone: ZoneInfo
) -> list[tuple[date, Decimal | None]]:
    """Include worked days and empty weekdays within the invoice range."""
    worked_hours = dict(daily_billable_hours(lines, timezone))
    shown_days = set(worked_hours)
    current_day = (
        invoice.range_start_utc.replace(tzinfo=UTC).astimezone(timezone).date()
    )
    final_day = (
        (invoice.range_end_utc - timedelta(microseconds=1))
        .replace(tzinfo=UTC)
        .astimezone(timezone)
        .date()
    )
    while current_day <= final_day:
        if current_day.weekday() < 5:
            shown_days.add(current_day)
        current_day += timedelta(days=1)
    return [(day, worked_hours.get(day)) for day in sorted(shown_days)]


def worker_summary_rows(
    lines: Sequence[InvoiceLine],
) -> list[tuple[str, Decimal]]:
    """Group immutable session snapshots by worker, including void invoices."""
    totals: dict[int, tuple[str, int]] = {}
    for line in lines:
        name, seconds = totals.get(line.user_id, (line.worker_name, 0))
        totals[line.user_id] = (name, seconds + line.total_seconds)
    return [
        (
            name,
            (Decimal(seconds) / Decimal(3600)).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            ),
        )
        for name, seconds in totals.values()
    ]
