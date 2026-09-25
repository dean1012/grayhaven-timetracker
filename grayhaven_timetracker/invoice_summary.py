"""Shared presentation summaries for invoice snapshots and their PDFs."""

import json
from collections.abc import Sequence
from datetime import UTC, date, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any
from zoneinfo import ZoneInfo

from .invoice_time import daily_billable_hours, worker_daily_billable_hours
from .models import Invoice, InvoiceLine


def build_worker_summary_json(
    invoice: Invoice, lines: Sequence[InvoiceLine], timezone: ZoneInfo
) -> str:
    """Freeze rounded worker-day rows and worker amounts with the invoice."""
    grouped: dict[int, list[InvoiceLine]] = {}
    for line in lines:
        grouped.setdefault(line.user_id, []).append(line)
    records = []
    for user_id, selected in grouped.items():
        days = daily_summary_rows(invoice, selected, timezone)
        hours = sum((value for _, value in days if value is not None), Decimal(0))
        cents = int(
            (hours * Decimal(invoice.hourly_rate_cents)).quantize(
                Decimal("1"), rounding=ROUND_HALF_UP
            )
        )
        records.append(
            {
                "user_id": user_id,
                "worker_name": selected[0].worker_name,
                "amount_cents": cents,
                "days": [
                    [day.isoformat(), str(value) if value is not None else None]
                    for day, value in days
                ],
            }
        )
    return json.dumps(records, separators=(",", ":"))


def worker_snapshot_records(invoice: Invoice) -> list[dict[str, Any]]:
    """Read the issued worker totals without recalculating historic invoices."""
    records = json.loads(invoice.worker_summary_json)
    if not isinstance(records, list) or (
        invoice.id is not None and invoice.pdf_version >= 2 and not records
    ):
        raise ValueError("Invoice worker snapshot is invalid.")
    return records


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
    timezone: ZoneInfo,
) -> list[tuple[str, Decimal]]:
    """Sum each worker's rounded daily billable hours."""
    names: dict[int, str] = {}
    for line in lines:
        names.setdefault(line.user_id, line.worker_name)
    days = worker_daily_billable_hours(lines, timezone)
    return [
        (name, sum((hours for _, hours in days[user_id]), Decimal("0.00")))
        for user_id, name in names.items()
    ]


def worker_daily_summary_rows(
    invoice: Invoice, lines: Sequence[InvoiceLine], timezone: ZoneInfo
) -> list[tuple[str, list[tuple[date, Decimal | None]]]]:
    """Return a separate day table for each invoiced worker."""
    if invoice.worker_summary_json and invoice.worker_summary_json != "[]":
        return [
            (
                str(record["worker_name"]),
                [
                    (date.fromisoformat(day), Decimal(hours) if hours else None)
                    for day, hours in record["days"]
                ],
            )
            for record in worker_snapshot_records(invoice)
        ]
    else:  # pragma: no cover - only used to render legacy invoices during migration
        worker_lines: dict[int, list[InvoiceLine]] = {}
        worker_names: dict[int, str] = {}
        for line in lines:
            worker_lines.setdefault(line.user_id, []).append(line)
            worker_names.setdefault(line.user_id, line.worker_name)
        rows: list[tuple[str, list[tuple[date, Decimal | None]]]] = []
        for user_id, selected in worker_lines.items():
            daily_rows = daily_summary_rows(invoice, selected, timezone)
            rows.append((worker_names[user_id], daily_rows))
        return rows
