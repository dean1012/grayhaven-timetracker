"""Contract report calculation and PDF rendering tests."""

from __future__ import annotations

import re
import unittest
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from zoneinfo import ZoneInfo

from PIL import Image as PillowImage
from sqlalchemy import select

from grayhaven_timetracker.database import session_scope
from grayhaven_timetracker.models import Client, Contract, Task, TimeEntry, User
from grayhaven_timetracker.reports import (
    allocate_session_costs,
    build_client_report,
    build_contract_report,
    build_pdf,
    calculate_cost,
    duration_seconds,
    format_datetime,
    format_duration,
    format_money,
    report_state_etag,
)
from tests.helpers import ADMIN_EMAIL, AppTestCase


def pdf_page_count(data: bytes) -> int:
    """Count PDF page objects without introducing another runtime dependency."""
    return len(re.findall(rb"/Type\s*/Page(?!s)\b", data))


class FormattingTests(AppTestCase):
    def test_duration_money_and_timezone_formatting(self) -> None:
        self.assertEqual(format_duration(0), "0:00:00")
        self.assertEqual(format_duration(3661), "1:01:01")
        self.assertEqual(format_duration(100 * 3600 + 2), "100:00:02")
        self.assertEqual(format_money(Decimal("1222.3")), "$1,222.30")
        self.assertEqual(
            format_datetime(
                datetime(2026, 7, 15, 5, 4, 32), ZoneInfo("America/Chicago")
            ),
            "2026-07-15 12:04:32 AM CDT",
        )

    def test_duration_and_cost_clamp_or_round_as_expected(self) -> None:
        start = datetime(2026, 7, 15, 12, 0, 0)
        self.assertEqual(duration_seconds(start, start - timedelta(seconds=1)), 0)
        self.assertEqual(duration_seconds(start, start + timedelta(seconds=7)), 7)
        self.assertEqual(calculate_cost(3600, 5500), Decimal("55.00"))
        self.assertEqual(calculate_cost(3, 5500), Decimal("0.05"))

    def test_allocated_session_costs_reconcile_with_group_cost(self) -> None:
        costs = allocate_session_costs([5083, 3], 5500)
        self.assertEqual(costs, (Decimal("77.66"), Decimal("0.04")))
        self.assertEqual(sum(costs), calculate_cost(5086, 5500))
        self.assertEqual(allocate_session_costs([], 5500), ())
        self.assertEqual(allocate_session_costs([0], 5500), (Decimal("0"),))


class ContractReportTests(AppTestCase):
    def test_client_report_contains_newest_contracts_and_aggregate_totals(self) -> None:
        seed = self.seed_contract()
        with session_scope(self.app) as database:
            client = database.get(Client, seed.client_id)
            assert client is not None
            newer = Contract(
                client=client,
                name="Newest Contract",
                contact_name="Contact",
                contact_email="contact@example.invalid",
                hourly_rate_cents=6500,
            )
            database.add(newer)
            database.flush()
            report = build_client_report(
                database,
                client,
                "America/Chicago",
                snapshot_at=datetime(2026, 7, 15, 5, 0, 0),
            )
            self.assertEqual(
                [item.contract.name for item in report.contracts],
                [
                    "Hamilton Beach - Phase 1",
                    "Newest Contract",
                ],
            )
            self.assertEqual(
                report.total_seconds,
                sum(item.total_seconds for item in report.contracts),
            )
            self.assertEqual(
                report.total_cost,
                sum(item.total_cost for item in report.contracts),
            )

    def test_report_groups_sessions_and_snapshots_active_timers(self) -> None:
        seed = self.seed_contract()
        snapshot = datetime(2026, 7, 15, 5, 0, 0)
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            contract = database.get(Contract, seed.contract_id)
            task = database.get(Task, seed.task_id)
            assert admin and contract and task
            database.add(
                active_entry := TimeEntry(
                    user=admin,
                    task=task,
                    started_at=snapshot - timedelta(seconds=3),
                    stopped_at=None,
                ),
            )
            database.flush()
            report = build_contract_report(
                database,
                contract,
                "America/Chicago",
                snapshot_at=snapshot,
            )
            self.assertEqual(len(report.sessions), 2)
            self.assertTrue(report.sessions[-1].active)
            self.assertEqual(report.sessions[-1].ended_at, snapshot)
            self.assertEqual(report.total_seconds, 3610)
            self.assertEqual(
                report.total_cost, sum(group.cost for group in report.groups)
            )
            pdf = build_pdf(
                report,
                self.root / "missing-branding",
                "https://example.invalid/contact",
            ).getvalue()
            self.assertTrue(pdf.startswith(b"%PDF-"))
            self.assertIsNone(active_entry.stopped_at)

    def test_report_etag_changes_only_when_visible_report_state_changes(self) -> None:
        seed = self.seed_contract()
        snapshot = datetime(2026, 7, 15, 5, 0, 0)
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            contract = database.get(Contract, seed.contract_id)
            task = database.get(Task, seed.task_id)
            assert admin and contract and task
            active_entry = TimeEntry(
                user=admin,
                task=task,
                started_at=snapshot - timedelta(seconds=3),
            )
            database.add(active_entry)
            database.flush()
            first = build_contract_report(
                database, contract, "America/Chicago", snapshot_at=snapshot
            )
            later = build_contract_report(
                database,
                contract,
                "America/Chicago",
                snapshot_at=snapshot + timedelta(seconds=30),
            )
            self.assertEqual(report_state_etag(first), report_state_etag(later))

            active_entry.stopped_at = snapshot + timedelta(seconds=20)
            database.flush()
            stopped = build_contract_report(
                database,
                contract,
                "America/Chicago",
                snapshot_at=snapshot + timedelta(seconds=30),
            )
            self.assertNotEqual(report_state_etag(first), report_state_etag(stopped))

    def test_empty_report_has_zero_totals(self) -> None:
        with session_scope(self.app) as database:
            client = Client(
                name="Empty Client",
                contact_name="Contact",
                contact_email="contact@example.invalid",
            )
            contract = Contract(
                client=client,
                name="Empty Contract",
                contact_name="Contact",
                contact_email="contact@example.invalid",
                hourly_rate_cents=5500,
            )
            database.add(client)
            database.flush()
            report = build_contract_report(database, contract, "America/Chicago")
            self.assertEqual(report.sessions, ())
            self.assertEqual(report.groups, ())
            self.assertEqual(report.total_seconds, 0)
            self.assertEqual(report.total_cost, Decimal("0"))


class PdfTests(AppTestCase):
    def test_pdf_contains_overview_contract_pages_and_clickable_contact_link(
        self,
    ) -> None:
        seed = self.seed_contract()
        branding = self.root / "branding-with-wordmark"
        branding.mkdir()
        PillowImage.new("RGB", (265, 63), "white").save(
            branding / "grayhaven-logo-wordmark-light.png"
        )
        with session_scope(self.app) as database:
            contract = database.get(Contract, seed.contract_id)
            assert contract is not None
            report = build_contract_report(
                database,
                contract,
                "America/Chicago",
                snapshot_at=datetime(2026, 7, 15, 5, 0, 0),
            )
            data = build_pdf(
                report,
                branding,
                "https://example.invalid/contact",
            ).getvalue()
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertEqual(pdf_page_count(data), 3)
        self.assertIn(b"Grayhaven Systems LLC", data)
        self.assertIn(b"https://example.invalid/contact", data)
        self.assertIn(b"/Subtype /Link", data)

    def test_empty_pdf_still_renders_overview_summary_and_detail_pages(self) -> None:
        with session_scope(self.app) as database:
            client = Client(
                name="Empty Client",
                contact_name="Contact",
                contact_email="contact@example.invalid",
            )
            contract = Contract(
                client=client,
                name="Empty Contract",
                contact_name="Contact",
                contact_email="contact@example.invalid",
                hourly_rate_cents=0,
            )
            database.add(client)
            database.flush()
            report = build_contract_report(database, contract, "America/Chicago")
            data = build_pdf(
                report, Path("/missing"), "https://example.invalid/contact"
            ).getvalue()
        self.assertEqual(pdf_page_count(data), 3)

    def test_large_summary_splits_without_layout_errors(self) -> None:
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            client = Client(
                name="Large Client",
                contact_name="Contact",
                contact_email="contact@example.invalid",
            )
            contract = Contract(
                client=client,
                name="Large Contract",
                contact_name="Contact",
                contact_email="contact@example.invalid",
                hourly_rate_cents=5500,
            )
            start = datetime(2026, 7, 15, 12, 0, 0)
            for index in range(40):
                task = Task(contract=contract, name=f"Task {index:02d}")
                database.add(
                    TimeEntry(
                        user=admin,
                        task=task,
                        started_at=start + timedelta(hours=index),
                        stopped_at=start
                        + timedelta(hours=index, minutes=15, seconds=index),
                    )
                )
            database.add(client)
            database.flush()
            report = build_contract_report(database, contract, "America/Chicago")
            data = build_pdf(
                report, Path("/missing"), "https://example.invalid/contact"
            ).getvalue()
        self.assertGreater(pdf_page_count(data), 3)


if __name__ == "__main__":
    unittest.main()
