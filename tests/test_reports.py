"""Billing totals preserve each session's independently rounded amount."""

from datetime import datetime, timedelta
from decimal import Decimal
from unittest import TestCase

from grayhaven_timetracker.database import session_scope
from grayhaven_timetracker.models import Client, Contract, TimeEntry
from grayhaven_timetracker.reports import (
    allocate_session_costs,
    build_client_report,
    build_contract_report,
    calculate_cost,
)
from tests.helpers import AppTestCase


class SessionCostTests(TestCase):
    """Small durations expose rounding differences hidden by whole hours."""

    def test_half_cent_rounds_up(self) -> None:
        self.assertEqual(calculate_cost(18, 100), Decimal("0.01"))
        self.assertEqual(calculate_cost(17, 100), Decimal("0.00"))
        self.assertEqual(calculate_cost(0, 5500), Decimal("0.00"))

    def test_rounding_is_independent_of_other_sessions(self) -> None:
        self.assertEqual(
            allocate_session_costs([60, 60], 5500),
            (Decimal("0.92"), Decimal("0.92")),
        )
        self.assertEqual(
            allocate_session_costs([60, 3600, 60], 5500),
            (Decimal("0.92"), Decimal("55.00"), Decimal("0.92")),
        )
        self.assertEqual(allocate_session_costs([], 5500), ())


class ReportTotalsTests(AppTestCase):
    """Check the public report builders against real stored sessions."""

    def test_rows_groups_and_client_total_use_same_session_amounts(self) -> None:
        first = self.seed_contract()
        with session_scope(self.app) as database:
            first_client = database.get(Client, first.client_id)
            assert first_client is not None
            first_client.name = "Billing Example"
        second = self.seed_contract(entry_user_id=self.create_user().id)
        now = datetime(2026, 9, 7, 12)
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, first.entry_id)
            other_entry = database.get(TimeEntry, second.entry_id)
            contract = database.get(Contract, first.contract_id)
            other_contract = database.get(Contract, second.contract_id)
            client = database.get(Client, first.client_id)
            assert entry and other_entry and contract and other_contract and client
            entry.started_at = now - timedelta(minutes=2)
            entry.stopped_at = now - timedelta(minutes=1)
            sibling = TimeEntry(
                user_id=entry.user_id,
                task_id=entry.task_id,
                subtask_id=entry.subtask_id,
                started_at=now - timedelta(minutes=1),
                stopped_at=now,
            )
            database.add(sibling)
            other_contract.client_id = client.id
            other_contract.public_number = 2
            other_contract.name = "Support"
            other_contract.hourly_rate_cents = 10500
            other_entry.started_at = now - timedelta(minutes=1)
            other_entry.stopped_at = now
            database.flush()

            report = build_contract_report(database, contract, "UTC", snapshot_at=now)
            self.assertEqual(
                [row.cost for row in report.sessions],
                [Decimal("0.92"), Decimal("0.92")],
            )
            self.assertEqual(report.groups[0].cost, Decimal("1.84"))
            self.assertEqual(report.total_cost, Decimal("1.84"))
            self.assertEqual(report.total_seconds, 120)

            # Moving a row to a different task changes grouping, never its cost.
            sibling.task_id = first.other_task_id
            sibling.subtask_id = None
            database.flush()
            database.expire_all()
            regrouped = build_contract_report(
                database, contract, "UTC", snapshot_at=now
            )
            self.assertEqual(len(regrouped.groups), 2)
            self.assertEqual(regrouped.total_cost, Decimal("1.84"))
            client_report = build_client_report(
                database, client, "UTC", snapshot_at=now
            )
            self.assertEqual(client_report.total_cost, Decimal("3.59"))
            self.assertEqual(
                sum(
                    (
                        row.cost
                        for section in client_report.contracts
                        for row in section.sessions
                    ),
                    Decimal(0),
                ),
                client_report.total_cost,
            )
