"""Invoice domain and route coverage for immutable billing workflows."""

from __future__ import annotations

import base64
import shutil
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from pypdf import PdfReader
from reportlab import rl_config
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from grayhaven_timetracker import invoice_routes
from grayhaven_timetracker import invoices as invoice_domain
from grayhaven_timetracker.database import session_scope
from grayhaven_timetracker.disbursements import (
    create_disbursement,
    outstanding_cents,
)
from grayhaven_timetracker.invoice_pdf import (
    invoice_pdf_with_status,
    render_invoice_pdf,
)
from grayhaven_timetracker.invoice_summary import (
    daily_summary_rows,
    worker_summary_rows,
)
from grayhaven_timetracker.invoice_time import (
    TimeSpan,
    daily_billable_hours,
    daily_seconds,
    total_billable_hours,
)
from grayhaven_timetracker.invoices import (
    InvoiceDomainError,
    calculate_due_date,
    create_invoice,
    mark_invoice_paid,
    preview_invoice,
    refund_invoice,
    void_invoice,
)
from grayhaven_timetracker.models import (
    AuditEvent,
    Client,
    Contract,
    Disbursement,
    Invoice,
    InvoiceLine,
    TimeEntry,
    User,
)
from grayhaven_timetracker.reports import invoice_entry_costs
from tests.helpers import AppTestCase, PublicInvoiceId


class InvoiceTimeTests(TestCase):
    """Daily allocation is exact across calendar and daylight boundaries."""

    def test_summaries_keep_distinct_workers_and_local_calendar_days(self) -> None:
        from zoneinfo import ZoneInfo

        timezone = ZoneInfo("America/Chicago")
        invoice = Invoice(
            range_start_utc=datetime(2026, 9, 14, 5),
            range_end_utc=datetime(2026, 9, 21, 5),
        )
        lines = [
            InvoiceLine(
                user_id=1,
                worker_name="Alex Example",
                started_at_utc=datetime(2026, 9, 15, 4, 30),
                stopped_at_utc=datetime(2026, 9, 15, 5, 30),
                total_seconds=3600,
            ),
            InvoiceLine(
                user_id=2,
                worker_name="Alex Example",
                started_at_utc=datetime(2026, 9, 19, 15),
                stopped_at_utc=datetime(2026, 9, 19, 15, 1),
                total_seconds=60,
            ),
            InvoiceLine(
                user_id=1,
                worker_name="Alex Example",
                started_at_utc=datetime(2026, 9, 19, 16),
                stopped_at_utc=datetime(2026, 9, 19, 16, 30),
                total_seconds=1800,
            ),
        ]
        self.assertEqual(
            daily_summary_rows(invoice, lines, timezone),
            [
                (date(2026, 9, 14), Decimal("0.50")),
                (date(2026, 9, 15), Decimal("0.50")),
                (date(2026, 9, 16), None),
                (date(2026, 9, 17), None),
                (date(2026, 9, 18), None),
                (date(2026, 9, 19), Decimal("0.50")),
            ],
        )
        self.assertEqual(
            worker_summary_rows(lines, timezone),
            [
                ("Alex Example", Decimal("1.50")),
                ("Alex Example", Decimal("0.00")),
            ],
        )

    def test_daily_rounding_splits_at_local_midnight(self) -> None:
        from zoneinfo import ZoneInfo

        span = TimeSpan(
            datetime(2026, 7, 15, 23, 59, 30),
            datetime(2026, 7, 16, 0, 0, 30),
            60,
        )
        timezone = ZoneInfo("UTC")
        self.assertEqual(
            daily_seconds([span], timezone),
            [(date(2026, 7, 15), 30), (date(2026, 7, 16), 30)],
        )
        self.assertEqual(
            daily_billable_hours([span], timezone),
            [
                (date(2026, 7, 15), Decimal("0.00")),
                (date(2026, 7, 16), Decimal("0.00")),
            ],
        )
        self.assertEqual(total_billable_hours([span], timezone), Decimal("0.00"))

    def test_daily_allocation_preserves_elapsed_seconds_across_dst(self) -> None:
        from zoneinfo import ZoneInfo

        spring_forward = TimeSpan(
            datetime(2026, 3, 8, 7, 59, 30),
            datetime(2026, 3, 8, 8, 0, 30),
            60,
        )
        self.assertEqual(
            daily_seconds([spring_forward], ZoneInfo("America/Chicago")),
            [(date(2026, 3, 8), 60)],
        )

    def test_daily_allocation_omits_zero_second_segments(self) -> None:
        from zoneinfo import ZoneInfo

        instant = datetime(2026, 7, 15, 12)
        self.assertEqual(
            daily_seconds(
                [TimeSpan(instant, instant + timedelta(seconds=1), 0)],
                ZoneInfo("UTC"),
            ),
            [],
        )

    def test_due_dates_advance_over_weekends_and_observed_holidays(self) -> None:
        self.assertEqual(calculate_due_date(date(2026, 7, 3), 0), date(2026, 7, 6))
        self.assertEqual(calculate_due_date(date(2026, 6, 12), 7), date(2026, 6, 22))
        with self.assertRaisesRegex(InvoiceDomainError, "0, 7, or 30"):
            calculate_due_date(date(2026, 7, 1), 14)


class InvoiceDomainTests(AppTestCase):
    """Invoice creation and corrections preserve snapshot and state invariants."""

    def setUp(self) -> None:
        super().setUp()
        self.seed = self.seed_contract()

    def test_status_overlay_preserves_issued_pdf_body(self) -> None:
        invoice_id = self.create_test_invoice()
        with session_scope(self.app) as database:
            invoice = database.get(Invoice, invoice_id)
            assert invoice is not None
            issued_pdf = invoice.pdf_bytes
            due_date = invoice.due_date.isoformat()
        original = PdfReader(BytesIO(issued_pdf))
        headings = {"INVOICE", "PAID", "VOID", "REFUNDED"}

        def body(pdf: PdfReader) -> list[list[str]]:
            return [
                [
                    line
                    for line in (page.extract_text() or "").splitlines()
                    if line.strip()
                    and line.strip() not in headings
                    and line.strip()
                    not in {"Due", "Paid", "Voided", "Refunded", due_date, "2026-07-16"}
                ]
                for page in pdf.pages
            ]

        for status in ("PAID", "VOID", "REFUNDED"):
            with self.subTest(status=status):
                updated = PdfReader(
                    BytesIO(
                        invoice_pdf_with_status(
                            issued_pdf,
                            status,
                            pdf_version=2,
                            status_date=date(2026, 7, 16),
                        )
                    )
                )
                self.assertEqual(len(updated.pages), len(original.pages))
                self.assertEqual(body(updated), body(original))
                labels = (updated.pages[0].extract_text() or "").splitlines()
                self.assertIn(status, labels)
                self.assertNotIn("INVOICE", labels)
                self.assertIn(
                    {"PAID": "Paid", "VOID": "Voided", "REFUNDED": "Refunded"}[status],
                    labels,
                )
                self.assertIn("2026-07-16", labels)
                self.assertNotIn("Due", labels)
        self.assertEqual(
            invoice_pdf_with_status(issued_pdf, "UNPAID", pdf_version=2),
            issued_pdf,
        )

    def test_status_overlay_preserves_matching_client_name(self) -> None:
        invoice_id = self.create_test_invoice()
        with session_scope(self.app) as database:
            invoice = database.get(Invoice, invoice_id)
            assert invoice is not None
            lines = list(invoice.lines)
            database.expunge(invoice)
        for name in ("PAID", "Bill to"):
            with self.subTest(name=name):
                invoice.client_name = name
                issued_pdf = render_invoice_pdf(invoice, lines)
                updated_pdf = invoice_pdf_with_status(
                    issued_pdf, "PAID", pdf_version=2, status_date=date(2026, 7, 16)
                )
                text = PdfReader(BytesIO(updated_pdf)).pages[0].extract_text()
                self.assertIsNotNone(text)
                assert text is not None
                self.assertEqual(text.splitlines().count(name), 2)
                self.assertIn("PAID", text.splitlines())

    def test_maximum_transaction_reference_fits_pdf_header(self) -> None:
        invoice_id = self.create_test_invoice()
        with session_scope(self.app) as database:
            invoice = database.get(Invoice, invoice_id)
            assert invoice is not None
            source = invoice.pdf_bytes
        rendered = invoice_pdf_with_status(
            source,
            "PAID",
            pdf_version=2,
            status_date=date(2026, 7, 16),
            transaction_id="W" * 20,
        )
        first_page = PdfReader(BytesIO(rendered)).pages[0]
        lines = (first_page.extract_text() or "").splitlines()
        self.assertIn("#" + "W" * 20, lines)

    def test_archived_clients_are_not_offered_for_invoice_generation(self) -> None:
        with session_scope(self.app) as database:
            client = database.get(Client, self.seed.client_id)
            assert client is not None
            client.archived_at = datetime(2026, 7, 16)
        with (
            session_scope(self.app) as database,
            self.app.test_request_context("/invoices"),
            patch.object(invoice_routes, "get_session", return_value=database),
        ):
            context = invoice_routes.range_context()
        self.assertNotIn(
            self.seed.client_id, [client.id for client in context["clients"]]
        )

    def test_void_requires_active_client_and_contract(self) -> None:
        invoice_id = self.create_test_invoice()
        for parent_type in (Client, Contract):
            with self.subTest(parent=parent_type.__name__):
                with session_scope(self.app) as database:
                    invoice = database.get(Invoice, invoice_id)
                    assert invoice is not None
                    parent = (
                        database.get(Client, invoice.client_id)
                        if parent_type is Client
                        else database.get(Contract, invoice.contract_id)
                    )
                    assert parent is not None
                    parent.archived_at = datetime(2026, 7, 16)
                with session_scope(self.app) as database:
                    with self.assertRaisesRegex(
                        InvoiceDomainError,
                        "Activate the client and contract before voiding",
                    ):
                        void_invoice(database, invoice_id)
                with session_scope(self.app) as database:
                    invoice = database.get(Invoice, invoice_id)
                    assert invoice is not None
                    parent = (
                        database.get(Client, invoice.client_id)
                        if parent_type is Client
                        else database.get(Contract, invoice.contract_id)
                    )
                    assert parent is not None
                    parent.archived_at = None
        with session_scope(self.app) as database:
            voided = void_invoice(database, invoice_id)
            self.assertEqual(voided.status, "VOID")

    def test_invoice_detail_summaries_survive_void_and_source_edits(self) -> None:
        self.login()
        invoice_id = self.create_test_invoice()
        with session_scope(self.app) as database:
            invoice = database.get(Invoice, invoice_id)
            assert invoice is not None
            contact = invoice.contact_email
            worker_name = invoice.lines[0].worker_name
            day = invoice.lines[0].started_at_utc.date().isoformat()
        unpaid = self.client.get(f"/invoices/{invoice_id}")
        self.assertEqual(unpaid.status_code, 200)
        self.assertTrue(unpaid.cache_control.no_store)
        unpaid_pdf = self.client.get(f"/invoices/{invoice_id}/download")
        self.assertTrue(unpaid_pdf.cache_control.no_store)
        for value in (
            "Billable Work -",
            "Billable hours are rounded daily",
            contact,
            worker_name,
            day,
            "1.00",
            "$55.00 per hour",
            "1 hour 7 seconds",
        ):
            self.assertIn(value, unpaid.text)
        with session_scope(self.app) as database:
            void_invoice(database, invoice_id)
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None
            entry.stopped_at = entry.started_at + timedelta(hours=2)
            entry.user.first_name = "Changed"
            entry.task.contract.contact_email = "changed@example.invalid"
            entry.task.contract.hourly_rate_cents = 9900
        self.app.config["BRANDING_PATH"] = str(
            Path(__file__).resolve().parents[1] / "branding"
        )
        voided = self.client.get(f"/invoices/{invoice_id}")
        self.assertEqual(voided.status_code, 200)
        voided_pdf = self.client.get(f"/invoices/{invoice_id}/download")
        self.assertEqual(voided_pdf.status_code, 200)
        self.assertTrue(voided_pdf.cache_control.no_store)
        self.assertNotEqual(voided_pdf.data, unpaid_pdf.data)
        self.assertIn(
            "VOID",
            (
                PdfReader(BytesIO(voided_pdf.data)).pages[0].extract_text() or ""
            ).splitlines(),
        )
        self.assertIn(
            "Voided",
            PdfReader(BytesIO(voided_pdf.data)).pages[0].extract_text(),
        )
        self.assertIn(b"VOID", voided.data)
        for value in (
            contact,
            worker_name,
            day,
            "1.00",
            "$55.00 per hour",
            "1 hour 7 seconds",
        ):
            self.assertIn(value, voided.text)
        self.assertNotIn("changed@example.invalid", voided.text)
        self.assertNotIn("Disbursement Management", voided.text)

    def create_test_invoice(self) -> int:
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None and entry.stopped_at is not None
            start = entry.started_at + timedelta(minutes=15)
            end = entry.stopped_at + timedelta(minutes=15)
            proposed = preview_invoice(
                database,
                contract_id=self.seed.contract_id,
                range_start_utc=start,
                range_end_utc=end,
                timezone_name="UTC",
            )
            self.assertEqual(len(proposed.entries), 1)
            self.assertTrue(proposed.entries[0].started_before_range)
            self.assertEqual(proposed.total_seconds, 3607)
            self.assertEqual(proposed.total_cents, 5500)
            invoice = create_invoice(
                database,
                contract_id=self.seed.contract_id,
                range_start_utc=start,
                range_end_utc=end,
                timezone_name="UTC",
                expected_fingerprint=proposed.fingerprint,
            )
            database.commit()
            self.assertEqual(invoice.invoice_number, "001-001-001")
            self.assertTrue(invoice.pdf_bytes.startswith(b"%PDF-"))
            return PublicInvoiceId(invoice.id, invoice.invoice_number)

    def test_preview_rejects_stale_details_and_claims_entries_once(self) -> None:
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None and entry.stopped_at is not None
            proposed = preview_invoice(
                database,
                contract_id=self.seed.contract_id,
                range_start_utc=entry.started_at,
                range_end_utc=entry.stopped_at + timedelta(seconds=1),
                timezone_name="UTC",
            )
            entry.task.contract.contact_name = "Changed after preview"
            database.commit()
            with self.assertRaisesRegex(InvoiceDomainError, "details changed"):
                create_invoice(
                    database,
                    contract_id=self.seed.contract_id,
                    range_start_utc=entry.started_at,
                    range_end_utc=entry.stopped_at + timedelta(seconds=1),
                    timezone_name="UTC",
                    expected_fingerprint=proposed.fingerprint,
                )

        invoice_id = self.create_test_invoice()
        with session_scope(self.app) as database:
            invoice = database.get(Invoice, invoice_id)
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert invoice is not None and entry is not None
            self.assertEqual(entry.invoice_id, invoice.id)
            self.assertEqual(entry.invoice_number, invoice.invoice_number)
            self.assertEqual(entry.billing_status, "invoiced")
            with self.assertRaisesRegex(InvoiceDomainError, "no eligible entries"):
                preview_invoice(
                    database,
                    contract_id=self.seed.contract_id,
                    range_start_utc=invoice.range_start_utc,
                    range_end_utc=invoice.range_end_utc,
                    timezone_name="UTC",
                )

    def test_payment_refund_and_void_transitions_are_consistent(self) -> None:
        invoice_id = self.create_test_invoice()
        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "Only a paid invoice"):
                refund_invoice(database, invoice_id)
        with session_scope(self.app) as database:
            mark_invoice_paid(
                database, invoice_id, date(2026, 7, 17), transaction_id="PAYMENT-1"
            )
            database.commit()
        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "Only an unpaid invoice"):
                mark_invoice_paid(database, invoice_id, date(2026, 7, 17))
            with self.assertRaisesRegex(InvoiceDomainError, "Only an unpaid invoice"):
                void_invoice(database, invoice_id)
        with session_scope(self.app) as database:
            refunded = refund_invoice(database, invoice_id, transaction_id="REFUND-1")
            self.assertEqual(refunded.display_status, "REFUNDED")
            self.assertIsNotNone(refunded.refunded_date)
            database.commit()
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None
            invoice = database.get(Invoice, invoice_id)
            assert invoice is not None
            self.assertEqual(invoice.display_status, "REFUNDED")
            self.assertEqual(entry.billing_status, "client_paid")
            self.assertEqual(entry.invoice_id, invoice.id)
            with self.assertRaisesRegex(InvoiceDomainError, "Only a paid invoice"):
                refund_invoice(database, invoice_id)

    def test_disbursement_balance_tracks_final_transactions(self) -> None:
        invoice_id = self.create_test_invoice()
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None
            worker_id = entry.user_id
            worker = database.get(User, worker_id)
            assert worker is not None
            worker.user_type = "llc_member"
            mark_invoice_paid(database, invoice_id, transaction_id="PAYMENT-1")
            database.commit()
        with session_scope(self.app) as database:
            self.assertEqual(outstanding_cents(database, worker_id), 5500)
            for kind, reference, amount in (
                ("DISBURSEMENT", "ACH-1", 1000),
                ("IN_KIND", "PURCHASE-1", 1500),
                ("RETAINED_EARNINGS", None, 3000),
            ):
                create_disbursement(
                    database,
                    user_id=worker_id,
                    actor_id=worker_id,
                    kind=kind,
                    date_value=date.today(),
                    transaction_id=reference,
                    amount_cents=amount,
                    notes=None,
                )
                database.commit()
            self.assertEqual(outstanding_cents(database, worker_id), 0)
            with self.assertRaisesRegex(InvoiceDomainError, "exceeds"):
                create_disbursement(
                    database,
                    user_id=worker_id,
                    actor_id=worker_id,
                    kind="DISBURSEMENT",
                    date_value=date.today(),
                    transaction_id="ACH-2",
                    amount_cents=1,
                    notes=None,
                )
            self.assertEqual(len(database.scalars(select(Disbursement)).all()), 3)

    def test_since_last_range_starts_at_the_previous_nonvoid_invoice(self) -> None:
        invoice_id = self.create_test_invoice()
        with session_scope(self.app) as database:
            invoice = database.get(Invoice, invoice_id)
            original = database.get(TimeEntry, self.seed.entry_id)
            assert invoice is not None and original is not None
            followup = TimeEntry(
                user_id=original.user_id,
                task_id=original.task_id,
                started_at=invoice.range_end_utc + timedelta(minutes=1),
                stopped_at=invoice.range_end_utc + timedelta(minutes=2),
            )
            database.add(followup)
        with session_scope(self.app) as database:
            proposed = preview_invoice(
                database,
                contract_id=self.seed.contract_id,
                timezone_name="UTC",
            )
            invoice = database.get(Invoice, invoice_id)
            assert invoice is not None
            self.assertEqual(proposed.range_start_utc, invoice.range_end_utc)
            self.assertEqual(len(proposed.entries), 1)

    def test_domain_rejects_invalid_ranges_and_unavailable_transitions(self) -> None:
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None and entry.stopped_at is not None
            cases = (
                ({"range_start_utc": entry.started_at}, "both invoice range bounds"),
                (
                    {
                        "range_start_utc": entry.started_at,
                        "range_end_utc": entry.started_at,
                    },
                    "end must be after",
                ),
                (
                    {
                        "range_start_utc": entry.started_at,
                        "range_end_utc": datetime.now(UTC) + timedelta(days=1),
                    },
                    "cannot be in the future",
                ),
            )
            for values, message in cases:
                with (
                    self.subTest(message=message),
                    self.assertRaisesRegex(InvoiceDomainError, message),
                ):
                    preview_invoice(
                        database,
                        contract_id=self.seed.contract_id,
                        timezone_name="UTC",
                        **values,
                    )
            with self.assertRaisesRegex(InvoiceDomainError, "timezone is invalid"):
                preview_invoice(
                    database,
                    contract_id=self.seed.contract_id,
                    timezone_name="Not/A-Timezone",
                )
            with self.assertRaisesRegex(InvoiceDomainError, "does not exist"):
                preview_invoice(database, contract_id=9999, timezone_name="UTC")

            empty_client = Client(
                name="No Work Client",
                contact_name="No Work Contact",
                contact_email="no-work@example.invalid",
            )
            empty_contract = Contract(
                client=empty_client,
                name="No Work Project",
                contact_name="No Work Contact",
                contact_email="no-work@example.invalid",
                hourly_rate_cents=5500,
            )
            database.add(empty_contract)
            database.flush()
            empty_contract_id = empty_contract.id
        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "no eligible entries"):
                preview_invoice(
                    database,
                    contract_id=empty_contract_id,
                    timezone_name="UTC",
                )

        with session_scope(self.app) as database:
            contract = database.get(Contract, self.seed.contract_id)
            assert contract is not None
            contract.archived_at = datetime.now()
        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "archived project"):
                preview_invoice(
                    database,
                    contract_id=self.seed.contract_id,
                    timezone_name="UTC",
                )
            contract = database.get(Contract, self.seed.contract_id)
            assert contract is not None
            contract.archived_at = None

        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "current preview"):
                create_invoice(
                    database,
                    contract_id=self.seed.contract_id,
                    timezone_name="UTC",
                    expected_fingerprint="",
                )
            with self.assertRaisesRegex(InvoiceDomainError, "does not exist"):
                mark_invoice_paid(database, 9999)

        invoice_id = self.create_test_invoice()
        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "future"):
                mark_invoice_paid(
                    database,
                    invoice_id,
                    datetime.now(UTC).date() + timedelta(days=1),
                    transaction_id="PAYMENT-FUTURE",
                )
        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "Only a paid invoice"):
                refund_invoice(database, invoice_id)

    def test_invoice_snapshot_and_lines_are_database_immutable(self) -> None:
        invoice_id = self.create_test_invoice()
        engine = self.app.extensions["database_engine"]
        statements = (
            text("UPDATE invoice SET client_name = 'Changed' WHERE id = :id"),
            text("UPDATE invoice SET total_cents = 1 WHERE id = :id"),
            text("UPDATE invoice SET worker_summary_json = '[]' WHERE id = :id"),
            text("UPDATE invoice SET pdf_bytes = X'25504446' WHERE id = :id"),
            text(
                "UPDATE invoice_line SET task_name = 'Changed' WHERE invoice_id = :id"
            ),
            text("DELETE FROM invoice_line WHERE invoice_id = :id"),
            text("DELETE FROM invoice WHERE id = :id"),
        )
        for statement in statements:
            with self.subTest(statement=str(statement)), engine.connect() as connection:
                transaction = connection.begin()
                with self.assertRaises(IntegrityError):
                    connection.execute(statement, {"id": invoice_id})
                transaction.rollback()

    def test_report_cost_allocation_preserves_the_frozen_invoice_total(self) -> None:
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None and entry.stopped_at is not None
            sibling = TimeEntry(
                user_id=entry.user_id,
                task_id=entry.task_id,
                started_at=entry.stopped_at + timedelta(minutes=1),
                stopped_at=entry.stopped_at + timedelta(minutes=2),
            )
            database.add(sibling)
            database.flush()
            sibling_id = sibling.id
            database.commit()
            proposed = preview_invoice(
                database,
                contract_id=self.seed.contract_id,
                range_start_utc=entry.started_at,
                range_end_utc=sibling.stopped_at + timedelta(seconds=1),
                timezone_name="UTC",
            )
            invoice = create_invoice(
                database,
                contract_id=self.seed.contract_id,
                range_start_utc=entry.started_at,
                range_end_utc=sibling.stopped_at + timedelta(seconds=1),
                timezone_name="UTC",
                expected_fingerprint=proposed.fingerprint,
            )
            database.commit()
            costs = invoice_entry_costs(database, {invoice.id})
            self.assertEqual(set(costs), {self.seed.entry_id, sibling_id})
            self.assertEqual(
                sum(costs.values(), Decimal(0)), Decimal(invoice.total_cents) / 100
            )
            self.assertGreater(costs[self.seed.entry_id], costs[sibling_id])
            self.assertEqual(invoice_entry_costs(database, set()), {})

    def test_zero_duration_invoice_allocates_zero_cost(self) -> None:
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None
            entry.stopped_at = entry.started_at
            database.commit()
            proposed = preview_invoice(
                database,
                contract_id=self.seed.contract_id,
                range_start_utc=entry.started_at,
                range_end_utc=entry.started_at + timedelta(seconds=1),
                timezone_name="UTC",
            )
            invoice = create_invoice(
                database,
                contract_id=self.seed.contract_id,
                range_start_utc=entry.started_at,
                range_end_utc=entry.started_at + timedelta(seconds=1),
                timezone_name="UTC",
                expected_fingerprint=proposed.fingerprint,
            )
            database.commit()
            self.assertEqual(invoice.total_seconds, 0)
            self.assertEqual(
                invoice_entry_costs(database, {invoice.id}),
                {self.seed.entry_id: Decimal(0)},
            )

    def test_invoice_sequence_stops_after_999(self) -> None:
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            contract = database.get(Contract, self.seed.contract_id)
            assert entry is not None and entry.stopped_at is not None
            assert contract is not None
            proposed = preview_invoice(
                database,
                contract_id=contract.id,
                range_start_utc=entry.started_at,
                range_end_utc=entry.stopped_at + timedelta(seconds=1),
                timezone_name="UTC",
            )
            database.add(
                Invoice(
                    client_id=contract.client_id,
                    contract_id=contract.id,
                    project_sequence=999,
                    invoice_number=(f"{contract.client_id:03d}-{contract.id:03d}-999"),
                    status="UNPAID",
                    issued_at=datetime(2026, 7, 1),
                    range_start_utc=datetime(2026, 6, 1),
                    range_end_utc=datetime(2026, 6, 2),
                    timezone_name="UTC",
                    client_name=contract.client.name,
                    project_name=contract.name,
                    contact_name=contract.contact_name,
                    contact_email=contract.contact_email,
                    hourly_rate_cents=contract.hourly_rate_cents,
                    payment_terms_days=contract.payment_terms_days,
                    total_seconds=0,
                    total_cents=0,
                    due_date=date(2026, 8, 12),
                    pdf_bytes=b"%PDF-test",
                )
            )
            database.commit()
            with self.assertRaisesRegex(InvoiceDomainError, "sequence 999"):
                create_invoice(
                    database,
                    contract_id=contract.id,
                    range_start_utc=entry.started_at,
                    range_end_utc=entry.stopped_at + timedelta(seconds=1),
                    timezone_name="UTC",
                    expected_fingerprint=proposed.fingerprint,
                )

    def test_generation_detects_an_entry_claim_change_after_preview(self) -> None:
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None and entry.stopped_at is not None
            proposed = preview_invoice(
                database,
                contract_id=self.seed.contract_id,
                range_start_utc=entry.started_at,
                range_end_utc=entry.stopped_at + timedelta(seconds=1),
                timezone_name="UTC",
            )
            original_scalars = database.scalars
            scalar_calls = 0

            def simulate_claim_change(statement, *args, **kwargs):
                nonlocal scalar_calls
                scalar_calls += 1
                if scalar_calls == 2:
                    return iter(())
                return original_scalars(statement, *args, **kwargs)

            with (
                patch.object(database, "scalars", side_effect=simulate_claim_change),
                self.assertRaisesRegex(InvoiceDomainError, "entries changed"),
            ):
                create_invoice(
                    database,
                    contract_id=self.seed.contract_id,
                    range_start_utc=entry.started_at,
                    range_end_utc=entry.stopped_at + timedelta(seconds=1),
                    timezone_name="UTC",
                    expected_fingerprint=proposed.fingerprint,
                )

    def test_claim_integrity_guards_reject_malformed_invoice_state(self) -> None:
        invoice = SimpleNamespace(id=7, invoice_number="001-001-001")
        entry = SimpleNamespace(
            id=9,
            invoice_number=invoice.invoice_number,
            billing_status="invoiced",
        )
        database = SimpleNamespace()
        database.scalars = lambda _statement: iter(())
        with self.assertRaisesRegex(InvoiceDomainError, "claims are inconsistent"):
            invoice_domain._claimed_entries(database, invoice)

        results = iter((iter((entry.id,)), iter((entry,))))
        database.scalars = lambda _statement: next(results)
        entry.invoice_number = "different"
        with self.assertRaisesRegex(InvoiceDomainError, "metadata is inconsistent"):
            invoice_domain._claimed_entries(database, invoice)

    def test_transition_guards_reject_malformed_claim_states(self) -> None:
        invoice = SimpleNamespace(
            id=7,
            status="UNPAID",
            timezone_name="UTC",
            client=SimpleNamespace(archived_at=None),
            contract=SimpleNamespace(archived_at=None),
        )
        entry = SimpleNamespace(billing_status="client_paid")
        with (
            patch.object(invoice_domain, "_immediate_transaction") as transaction,
            patch.object(invoice_domain, "_invoice", return_value=invoice),
            patch.object(invoice_domain, "_claimed_entries", return_value=[entry]),
        ):
            transaction.return_value.__enter__.return_value = None
            with self.assertRaisesRegex(
                InvoiceDomainError, "not awaiting client payment"
            ):
                mark_invoice_paid(SimpleNamespace(), invoice.id)

            invoice.status = "UNPAID"
            entry.billing_status = "disbursed"
            with self.assertRaisesRegex(InvoiceDomainError, "invalid payment state"):
                void_invoice(SimpleNamespace(), invoice.id)

            entry.billing_status = "client_paid"
            with self.assertRaisesRegex(InvoiceDomainError, "invalid payment state"):
                void_invoice(SimpleNamespace(), invoice.id)

    def test_timestamp_and_contract_guards_fail_closed(self) -> None:
        invalid_timestamp = SimpleNamespace(tzinfo=object())
        invalid_timestamp.astimezone = lambda _timezone: (_ for _ in ()).throw(
            OverflowError
        )
        with self.assertRaisesRegex(InvoiceDomainError, "valid UTC timestamp"):
            invoice_domain._utc_timestamp(invalid_timestamp, "Invoice range start")

        malformed_contract = SimpleNamespace(
            archived_at=None,
            payment_terms_days=14,
        )
        database = SimpleNamespace(scalar=lambda _statement: malformed_contract)
        with self.assertRaisesRegex(InvoiceDomainError, "invalid payment terms"):
            invoice_domain._build_preview(
                database,
                contract_id=1,
                range_start_utc=None,
                range_end_utc=None,
                timezone_name="UTC",
                now=datetime(2026, 7, 15),
            )

    def test_pdf_daily_summary_shows_weekdays_without_work(self) -> None:
        invoice = Invoice(
            range_start_utc=datetime(2026, 7, 13),
            range_end_utc=datetime(2026, 7, 18),
            timezone_name="UTC",
        )
        line = InvoiceLine(
            started_at_utc=datetime(2026, 7, 13, 9),
            stopped_at_utc=datetime(2026, 7, 13, 10),
            total_seconds=3600,
        )
        rows = daily_summary_rows(invoice, [line], UTC)
        self.assertEqual(
            [day for day, _ in rows],
            [date(2026, 7, day) for day in range(13, 18)],
        )
        self.assertIn(None, [hours for _, hours in rows])

        weekend_range = Invoice(
            range_start_utc=datetime(2026, 7, 17),
            range_end_utc=datetime(2026, 7, 21),
            timezone_name="UTC",
        )
        weekend_rows = daily_summary_rows(weekend_range, [], UTC)
        self.assertEqual(
            [day for day, _ in weekend_rows],
            [date(2026, 7, 17), date(2026, 7, 20)],
        )

    def test_pdf_rejects_incomplete_runtime_assets(self) -> None:
        with self.assertRaisesRegex(ValueError, "Both regular and bold"):
            render_invoice_pdf(
                Invoice(), [], font_regular_path=Path(__file__).resolve()
            )
        missing = self.root / "missing-font.ttf"
        with self.assertRaisesRegex(ValueError, "font files are unavailable"):
            render_invoice_pdf(
                Invoice(),
                [],
                font_regular_path=missing,
                font_bold_path=missing,
            )
        invoice = Invoice(
            invoice_number="001-001-001", status="UNPAID", timezone_name="UTC"
        )
        with self.assertRaisesRegex(ValueError, "logo file is unavailable"):
            render_invoice_pdf(invoice, [], logo_path=self.root / "missing-logo.png")


class InvoiceRouteTests(AppTestCase):
    """Only administrators may issue and mutate invoices after reauthentication."""

    def setUp(self) -> None:
        super().setUp()
        self.seed = self.seed_contract()
        branding = self.root / "invoice-branding"
        fonts = branding / "fonts"
        fonts.mkdir(parents=True)
        (branding / "grayhaven-logo-wordmark-light.png").write_bytes(
            base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
                "+A8AAQUBAScY42YAAAAASUVORK5CYII="
            )
        )
        search_paths = [Path(path) for path in rl_config.TTFSearchPath]
        regular = next(
            path / "Vera.ttf" for path in search_paths if (path / "Vera.ttf").is_file()
        )
        bold = next(
            path / "VeraBd.ttf"
            for path in search_paths
            if (path / "VeraBd.ttf").is_file()
        )
        shutil.copyfile(regular, fonts / "inter-400.ttf")
        shutil.copyfile(bold, fonts / "inter-700.ttf")
        self.app.config["BRANDING_PATH"] = str(branding)

    def test_void_is_unavailable_for_archived_contract(self) -> None:
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None and entry.stopped_at is not None
            preview = preview_invoice(
                database,
                contract_id=self.seed.contract_id,
                range_start_utc=entry.started_at,
                range_end_utc=entry.stopped_at + timedelta(seconds=1),
                timezone_name="UTC",
            )
            invoice = create_invoice(
                database,
                contract_id=self.seed.contract_id,
                range_start_utc=preview.range_start_utc,
                range_end_utc=preview.range_end_utc,
                timezone_name="UTC",
                expected_fingerprint=preview.fingerprint,
            )
            database.flush()
            invoice_id = PublicInvoiceId(invoice.id, invoice.invoice_number)
            contract = database.get(Contract, self.seed.contract_id)
            assert contract is not None
            contract.archived_at = datetime(2026, 7, 16)
        self.login()
        path = f"/invoices/{invoice_id}/void"
        self.assertEqual(self.client.get(path).status_code, 409)
        self.assertEqual(self.client.post(path).status_code, 409)
        self.assertIn(b"Void</button>", self.client.get("/invoices").data)
        self.assertIn(b"Void</button>", self.client.get(f"/invoices/{invoice_id}").data)

    def test_payment_reference_errors_preserve_form_values(self) -> None:
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None and entry.stopped_at is not None
            proposed = preview_invoice(
                database,
                contract_id=self.seed.contract_id,
                range_start_utc=entry.started_at,
                range_end_utc=entry.stopped_at + timedelta(seconds=1),
                timezone_name="UTC",
            )
            invoice = create_invoice(
                database,
                contract_id=self.seed.contract_id,
                range_start_utc=proposed.range_start_utc,
                range_end_utc=proposed.range_end_utc,
                timezone_name="UTC",
                expected_fingerprint=proposed.fingerprint,
            )
            database.commit()
            invoice_id = PublicInvoiceId(invoice.id, invoice.invoice_number)
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None
            entry.transaction_number = "ALREADY-USED"
        self.login()
        path = f"/invoices/{invoice_id}/paid"
        self.authorize_sensitive_action(path)
        missing = self.client.post(
            path,
            data={"transaction_id": " ", "status_date": date.today().isoformat()},
        )
        self.assertEqual(missing.status_code, 409)
        self.assertIn(b"Transaction ID is required.", missing.data)
        duplicate = self.client.post(
            path,
            data={
                "transaction_id": "ALREADY-USED",
                "status_date": date.today().isoformat(),
            },
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertIn(b"Transaction ID is already in use.", duplicate.data)
        self.assertIn(b'value="ALREADY-USED"', duplicate.data)

    def test_standard_user_cannot_access_invoice_routes(self) -> None:
        user = self.create_user()
        browser = self.app.test_client()
        self.login(
            browser,
            email=user.email,
            password="Standard-User-Test-Password-0001!",
            totp_secret="KRSXG5DSNFXGOIDB",
        )
        self.assertEqual(browser.get("/invoices").status_code, 403)
        self.assertEqual(browser.get("/invoices/new").status_code, 403)
        self.assertEqual(browser.post("/invoices/preview").status_code, 403)

    def test_preview_generation_payment_and_download_use_sensitive_flow(self) -> None:
        self.login()
        self.assertEqual(self.client.get("/invoices/new").status_code, 200)
        preview = self.client.post(
            "/invoices/preview",
            data={
                "client_id": str(self.seed.client_id),
                "contract_id": str(self.seed.contract_id),
                "mode": "custom",
                "range_start": "2026-07-14T20:00",
                "range_end": "2026-07-14T22:00",
            },
        )
        self.assertEqual(preview.status_code, 200)
        self.assertIn(b"1 hour 7 seconds", preview.data)
        with self.client.session_transaction() as browser_session:
            nonce = browser_session["invoice_draft"]["nonce"]

        unauthenticated_generation = self.client.post(
            "/invoices/generate", data={"nonce": nonce}
        )
        self.assertEqual(unauthenticated_generation.status_code, 302)
        self.assertIn("/reauthenticate?", unauthenticated_generation.location)
        self.authorize_sensitive_action("/invoices/generate")
        refreshed_preview = self.client.get("/invoices/generate")
        self.assertEqual(refreshed_preview.status_code, 200)
        self.assertIn(b"1 hour 7 seconds", refreshed_preview.data)
        generated = self.client.post("/invoices/generate", data={"nonce": nonce})
        self.assertEqual(generated.status_code, 302)
        self.assertEqual(generated.location, "/invoices")

        with session_scope(self.app) as database:
            invoice = database.scalar(select(Invoice))
            assert invoice is not None
            invoice_id = PublicInvoiceId(invoice.id, invoice.invoice_number)
            self.assertEqual(invoice.status, "UNPAID")
            self.assertEqual(len(invoice.lines), 1)
            billing_snapshot = (
                invoice.total_cents,
                invoice.worker_summary_json,
                invoice.pdf_version,
            )
            original_pdf = invoice.pdf_bytes
            created = database.scalar(
                select(AuditEvent).where(AuditEvent.event == "invoice_created")
            )
            self.assertIsNotNone(created)

        invoice_index = self.client.get("/invoices")
        self.assertEqual(invoice_index.status_code, 200)
        self.assertIn(b"001-001-001", invoice_index.data)

        download = self.client.get(f"/invoices/{invoice_id}/download")
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.mimetype, "application/pdf")
        self.assertTrue(download.data.startswith(b"%PDF-"))
        self.assertIn("001-001-001", download.headers["Content-Disposition"])

        with session_scope(self.app) as database:
            malformed_invoice = database.get(Invoice, invoice_id)
            assert malformed_invoice is not None
            _ = malformed_invoice.client, malformed_invoice.contract
            malformed_line = malformed_invoice.lines[0]
            _ = malformed_line.entry
            database.expunge_all()
        malformed_line.entry = None
        with patch.object(
            invoice_routes, "get_invoice", return_value=malformed_invoice
        ):
            malformed_detail = self.client.get(f"/invoices/{invoice_id}")
        self.assertEqual(malformed_detail.status_code, 200)

        paid_path = f"/invoices/{invoice_id}/paid"
        self.authorize_sensitive_action(paid_path)
        with (
            patch.object(invoice_routes, "get_invoice", return_value=malformed_invoice),
            patch.object(
                invoice_routes, "mark_invoice_paid", return_value=malformed_invoice
            ),
            patch.object(invoice_routes, "audit_invoice"),
        ):
            malformed_action = self.client.post(
                paid_path, data={"status_date": date.today().isoformat()}
            )
        self.assertEqual(malformed_action.status_code, 302)

        self.assertIn("/reauthenticate?", self.client.get(paid_path).location)
        self.authorize_sensitive_action(paid_path)
        missing_date = self.client.post(paid_path, data={"transaction_id": "PAYMENT-1"})
        self.assertEqual(missing_date.status_code, 409)
        self.assertIn(b"Enter a valid date.", missing_date.data)
        payment_day = date.today() - timedelta(days=2)
        paid = self.client.post(
            paid_path,
            data={
                "transaction_id": "PAYMENT-1",
                "status_date": payment_day.isoformat(),
            },
        )
        self.assertEqual(paid.status_code, 302)
        with session_scope(self.app) as database:
            invoice = database.get(Invoice, invoice_id)
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert invoice is not None and entry is not None
            self.assertEqual(invoice.status, "PAID")
            self.assertEqual(invoice.paid_transaction_id, "PAYMENT-1")
            self.assertEqual(invoice.paid_date, payment_day)
            self.assertEqual(
                (invoice.total_cents, invoice.worker_summary_json, invoice.pdf_version),
                billing_snapshot,
            )
            self.assertEqual(invoice.pdf_bytes, original_pdf)
            self.assertEqual(entry.billing_status, "client_paid")
            event = database.scalar(
                select(AuditEvent).where(AuditEvent.event == "invoice_paid")
            )
            self.assertIsNotNone(event)
        self.assertEqual(self.client.get(paid_path).status_code, 409)
        paid_pdf = self.client.get(f"/invoices/{invoice_id}/download").data
        self.assertNotEqual(paid_pdf, original_pdf)
        self.assertIn(
            "#PAYMENT-1", PdfReader(BytesIO(paid_pdf)).pages[0].extract_text()
        )
        self.assertIn("Paid", PdfReader(BytesIO(paid_pdf)).pages[0].extract_text())

        detail = self.client.get(f"/invoices/{invoice_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"#PAYMENT-1", detail.data)
        self.assertIn(b"Admin Operator", detail.data)
        self.assertEqual(self.client.get("/invoices/9999").status_code, 404)
        self.assertEqual(self.client.get("/invoices/not-an-action").status_code, 404)
        self.assertEqual(
            self.client.get(f"/invoices/{invoice_id}/disburse").status_code, 404
        )
        self.assertEqual(
            self.client.get(f"/invoices/{invoice_id}/paid/9999").status_code, 404
        )
        self.assertEqual(
            self.client.get(f"/invoices/{invoice_id}/disburse/9999").status_code,
            404,
        )

        refund_path = f"/invoices/{invoice_id}/refund"
        refund_day = date.today() - timedelta(days=1)
        self.authorize_sensitive_action(refund_path)
        self.assertEqual(self.client.get(refund_path).status_code, 200)
        self.assertEqual(self.client.post(refund_path).status_code, 409)
        future_date = self.client.post(
            refund_path,
            data={
                "correction_reason": "Client refund recorded",
                "transaction_id": "REFUND-1",
                "status_date": (date.today() + timedelta(days=1)).isoformat(),
            },
        )
        self.assertEqual(future_date.status_code, 409)
        self.assertIn(b"Refund date cannot be in the future.", future_date.data)
        self.assertEqual(
            self.client.post(
                refund_path,
                data={
                    "correction_reason": "Client refund recorded",
                    "transaction_id": "REFUND-1",
                    "status_date": refund_day.isoformat(),
                },
            ).status_code,
            302,
        )
        with session_scope(self.app) as database:
            invoice = database.get(Invoice, invoice_id)
            assert invoice is not None
            self.assertEqual(invoice.display_status, "REFUNDED")
            self.assertEqual(invoice.refund_transaction_id, "REFUND-1")
            self.assertEqual(invoice.refunded_date, refund_day)
            self.assertTrue(invoice.pdf_bytes.startswith(b"%PDF-"))
            self.assertEqual(
                (invoice.total_cents, invoice.worker_summary_json, invoice.pdf_version),
                billing_snapshot,
            )
            self.assertEqual(invoice.pdf_bytes, original_pdf)
        refunded_pdf = self.client.get(f"/invoices/{invoice_id}/download").data
        self.assertNotEqual(refunded_pdf, paid_pdf)
        self.assertIn(
            "#REFUND-1", PdfReader(BytesIO(refunded_pdf)).pages[0].extract_text()
        )
        self.assertNotIn(
            "#PAYMENT-1", PdfReader(BytesIO(refunded_pdf)).pages[0].extract_text()
        )
        self.assertIn(
            "Refunded", PdfReader(BytesIO(refunded_pdf)).pages[0].extract_text()
        )
        refunded_detail = self.client.get(f"/invoices/{invoice_id}")
        self.assertEqual(refunded_detail.status_code, 200)
        self.assertIn(b"Payment #PAYMENT-1", refunded_detail.data)
        self.assertIn(b"Refund #REFUND-1", refunded_detail.data)
        self.assertEqual(self.client.get(refund_path).status_code, 409)
        self.assertEqual(self.client.get(paid_path).status_code, 409)
        self.assertEqual(self.client.get("/invoices?page=invalid").status_code, 400)
        self.assertEqual(self.client.get("/invoices?page=0").status_code, 400)
        self.assertEqual(self.client.get("/invoices?page=99").status_code, 302)

    def test_preview_validates_project_ownership_and_nonce_replacement(self) -> None:
        self.login()
        invalid = self.client.post(
            "/invoices/preview",
            data={
                "client_id": "999",
                "contract_id": str(self.seed.contract_id),
                "mode": "since_last",
            },
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertIn(b"Select an active project", invalid.data)
        self.assertEqual(self.client.get("/invoices/generate").status_code, 302)

        invalid_mode = self.client.post(
            "/invoices/preview",
            data={
                "client_id": str(self.seed.client_id),
                "contract_id": str(self.seed.contract_id),
                "mode": "invalid",
            },
        )
        self.assertEqual(invalid_mode.status_code, 400)
        self.assertIn(b"Select a valid invoice range mode", invalid_mode.data)
        current = self.client.post(
            "/invoices/preview",
            data={
                "client_id": str(self.seed.client_id),
                "contract_id": str(self.seed.contract_id),
                "mode": "since_last",
            },
        )
        self.assertEqual(current.status_code, 200)
        self.assertEqual(
            self.client.post("/invoices/generate", data={"nonce": "stale"}).status_code,
            409,
        )
        self.authorize_sensitive_action("/invoices/generate")
        with session_scope(self.app) as database:
            contract = database.get(Contract, self.seed.contract_id)
            assert contract is not None
            contract.contact_name = "Changed after preview"
        stale = self.client.get("/invoices/generate")
        self.assertEqual(stale.status_code, 302)
        self.assertEqual(stale.location, "/invoices/new")
