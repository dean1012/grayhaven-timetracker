"""Invoice domain and route coverage for immutable billing workflows."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from unittest import TestCase

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from grayhaven_timetracker.database import session_scope
from grayhaven_timetracker.invoice_pdf import _daily_summary_rows, render_invoice_pdf
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
    disburse_invoice,
    mark_invoice_paid,
    mark_invoice_unpaid,
    preview_invoice,
    undo_disbursement,
    void_invoice,
)
from grayhaven_timetracker.models import (
    AuditEvent,
    Client,
    Contract,
    Invoice,
    InvoiceLine,
    TimeEntry,
)
from grayhaven_timetracker.reports import invoice_entry_costs
from tests.helpers import AppTestCase


class InvoiceTimeTests(TestCase):
    """Daily allocation is exact across calendar and daylight boundaries."""

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
                (date(2026, 7, 15), Decimal("0.01")),
                (date(2026, 7, 16), Decimal("0.01")),
            ],
        )
        self.assertEqual(total_billable_hours([span], timezone), Decimal("0.02"))

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
            return invoice.id

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

    def test_payment_disbursement_and_void_transitions_are_consistent(self) -> None:
        invoice_id = self.create_test_invoice()
        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "Only a paid invoice"):
                mark_invoice_unpaid(database, invoice_id)
            with self.assertRaisesRegex(InvoiceDomainError, "Only a paid invoice"):
                undo_disbursement(database, invoice_id, user_id=1)
        with session_scope(self.app) as database:
            mark_invoice_paid(database, invoice_id, date(2026, 7, 17))
            database.commit()
        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "Only an unpaid invoice"):
                mark_invoice_paid(database, invoice_id, date(2026, 7, 17))
            with self.assertRaisesRegex(InvoiceDomainError, "Only an unpaid invoice"):
                void_invoice(database, invoice_id)
        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "future"):
                disburse_invoice(
                    database,
                    invoice_id,
                    disbursement_date=date.today() + timedelta(days=1),
                    reference="ACH-100",
                )
            with self.assertRaisesRegex(InvoiceDomainError, "no matching paid"):
                disburse_invoice(
                    database,
                    invoice_id,
                    disbursement_date=date(2026, 7, 18),
                    reference="ACH-100",
                    user_id=9999,
                )
            with self.assertRaisesRegex(InvoiceDomainError, "no disbursed sessions"):
                undo_disbursement(database, invoice_id, user_id=1)
        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "before the invoice"):
                disburse_invoice(
                    database,
                    invoice_id,
                    disbursement_date=date(2026, 7, 16),
                    reference="ACH-100",
                )
        with session_scope(self.app) as database:
            disbursed = disburse_invoice(
                database,
                invoice_id,
                disbursement_date=date(2026, 7, 18),
                reference="  ACH-100  ",
            )
            self.assertEqual([entry.id for entry in disbursed], [self.seed.entry_id])
            self.assertEqual(disbursed[0].transaction_number, "ACH-100")
            database.commit()
        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "disbursed invoice"):
                mark_invoice_unpaid(database, invoice_id)
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None
            undo_disbursement(database, invoice_id, user_id=entry.user_id)
            database.commit()
        with session_scope(self.app) as database:
            mark_invoice_unpaid(database, invoice_id)
            database.commit()
        with session_scope(self.app) as database:
            void_invoice(database, invoice_id)
            database.commit()
            invoice = database.get(Invoice, invoice_id)
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert invoice is not None and entry is not None
            self.assertEqual(invoice.status, "VOID")
            self.assertEqual(entry.billing_status, "pending_invoice")
            self.assertIsNone(entry.invoice_id)

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
                    database, invoice_id, date.today() + timedelta(days=1)
                )
        with session_scope(self.app) as database:
            with self.assertRaisesRegex(InvoiceDomainError, "Only a paid invoice"):
                disburse_invoice(
                    database,
                    invoice_id,
                    disbursement_date=date.today(),
                    reference="ACH-200",
                )
            with self.assertRaisesRegex(InvoiceDomainError, "reference is required"):
                disburse_invoice(
                    database,
                    invoice_id,
                    disbursement_date=date.today(),
                    reference=" ",
                )
            with self.assertRaisesRegex(InvoiceDomainError, "reference is too long"):
                disburse_invoice(
                    database,
                    invoice_id,
                    disbursement_date=date.today(),
                    reference="X" * 101,
                )

    def test_invoice_snapshot_and_lines_are_database_immutable(self) -> None:
        invoice_id = self.create_test_invoice()
        engine = self.app.extensions["database_engine"]
        statements = (
            text("UPDATE invoice SET client_name = 'Changed' WHERE id = :id"),
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
        rows = _daily_summary_rows(invoice, [line], UTC)
        self.assertEqual(
            [day for day, _ in rows],
            [date(2026, 7, day) for day in range(13, 18)],
        )
        self.assertIn(None, [hours for _, hours in rows])

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
        self.app.config["BRANDING_PATH"] = str(
            Path(__file__).resolve().parents[1] / "branding"
        )

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
            invoice_id = invoice.id
            self.assertEqual(invoice.status, "UNPAID")
            self.assertEqual(len(invoice.lines), 1)
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

        paid_path = f"/invoices/{invoice_id}/paid"
        self.assertIn("/reauthenticate?", self.client.get(paid_path).location)
        self.authorize_sensitive_action(paid_path)
        paid = self.client.post(paid_path)
        self.assertEqual(paid.status_code, 302)
        with session_scope(self.app) as database:
            invoice = database.get(Invoice, invoice_id)
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert invoice is not None and entry is not None
            self.assertEqual(invoice.status, "PAID")
            self.assertEqual(entry.billing_status, "client_paid")
            event = database.scalar(
                select(AuditEvent).where(AuditEvent.event == "invoice_paid")
            )
            self.assertIsNotNone(event)
        self.assertEqual(self.client.get(paid_path).status_code, 409)

        detail = self.client.get(f"/invoices/{invoice_id}")
        self.assertEqual(detail.status_code, 200)
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

        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None
            worker_id = entry.user_id
        disburse_path = f"/invoices/{invoice_id}/disburse/{worker_id}"
        self.authorize_sensitive_action(disburse_path)
        self.assertEqual(self.client.get(disburse_path).status_code, 200)
        invalid_disbursement = self.client.post(
            disburse_path,
            data={"disbursement_date": "not-a-date", "reference": "ACH-300"},
        )
        self.assertEqual(invalid_disbursement.status_code, 409)
        disbursed = self.client.post(
            disburse_path,
            data={"disbursement_date": str(date.today()), "reference": "ACH-300"},
        )
        self.assertEqual(disbursed.status_code, 302)
        self.assertEqual(
            self.client.get(f"/invoices/{invoice_id}/unpaid").status_code, 409
        )

        undo_path = f"/invoices/{invoice_id}/undo-disbursement/{worker_id}"
        self.authorize_sensitive_action(undo_path)
        self.assertEqual(self.client.get(undo_path).status_code, 200)
        self.assertEqual(self.client.post(undo_path).status_code, 409)
        self.assertEqual(
            self.client.post(
                undo_path, data={"correction_reason": "Correct payout record"}
            ).status_code,
            302,
        )

        unpaid_path = f"/invoices/{invoice_id}/unpaid"
        self.authorize_sensitive_action(unpaid_path)
        self.assertEqual(self.client.get(unpaid_path).status_code, 200)
        self.assertEqual(self.client.post(unpaid_path).status_code, 409)
        self.assertEqual(
            self.client.post(
                unpaid_path, data={"correction_reason": "Payment was reversed"}
            ).status_code,
            302,
        )

        void_path = f"/invoices/{invoice_id}/void"
        self.authorize_sensitive_action(void_path)
        self.assertEqual(self.client.get(void_path).status_code, 200)
        self.assertEqual(
            self.client.post(
                void_path, data={"correction_reason": "Invoice issued in error"}
            ).status_code,
            302,
        )
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
