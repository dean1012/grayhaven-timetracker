"""Disbursement permissions, balances, and final transactions."""

from datetime import date, timedelta

from sqlalchemy import select

from grayhaven_timetracker.database import session_scope
from grayhaven_timetracker.disbursements import (
    _validated_values,
    create_disbursement,
    outstanding_cents,
)
from grayhaven_timetracker.invoices import (
    InvoiceDomainError,
    create_invoice,
    mark_invoice_paid,
    preview_invoice,
    refund_invoice,
    require_available_transaction_id,
)
from grayhaven_timetracker.models import AuditEvent, Disbursement, TimeEntry, User
from tests.helpers import AppTestCase


class DisbursementRouteTests(AppTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.seed = self.seed_contract()
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None and entry.stopped_at is not None
            self.worker_id = entry.user_id
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
            database.commit()
            self.invoice_id = invoice.id
        with session_scope(self.app) as database:
            mark_invoice_paid(database, self.invoice_id, transaction_id="PAYMENT-1")
            database.commit()
        self.login()

    def test_admin_transaction_flow_and_worker_history(self) -> None:
        listing = self.client.get("/disbursements")
        self.assertEqual(listing.status_code, 200)
        self.assertIn(b"$55.00", listing.data)
        self.assertEqual(self.client.get("/disbursements?page=0").status_code, 400)
        self.assertEqual(
            self.client.get(f"/disbursements/{self.worker_id}").status_code, 200
        )
        self.assertEqual(self.client.get("/my/disbursements").status_code, 200)

        new_path = f"/disbursements/{self.worker_id}/new"
        self.authorize_sensitive_action(new_path)
        invalid = self.client.post(
            new_path,
            data={
                "date": date.today().isoformat(),
                "type": "DISBURSEMENT",
                "transaction_id": "ACH-1",
                "amount": "56.00",
            },
        )
        self.assertEqual(invalid.status_code, 409)
        self.assertIn(b'value="ACH-1"', invalid.data)
        self.assertIn(b'value="56.00"', invalid.data)
        created = self.client.post(
            new_path,
            data={
                "date": date.today().isoformat(),
                "type": "DISBURSEMENT",
                "transaction_id": "ACH-1",
                "amount": "10.00",
            },
        )
        self.assertEqual(created.status_code, 302)
        self.authorize_sensitive_action(new_path)
        duplicate = self.client.post(
            new_path,
            data={
                "date": date.today().isoformat(),
                "type": "DISBURSEMENT",
                "transaction_id": "ACH-1",
                "amount": "1.00",
                "notes": "Sample note",
            },
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertIn(b"Transaction ID is already in use.", duplicate.data)
        self.assertIn(b'value="ACH-1"', duplicate.data)
        self.assertIn(b"Sample note", duplicate.data)
        with session_scope(self.app) as database:
            item = database.scalar(select(Disbursement))
            assert item is not None
            item_id = item.id
            self.assertEqual(item.amount_cents, 1000)
            self.assertEqual(outstanding_cents(database, self.worker_id), 4500)
            self.assertIsNotNone(
                database.scalar(
                    select(AuditEvent).where(AuditEvent.event == "disbursement_created")
                )
            )

        self.assertIn(b"ACH-1", self.client.get("/my/disbursements").data)
        for action in ("edit", "archive", "unarchive", "delete"):
            self.assertEqual(
                self.client.post(f"/disbursements/{item_id}/{action}").status_code,
                404,
            )

    def test_worker_can_view_own_disbursements_only(self) -> None:
        self.create_user()
        self.client.post("/logout")
        self.login(
            email="user@example.invalid",
            password="Standard-User-Test-Password-0001!",
            totp_secret="KRSXG5DSNFXGOIDB",
        )
        self.assertEqual(self.client.get("/my/disbursements").status_code, 200)
        self.assertEqual(self.client.get("/disbursements").status_code, 403)

    def test_invalid_inputs_and_unavailable_actions(self) -> None:
        self.assertEqual(
            self.client.get("/disbursements?page=invalid").status_code, 400
        )
        self.assertEqual(
            self.client.get(f"/disbursements/{self.worker_id}?page=0").status_code,
            400,
        )
        self.assertEqual(
            self.client.get(f"/disbursements/{self.worker_id}?page=999").status_code,
            302,
        )
        self.assertEqual(self.client.get("/disbursements/999999").status_code, 404)
        self.assertEqual(self.client.get("/disbursements/999999/new").status_code, 404)
        self.assertEqual(self.client.get("/disbursements/999999/edit").status_code, 404)
        self.assertEqual(
            self.client.get("/disbursements/999999/unknown").status_code, 404
        )

        path = f"/disbursements/{self.worker_id}/new"
        self.authorize_sensitive_action(path)
        self.assertEqual(self.client.get(path).status_code, 200)
        valid = {
            "date": date.today().isoformat(),
            "type": "DISBURSEMENT",
            "transaction_id": "ACH-1",
            "amount": "10.00",
        }
        for changes in ({"date": "invalid"}, {"amount": "invalid"}, {"amount": "0"}):
            with self.subTest(changes=changes):
                self.assertEqual(
                    self.client.post(path, data=valid | changes).status_code, 409
                )
        with session_scope(self.app) as database:
            self.assertIsNone(database.scalar(select(Disbursement)))

    def test_member_only_transaction_types_require_member_account(self) -> None:
        with session_scope(self.app) as database:
            worker = database.get(User, self.worker_id)
            assert worker is not None
            worker.user_type = "subcontractor"
        path = f"/disbursements/{self.worker_id}/new"
        self.authorize_sensitive_action(path)
        form = self.client.get(path)
        self.assertNotIn(b'value="IN_KIND"', form.data)
        self.assertNotIn(b'value="RETAINED_EARNINGS"', form.data)
        for kind, reference in (("IN_KIND", "PURCHASE-1"), ("RETAINED_EARNINGS", "")):
            with self.subTest(kind=kind):
                response = self.client.post(
                    path,
                    data={
                        "date": date.today().isoformat(),
                        "type": kind,
                        "transaction_id": reference,
                        "amount": "10.00",
                    },
                )
                self.assertEqual(response.status_code, 409)
                self.assertIn(b"only for LLC Members", response.data)

    def test_member_only_records_block_reclassification(self) -> None:
        with session_scope(self.app) as database:
            worker = database.get(User, self.worker_id)
            assert worker is not None
            create_disbursement(
                database,
                user_id=worker.id,
                actor_id=worker.id,
                kind="IN_KIND",
                date_value=date.today(),
                transaction_id="PURCHASE-1",
                amount_cents=100,
                notes=None,
            )
            database.commit()
            values = {
                "first_name": worker.first_name,
                "last_name": worker.last_name,
                "email": worker.email,
                "user_type": "subcontractor",
            }
        path = f"/users/{self.worker_id}/edit"
        self.assertEqual(self.client.post(path, data=values).status_code, 400)
        with session_scope(self.app) as database:
            worker = database.get(User, self.worker_id)
            assert worker is not None
            self.assertEqual(worker.user_type, "llc_member")
            create_disbursement(
                database,
                user_id=worker.id,
                actor_id=worker.id,
                kind="RETAINED_EARNINGS",
                date_value=date.today(),
                transaction_id=None,
                amount_cents=100,
                notes=None,
            )
            database.commit()
        self.assertEqual(self.client.post(path, data=values).status_code, 400)

    def test_disbursement_field_guards(self) -> None:
        with session_scope(self.app) as database:
            worker = database.get(User, self.worker_id)
            assert worker is not None
            valid = {
                "kind": "DISBURSEMENT",
                "date_value": date.today(),
                "transaction_id": "ACH-1",
                "amount_cents": 100,
                "notes": None,
            }
            invalid = (
                {"kind": "UNKNOWN"},
                {"amount_cents": 0},
                {"date_value": date.today() + timedelta(days=1)},
                {"transaction_id": None},
                {"transaction_id": "A" * 21},
                {"notes": "N" * 2001},
                {"kind": "RETAINED_EARNINGS", "transaction_id": "ACH-1"},
            )
            for changes in invalid:
                with self.subTest(changes=changes):
                    with self.assertRaises(InvoiceDomainError):
                        _validated_values(worker, **(valid | changes))

    def test_disbursement_state_and_balance_guards(self) -> None:
        with session_scope(self.app) as database:
            with self.assertRaises(InvoiceDomainError):
                create_disbursement(
                    database,
                    user_id=999999,
                    actor_id=self.worker_id,
                    kind="DISBURSEMENT",
                    date_value=date.today(),
                    transaction_id="ACH-1",
                    amount_cents=100,
                    notes=None,
                )
            database.rollback()
            create_disbursement(
                database,
                user_id=self.worker_id,
                actor_id=self.worker_id,
                kind="DISBURSEMENT",
                date_value=date.today(),
                transaction_id="ACH-1",
                amount_cents=1000,
                notes=None,
            )
            database.commit()
            with self.assertRaisesRegex(InvoiceDomainError, "exceeds"):
                create_disbursement(
                    database,
                    user_id=self.worker_id,
                    actor_id=self.worker_id,
                    kind="DISBURSEMENT",
                    date_value=date.today(),
                    transaction_id="ACH-2",
                    amount_cents=5000,
                    notes=None,
                )

    def test_transaction_ids_are_required_and_never_reusable(self) -> None:
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None
            entry.transaction_number = "LEGACY-1"
            database.commit()
            for reference in (None, "", "  "):
                with self.subTest(reference=reference):
                    with self.assertRaisesRegex(InvoiceDomainError, "required"):
                        require_available_transaction_id(database, reference)
            with self.assertRaisesRegex(InvoiceDomainError, "invalid characters"):
                require_available_transaction_id(database, "bad\nreference")
            with self.assertRaisesRegex(InvoiceDomainError, "too long"):
                require_available_transaction_id(database, "W" * 21)
            self.assertEqual(
                require_available_transaction_id(database, "W" * 20), "W" * 20
            )
            for reference in ("LEGACY-1", "PAYMENT-1"):
                with self.subTest(reference=reference):
                    with self.assertRaisesRegex(InvoiceDomainError, "already in use"):
                        require_available_transaction_id(database, reference)
            item = create_disbursement(
                database,
                user_id=self.worker_id,
                actor_id=self.worker_id,
                kind="DISBURSEMENT",
                date_value=date.today(),
                transaction_id="ACH-1",
                amount_cents=100,
                notes=None,
            )
            database.commit()
            for reference in ("ACH-1", "PAYMENT-1", "LEGACY-1"):
                with self.subTest(reference=reference):
                    with self.assertRaisesRegex(InvoiceDomainError, "already in use"):
                        create_disbursement(
                            database,
                            user_id=self.worker_id,
                            actor_id=self.worker_id,
                            kind="DISBURSEMENT",
                            date_value=date.today(),
                            transaction_id=reference,
                            amount_cents=100,
                            notes=None,
                        )
                    database.rollback()
            self.assertEqual(item.transaction_id, "ACH-1")
            with self.assertRaisesRegex(InvoiceDomainError, "already in use"):
                refund_invoice(database, self.invoice_id, transaction_id="ACH-1")
            database.rollback()
            refund_invoice(database, self.invoice_id, transaction_id="REFUND-1")
            database.commit()
            with self.assertRaisesRegex(InvoiceDomainError, "already in use"):
                require_available_transaction_id(database, "REFUND-1")
