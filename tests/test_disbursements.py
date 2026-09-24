"""Disbursement permissions, balances, and correction workflows."""

from datetime import date, timedelta

from sqlalchemy import select

from grayhaven_timetracker.database import session_scope
from grayhaven_timetracker.disbursements import (
    _validated_values,
    archive_disbursement,
    create_disbursement,
    unarchive_disbursement,
    update_disbursement,
)
from grayhaven_timetracker.invoices import (
    InvoiceDomainError,
    create_invoice,
    mark_invoice_paid,
    preview_invoice,
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
            mark_invoice_paid(database, self.invoice_id)
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
        with session_scope(self.app) as database:
            item = database.scalar(select(Disbursement))
            assert item is not None
            item_id = item.id
            self.assertEqual(item.amount_cents, 1000)
            self.assertIsNotNone(
                database.scalar(
                    select(AuditEvent).where(AuditEvent.event == "disbursement_created")
                )
            )

        edit_path = f"/disbursements/{item_id}/edit"
        self.authorize_sensitive_action(edit_path)
        edited = self.client.post(
            edit_path,
            data={
                "date": date.today().isoformat(),
                "type": "IN_KIND",
                "transaction_id": "PURCHASE-1",
                "amount": "12.00",
                "notes": "Equipment",
                "correction_reason": "Correct transaction",
            },
        )
        self.assertEqual(edited.status_code, 302)
        archive_path = f"/disbursements/{item_id}/archive"
        self.authorize_sensitive_action(archive_path)
        archived = self.client.post(
            archive_path, data={"correction_reason": "Correct transaction"}
        )
        self.assertEqual(archived.status_code, 302)
        self.assertIn(
            b"PURCHASE-1",
            self.client.get(f"/disbursements/{self.worker_id}?view=archived").data,
        )
        self.assertNotIn(b"PURCHASE-1", self.client.get("/my/disbursements").data)
        unarchive_path = f"/disbursements/{item_id}/unarchive"
        self.authorize_sensitive_action(unarchive_path)
        self.assertEqual(
            self.client.post(
                unarchive_path,
                data={"correction_reason": "Restore transaction"},
            ).status_code,
            302,
        )
        self.assertIn(b"PURCHASE-1", self.client.get("/my/disbursements").data)

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
            item = create_disbursement(
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
            item_id = item.id
        self.assertEqual(
            self.client.get(f"/disbursements/{item_id}/unarchive").status_code,
            409,
        )
        with session_scope(self.app) as database:
            archive_disbursement(database, item_id, actor_id=self.worker_id)
            database.commit()
        self.assertEqual(
            self.client.get(f"/disbursements/{item_id}/edit").status_code, 409
        )

    def test_retained_earnings_requires_member_type(self) -> None:
        with session_scope(self.app) as database:
            worker = database.get(User, self.worker_id)
            assert worker is not None
            worker.user_type = "subcontractor"
        path = f"/disbursements/{self.worker_id}/new"
        self.authorize_sensitive_action(path)
        response = self.client.post(
            path,
            data={
                "date": date.today().isoformat(),
                "type": "RETAINED_EARNINGS",
                "amount": "10.00",
            },
        )
        self.assertEqual(response.status_code, 409)
        self.assertIn(b"only for LLC Members", response.data)

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
                {"transaction_id": "A" * 101},
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
            item = create_disbursement(
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
            item_id = item.id

        with session_scope(self.app) as database:
            with self.assertRaises(InvoiceDomainError):
                update_disbursement(
                    database,
                    item_id,
                    kind="DISBURSEMENT",
                    date_value=date.today(),
                    transaction_id="ACH-1",
                    amount_cents=5600,
                    notes=None,
                )
            database.rollback()
            with self.assertRaises(InvoiceDomainError):
                update_disbursement(
                    database,
                    999999,
                    kind="DISBURSEMENT",
                    date_value=date.today(),
                    transaction_id="ACH-1",
                    amount_cents=100,
                    notes=None,
                )
            database.rollback()
            with self.assertRaises(InvoiceDomainError):
                unarchive_disbursement(database, item_id)
            database.rollback()
            archive_disbursement(database, item_id, actor_id=self.worker_id)
            database.commit()

        with session_scope(self.app) as database:
            with self.assertRaises(InvoiceDomainError):
                archive_disbursement(database, item_id, actor_id=self.worker_id)
            database.rollback()
            with self.assertRaises(InvoiceDomainError):
                update_disbursement(
                    database,
                    item_id,
                    kind="DISBURSEMENT",
                    date_value=date.today(),
                    transaction_id="ACH-1",
                    amount_cents=100,
                    notes=None,
                )

    def test_unarchive_rechecks_member_type_and_available_balance(self) -> None:
        with session_scope(self.app) as database:
            item = create_disbursement(
                database,
                user_id=self.worker_id,
                actor_id=self.worker_id,
                kind="RETAINED_EARNINGS",
                date_value=date.today(),
                transaction_id=None,
                amount_cents=1000,
                notes=None,
            )
            database.commit()
            item_id = item.id
        with session_scope(self.app) as database:
            archive_disbursement(database, item_id, actor_id=self.worker_id)
            worker = database.get(User, self.worker_id)
            assert worker is not None
            worker.user_type = "subcontractor"
            database.commit()
        with session_scope(self.app) as database:
            with self.assertRaises(InvoiceDomainError):
                unarchive_disbursement(database, item_id)
            database.rollback()
            worker = database.get(User, self.worker_id)
            assert worker is not None
            worker.user_type = "llc_member"
            database.commit()
        with session_scope(self.app) as database:
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
            database.commit()
        with session_scope(self.app) as database:
            with self.assertRaises(InvoiceDomainError):
                unarchive_disbursement(database, item_id)
