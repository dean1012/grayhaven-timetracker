"""Public client and contract references retain independent database keys."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from werkzeug.routing import ValidationError

from grayhaven_timetracker.database import session_scope
from grayhaven_timetracker.invoices import create_invoice, preview_invoice
from grayhaven_timetracker.models import Client, Contract, Task, TimeEntry
from grayhaven_timetracker.public_ids import (
    ClientNumberConverter,
    ContractNumberConverter,
    InvoiceNumberConverter,
    find_client,
    find_contract,
    public_audit_details,
)
from tests.helpers import AppTestCase


class PublicNumberTests(AppTestCase):
    def test_missing_public_references_are_rejected(self) -> None:
        self.seed_contract()
        with self.app.app_context(), session_scope(self.app) as database:
            self.assertIsNone(find_client(database, "1"))
            self.assertIsNone(find_contract(database, "1-1"))
            client = ClientNumberConverter(self.app.url_map)
            contract = ContractNumberConverter(self.app.url_map)
            invoice = InvoiceNumberConverter(self.app.url_map)
            for converter, reference in (
                (client, "999"),
                (contract, "999-001"),
                (invoice, "999-001-001"),
            ):
                with self.subTest(reference=reference):
                    with self.assertRaises(ValidationError):
                        converter.to_python(reference)
            with self.assertRaises(ValidationError):
                contract.to_python("0")
            self.assertEqual(client.to_url(0), "0")
            self.assertEqual(contract.to_url(0), "0")
            for converter in (client, contract, invoice):
                with self.assertRaises(ValueError):
                    converter.to_url(9999)

    def test_new_client_numbers_are_unique_and_contracts_restart(self) -> None:
        self.login()
        existing = self.seed_contract()
        continued = self.client.post(
            "/contracts/new/001",
            data={
                "name": "Second Existing Contract",
                "contact_name": "Contact",
                "contact_email": "continued@example.invalid",
                "hourly_rate": "55",
            },
        )
        self.assertEqual(continued.status_code, 302)
        self.assertEqual(self.client.get("/contracts/001-002").status_code, 200)
        responses = [
            self.client.post(
                "/clients/new",
                data={
                    "name": f"New Client {number}",
                    "contact_name": "Contact",
                    "contact_email": f"client{number}@example.invalid",
                },
            )
            for number in (1, 2)
        ]
        with session_scope(self.app) as database:
            clients = database.scalars(
                select(Client).where(Client.name.like("New Client %"))
            ).all()
            assert len(clients) == 2
            numbers = {client.public_number for client in clients}
            self.assertEqual(len(numbers), 2)
            self.assertTrue(all(100 <= number <= 999 for number in numbers))
            client = clients[0]
            client_key = client.id
            client_number = client.display_number
            original = database.get(Client, existing.client_id)
            assert original is not None
            self.assertEqual(original.display_number, "001")
        self.assertEqual(responses[0].status_code, 302)
        self.assertEqual(responses[1].status_code, 302)
        self.assertEqual(self.client.get(f"/clients/{client_number}").status_code, 200)
        self.assertEqual(self.client.get(f"/clients/{client_key}").status_code, 404)
        created = self.client.post(
            f"/contracts/new/{client_number}",
            data={
                "name": "First Contract",
                "contact_name": "Contact",
                "contact_email": "contract@example.invalid",
                "hourly_rate": "55",
            },
        )
        self.assertEqual(created.status_code, 302)
        with session_scope(self.app) as database:
            contract = database.scalar(
                select(Contract).where(Contract.client_id == client_key)
            )
            assert contract is not None
            reference = contract.public_ref
            contract_key = contract.id
            self.assertEqual(contract.public_number, 1)
        self.assertEqual(reference, f"{client_number}-001")
        self.assertEqual(self.client.get(f"/contracts/{reference}").status_code, 200)
        self.assertEqual(self.client.get(f"/contracts/{contract_key}").status_code, 404)

        with session_scope(self.app) as database:
            contract = database.get(Contract, contract_key)
            original_entry = database.get(TimeEntry, existing.entry_id)
            assert contract is not None and original_entry is not None
            start = datetime(2026, 7, 16, 1)
            entry = TimeEntry(
                user=original_entry.user,
                task=Task(contract=contract, name="Sample Task"),
                started_at=start,
                stopped_at=start + timedelta(hours=1),
            )
            database.add(entry)
            database.commit()
            preview = preview_invoice(
                database,
                contract_id=contract.id,
                range_start_utc=start,
                range_end_utc=entry.stopped_at + timedelta(minutes=1),
                timezone_name="UTC",
            )
            invoice = create_invoice(
                database,
                contract_id=contract.id,
                range_start_utc=start,
                range_end_utc=entry.stopped_at + timedelta(minutes=1),
                timezone_name="UTC",
                expected_fingerprint=preview.fingerprint,
            )
            database.commit()
            invoice_number = invoice.invoice_number
            invoice_key = invoice.id
        self.assertEqual(invoice_number, f"{client_number}-001-001")
        self.assertEqual(
            self.client.get(f"/invoices/{invoice_number}").status_code, 200
        )
        self.assertEqual(self.client.get(f"/invoices/{invoice_key}").status_code, 404)

    def test_historical_audit_references_render_public_numbers(self) -> None:
        details = {
            "client": "Client (ID: 2)",
            "contract": "Contract (ID: 7)",
            "invoice_id": 3,
            "changes": {"Client": {"from": "Old (ID: 2)", "to": "New (ID: 2)"}},
        }
        visible = public_audit_details(
            details, {2: "174"}, {7: "174-001"}, {3: "174-001-001"}
        )
        self.assertEqual(visible["client"], "Client (ID: 174)")
        self.assertEqual(visible["contract"], "Contract (ID: 174-001)")
        self.assertEqual(visible["invoice_number"], "174-001-001")
        self.assertEqual(visible["changes"]["Client"]["from"], "Old (ID: 174)")

        current = public_audit_details(
            {"client": "Sample Client (ID: 174)", "_public_number_labels": True},
            {2: "174"},
            {},
            {},
        )
        self.assertEqual(current, {"client": "Sample Client (ID: 174)"})
