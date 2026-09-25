"""Translate public business numbers at the HTTP boundary."""

from __future__ import annotations

import re
from typing import Any, cast

from flask import current_app
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session
from werkzeug.routing import BaseConverter, ValidationError

from .models import Client, Contract, Invoice


def public_audit_details(
    details: dict[str, Any],
    clients: dict[int, str],
    contracts: dict[int, str],
    invoices: dict[int, str],
) -> dict[str, Any]:
    """Show historical business references using current public numbers."""
    mappings = {"client": clients, "contract": contracts, "invoice": invoices}
    labels_are_public = details.get("_public_number_labels") is True

    def convert(value: Any, field: str) -> Any:
        mapping = mappings.get(field)
        if isinstance(value, dict):
            return {
                key: convert(item, field if key in {"from", "to"} else key.lower())
                for key, item in value.items()
            }
        if mapping is None:
            return value
        if isinstance(value, int):
            return mapping.get(value, "Unavailable")
        if not isinstance(value, str):
            return value
        if labels_are_public:
            return value

        def replace(match: re.Match[str]) -> str:
            return f"(ID: {mapping.get(int(match.group(1)), 'Unavailable')})"

        return re.sub(r"\(ID: ([0-9]+)\)", replace, value)

    converted = {}
    for key, value in details.items():
        if key == "_public_number_labels":
            continue
        field = key.lower().removeprefix("previous_").removesuffix("_id")
        visible_key = "invoice_number" if key == "invoice_id" else key
        converted[visible_key] = convert(value, field)
    return converted


def _engine() -> Engine:
    return cast(Engine, current_app.extensions["database_engine"])


def find_client(database: Session, number: str) -> Client | None:
    if re.fullmatch(r"[0-9]{3}", number) is None:
        return None
    return database.scalar(select(Client).where(Client.public_number == int(number)))


def find_contract(database: Session, reference: str) -> Contract | None:
    if re.fullmatch(r"[0-9]{3}-[0-9]{3}", reference) is None:
        return None
    client_number, contract_number = (int(part) for part in reference.split("-"))
    return database.scalar(
        select(Contract)
        .join(Client, Client.id == Contract.client_id)
        .where(
            Client.public_number == client_number,
            Contract.public_number == contract_number,
        )
    )


class ClientNumberConverter(BaseConverter):
    regex = r"[0-9]{3}"

    def to_python(self, value: str) -> int:
        with _engine().connect() as connection:
            identifier = connection.execute(
                select(Client.id).where(Client.public_number == int(value))
            ).scalar()
        if identifier is None:
            raise ValidationError()
        return int(identifier)

    def to_url(self, value: Any) -> str:
        if int(value) == 0:
            return "0"
        with _engine().connect() as connection:
            number = connection.execute(
                select(Client.public_number).where(Client.id == int(value))
            ).scalar()
        if number is None:
            raise ValueError("Client does not exist")
        return f"{int(number):03d}"


class ContractNumberConverter(BaseConverter):
    regex = r"(?:[0-9]{3}-[0-9]{3}|0)"

    def to_python(self, value: str) -> int:
        if value == "0":
            raise ValidationError()
        client_number, contract_number = (int(part) for part in value.split("-"))
        with _engine().connect() as connection:
            identifier = connection.execute(
                select(Contract.id)
                .join(Client, Client.id == Contract.client_id)
                .where(
                    Client.public_number == client_number,
                    Contract.public_number == contract_number,
                )
            ).scalar()
        if identifier is None:
            raise ValidationError()
        return int(identifier)

    def to_url(self, value: Any) -> str:
        if int(value) == 0:
            return "0"
        with _engine().connect() as connection:
            numbers = connection.execute(
                select(Client.public_number, Contract.public_number)
                .join(Contract, Contract.client_id == Client.id)
                .where(Contract.id == int(value))
            ).one_or_none()
        if numbers is None:
            raise ValueError("Contract does not exist")
        return f"{int(numbers[0]):03d}-{int(numbers[1]):03d}"


class InvoiceNumberConverter(BaseConverter):
    regex = r"[0-9]{3}-[0-9]{3}-[0-9]{3}"

    def to_python(self, value: str) -> int:
        with _engine().connect() as connection:
            identifier = connection.execute(
                select(Invoice.id).where(Invoice.invoice_number == value)
            ).scalar()
        if identifier is None:
            raise ValidationError()
        return int(identifier)

    def to_url(self, value: Any) -> str:
        with _engine().connect() as connection:
            number = connection.execute(
                select(Invoice.invoice_number).where(Invoice.id == int(value))
            ).scalar()
        if number is None:
            raise ValueError("Invoice does not exist")
        return str(number)
