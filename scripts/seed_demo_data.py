#!/usr/bin/env python3
"""Create representative local UAT data without modifying existing records."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import select

from grayhaven_timetracker import create_app
from grayhaven_timetracker.database import session_scope
from grayhaven_timetracker.models import (
    Client,
    Contract,
    Subtask,
    Task,
    TimeEntry,
    User,
)


def main() -> int:
    app = create_app()
    with session_scope(app) as database:
        if database.scalar(select(Client).where(Client.name == "Pellera")):
            print("Demo data already exists.")
            return 0
        admin = database.scalar(select(User).where(User.role == "admin"))
        if admin is None:
            raise RuntimeError("An administrator must exist before seeding demo data")
        client = Client(
            name="Pellera",
            contact_name="Alex Example",
            contact_email="alex@example.invalid",
        )
        contract = Contract(
            client=client,
            name="Hamilton Beach - Phase 1",
            contact_name="Alex Example",
            contact_email="alex@example.invalid",
            hourly_rate_cents=int(Decimal("55.00") * 100),
        )
        discovery = Task(contract=contract, name="Discovery")
        server = Subtask(task=discovery, name="Server 1")
        implementation = Task(contract=contract, name="Implementation")
        now = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
        database.add_all(
            [
                client,
                contract,
                discovery,
                server,
                implementation,
                TimeEntry(
                    user=admin,
                    task=discovery,
                    subtask=server,
                    started_at=now - timedelta(hours=3, minutes=20),
                    stopped_at=now - timedelta(hours=2, minutes=20),
                ),
                TimeEntry(
                    user=admin,
                    task=implementation,
                    subtask=None,
                    started_at=now - timedelta(hours=2),
                    stopped_at=now - timedelta(minutes=35, seconds=17),
                ),
            ]
        )
    print("Demo data created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
