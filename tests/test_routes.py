"""End-to-end route, permission, security-header, and workflow tests."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

import pyotp
from sqlalchemy import select, text

from grayhaven_timetracker import routes
from grayhaven_timetracker.auth import LoginLimiter, verify_password
from grayhaven_timetracker.database import get_session, session_scope
from grayhaven_timetracker.models import (
    Client,
    Contract,
    Subtask,
    Task,
    TimeEntry,
    User,
)
from grayhaven_timetracker.routes import local_datetime_to_utc
from tests.helpers import (
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    ADMIN_TOTP_SECRET,
    AppTestCase,
)


class AuthenticationRouteTests(AppTestCase):
    def test_login_logout_head_and_safe_next_workflow(self) -> None:
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertIn("next=/", self.client.get("/").location)
        self.assertEqual(self.client.get("/login").status_code, 200)
        self.assertEqual(self.client.head("/login").status_code, 200)
        rejected = self.client.post(
            "/login", data={"email": ADMIN_EMAIL, "password": "wrong", "totp": "000000"}
        )
        self.assertEqual(rejected.status_code, 401)
        rejected_totp = self.client.post(
            "/login",
            data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "totp": "000000"},
        )
        self.assertEqual(rejected_totp.status_code, 401)
        accepted = self.client.post(
            "/login?next=/profile",
            data={
                "email": f" {ADMIN_EMAIL.upper()} ",
                "password": ADMIN_PASSWORD,
                "totp": pyotp.TOTP(ADMIN_TOTP_SECRET).now(),
            },
        )
        self.assertEqual(accepted.location, "/profile")
        self.assertEqual(self.client.get("/login").location, "/")
        self.assertEqual(self.client.post("/logout").status_code, 302)
        self.assertEqual(self.client.get("/profile").status_code, 302)

    def test_login_rejects_disabled_user_and_rate_limits_failures(self) -> None:
        user = self.create_user(enabled=False)
        rejected = self.client.post(
            "/login",
            data={
                "email": user.email,
                "password": "Standard-User-Test-Password-0001!",
                "totp": pyotp.TOTP(user.totp_secret or "").now(),
            },
        )
        self.assertEqual(rejected.status_code, 401)
        routes.login_limiter = LoginLimiter(limit=1)
        first = self.client.post(
            "/login", data={"email": "unknown@example.invalid", "password": "wrong"}
        )
        second = self.client.post(
            "/login", data={"email": "unknown@example.invalid", "password": "wrong"}
        )
        self.assertEqual(first.status_code, 401)
        self.assertEqual(second.status_code, 429)

    def test_csrf_and_request_size_fail_closed(self) -> None:
        self.app.config["WTF_CSRF_ENABLED"] = True
        self.assertEqual(
            self.client.post(
                "/login", data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
            ).status_code,
            400,
        )
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.app.config["MAX_CONTENT_LENGTH"] = 128
        response = self.client.post(
            "/login",
            data={"email": ADMIN_EMAIL, "password": "x" * 1024},
        )
        self.assertEqual(response.status_code, 413)


class SecurityAndErrorRouteTests(AppTestCase):
    def test_security_headers_cache_policy_health_and_errors(self) -> None:
        response = self.client.get("/login", base_url="https://example.invalid")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn(
            "frame-ancestors 'none'", response.headers["Content-Security-Policy"]
        )
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn("max-age=31536000", response.headers["Strict-Transport-Security"])
        health = self.client.get("/health")
        self.assertEqual(health.json, {"status": "ok"})
        self.assertEqual(health.headers["Cache-Control"], "no-store")
        self.assertEqual(self.client.get("/missing").status_code, 404)
        self.assertEqual(self.client.post("/health").status_code, 405)

    def test_health_failure_and_database_error_return_generic_pages(self) -> None:
        self.app.config["PROPAGATE_EXCEPTIONS"] = False

        @self.app.get("/test-database-error")
        def database_error() -> str:
            get_session().execute(text("SELECT * FROM missing_test_table"))
            return "unreachable"

        with patch(
            "grayhaven_timetracker.routes.health_check", side_effect=RuntimeError
        ):
            self.assertEqual(self.client.get("/health").status_code, 503)

        response = self.client.get("/test-database-error")
        self.assertEqual(response.status_code, 500)
        self.assertIn(b"unexpected application error", response.data)
        with session_scope(self.app) as database:
            self.assertEqual(database.execute(text("SELECT 1")).scalar_one(), 1)

    def test_branding_route_serves_only_files_inside_branding_root(self) -> None:
        branding = self.root / "branding"
        branding.mkdir()
        logo = branding / "logo.svg"
        logo.write_text("<svg></svg>", encoding="utf-8")
        outside = self.root / "outside.svg"
        outside.write_text("outside", encoding="utf-8")
        (branding / "escape.svg").symlink_to(outside)
        response = self.client.get("/branding/logo.svg")
        self.assertEqual(response.status_code, 200)
        response.close()
        self.assertEqual(self.client.get("/branding/escape.svg").status_code, 404)
        self.assertEqual(self.client.get("/branding/missing.svg").status_code, 404)


class ClientContractTaskRouteTests(AppTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.login()

    def test_client_and_contract_creation_validation_and_display(self) -> None:
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/clients/new").status_code, 200)
        invalid_client = self.client.post(
            "/clients/new",
            data={"name": "", "contact_name": "Contact", "contact_email": "invalid"},
        )
        self.assertEqual(invalid_client.status_code, 400)
        created = self.client.post(
            "/clients/new",
            data={
                "name": "Client One",
                "contact_name": "Client Contact",
                "contact_email": "CLIENT@EXAMPLE.INVALID",
            },
        )
        self.assertEqual(created.status_code, 302)
        with session_scope(self.app) as database:
            client = database.scalar(select(Client).where(Client.name == "Client One"))
            assert client is not None
            client_id = client.id
            self.assertEqual(client.contact_email, "client@example.invalid")
        self.assertEqual(self.client.get(f"/clients/{client_id}").status_code, 200)
        self.assertEqual(self.client.get("/clients/9999").status_code, 404)
        for rate in ("invalid", "-1", "1000000.01"):
            with self.subTest(rate=rate):
                response = self.client.post(
                    f"/contracts/new/{client_id}",
                    data={
                        "name": "Contract",
                        "contact_name": "Contract Contact",
                        "contact_email": "contract@example.invalid",
                        "hourly_rate": rate,
                    },
                )
                self.assertEqual(response.status_code, 400)
        created_contract = self.client.post(
            f"/contracts/new/{client_id}",
            data={
                "name": "Contract One",
                "contact_name": "Contract Contact",
                "contact_email": "contract@example.invalid",
                "hourly_rate": "55.005",
            },
        )
        self.assertEqual(created_contract.status_code, 302)
        with session_scope(self.app) as database:
            contract = database.scalar(
                select(Contract).where(Contract.name == "Contract One")
            )
            assert contract is not None
            self.assertEqual(contract.hourly_rate_cents, 5501)

    def test_task_subtask_rename_delete_and_time_guards(self) -> None:
        seed = self.seed_contract()
        self.assertEqual(
            self.client.get(f"/contracts/{seed.contract_id}").status_code, 200
        )
        self.assertEqual(self.client.get("/contracts/9999").status_code, 404)
        self.assertEqual(
            self.client.post(
                f"/tasks/{seed.contract_id}/new", data={"name": ""}
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post(
                f"/tasks/{seed.contract_id}/new", data={"name": "Unused"}
            ).status_code,
            302,
        )
        with session_scope(self.app) as database:
            unused = database.scalar(select(Task).where(Task.name == "Unused"))
            assert unused is not None
            unused_id = unused.id
        self.assertEqual(
            self.client.post(
                f"/subtasks/{unused_id}/new", data={"name": "Child"}
            ).status_code,
            302,
        )
        with session_scope(self.app) as database:
            child = database.scalar(select(Subtask).where(Subtask.task_id == unused_id))
            assert child is not None
            child_id = child.id
        self.assertEqual(
            self.client.post(
                f"/tasks/{unused_id}/rename", data={"name": "Renamed"}
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post(
                f"/subtasks/{child_id}/rename", data={"name": "Renamed child"}
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post(f"/subtasks/{child_id}/delete").status_code, 302
        )
        self.assertEqual(
            self.client.post(f"/tasks/{unused_id}/delete").status_code, 302
        )
        self.assertEqual(
            self.client.post(f"/tasks/{seed.task_id}/delete").status_code, 409
        )
        self.assertEqual(
            self.client.post(f"/subtasks/{seed.subtask_id}/delete").status_code, 409
        )


class TimerAndPermissionRouteTests(AppTestCase):
    USER_PASSWORD = "Standard-User-Test-Password-0001!"
    USER_SECRET = "KRSXG5DSNFXGOIDB"

    def setUp(self) -> None:
        super().setUp()
        self.user = self.create_user(
            password=self.USER_PASSWORD, totp_secret=self.USER_SECRET
        )
        self.seed = self.seed_contract(entry_user_id=self.user.id)
        self.login(
            email=self.user.email,
            password=self.USER_PASSWORD,
            totp_secret=self.USER_SECRET,
        )

    def test_standard_user_permissions_and_timer_lifecycle(self) -> None:
        self.assertEqual(self.client.get("/users").status_code, 403)
        self.assertEqual(
            self.client.get(f"/reports/{self.seed.contract_id}").status_code, 403
        )
        self.assertEqual(self.client.post("/clients/new").status_code, 403)
        started = self.client.post(
            "/timer/start",
            data={"task_id": self.seed.task_id, "subtask_id": self.seed.subtask_id},
        )
        self.assertEqual(started.status_code, 302)
        self.assertEqual(
            self.client.post(
                "/timer/start", data={"task_id": self.seed.task_id}
            ).status_code,
            303,
        )
        with session_scope(self.app) as database:
            active = database.scalar(
                select(TimeEntry).where(
                    TimeEntry.user_id == self.user.id, TimeEntry.stopped_at.is_(None)
                )
            )
            assert active is not None
            active_id = active.id
        dashboard = self.client.get("/")
        self.assertIn(b"ACTIVE TIMER", dashboard.data)
        stopped = self.client.post(
            f"/timer/stop/{active_id}", data={"next": "https://evil.invalid"}
        )
        self.assertEqual(stopped.location, f"/contracts/{self.seed.contract_id}")
        self.assertEqual(self.client.post(f"/timer/stop/{active_id}").status_code, 403)

    def test_timer_rejects_invalid_and_cross_task_subtask_assignments(self) -> None:
        self.assertEqual(
            self.client.post("/timer/start", data={"task_id": "x"}).status_code, 400
        )
        self.assertEqual(
            self.client.post("/timer/start", data={"task_id": 9999}).status_code, 404
        )
        with session_scope(self.app) as database:
            other = Task(contract_id=self.seed.contract_id, name="Other")
            database.add(other)
            database.flush()
            other_id = other.id
        response = self.client.post(
            "/timer/start",
            data={"task_id": other_id, "subtask_id": self.seed.subtask_id},
        )
        self.assertEqual(response.status_code, 400)


class ProfileAndUserAdministrationTests(AppTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.login()

    def test_profile_name_and_password_change_require_valid_inputs(self) -> None:
        self.assertEqual(self.client.get("/profile").status_code, 200)
        self.assertEqual(
            self.client.post(
                "/profile/name", data={"first_name": "", "last_name": "Operator"}
            ).status_code,
            302,
        )
        self.client.post(
            "/profile/name", data={"first_name": "Updated", "last_name": "Operator"}
        )
        cases = [
            {
                "current_password": "wrong",
                "new_password": "New-Password-For-Testing-0000001!",
                "confirm_password": "New-Password-For-Testing-0000001!",
            },
            {
                "current_password": ADMIN_PASSWORD,
                "new_password": ADMIN_PASSWORD,
                "confirm_password": ADMIN_PASSWORD,
            },
            {
                "current_password": ADMIN_PASSWORD,
                "new_password": "New-Password-For-Testing-0000001!",
                "confirm_password": "different",
            },
            {
                "current_password": ADMIN_PASSWORD,
                "new_password": "short",
                "confirm_password": "short",
            },
        ]
        for data in cases:
            with self.subTest(data=data):
                self.assertEqual(
                    self.client.post("/profile/password", data=data).status_code, 302
                )
        new_password = "New-Administrative-Password-For-Testing-0001!"
        changed = self.client.post(
            "/profile/password",
            data={
                "current_password": ADMIN_PASSWORD,
                "new_password": new_password,
                "confirm_password": new_password,
            },
        )
        self.assertEqual(changed.status_code, 302)
        self.assertEqual(self.client.get("/profile").status_code, 200)
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            self.assertEqual(admin.first_name, "Updated")
            self.assertTrue(verify_password(admin.password_hash, new_password))

    def test_totp_setup_confirmation_and_disable(self) -> None:
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.totp_secret = None
        setup = self.client.post("/profile/totp/setup")
        self.assertEqual(setup.status_code, 200)
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin and admin.pending_totp_secret
            pending = admin.pending_totp_secret
        self.assertEqual(
            self.client.post(
                "/profile/totp/confirm", data={"totp": "000000"}
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                "/profile/totp/confirm", data={"totp": pyotp.TOTP(pending).now()}
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post(
                "/profile/totp/disable",
                data={"current_password": "wrong", "totp": "000000"},
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                "/profile/totp/disable",
                data={
                    "current_password": ADMIN_PASSWORD,
                    "totp": pyotp.TOTP(pending).now(),
                },
            ).status_code,
            302,
        )

    def test_user_creation_role_changes_and_disable_stops_timer(self) -> None:
        self.assertEqual(self.client.get("/users/new").status_code, 200)
        invalid = self.client.post(
            "/users/new",
            data={
                "first_name": "",
                "last_name": "User",
                "email": "invalid",
                "password": "short",
            },
        )
        self.assertEqual(invalid.status_code, 400)
        password = "New-Standard-User-Password-For-Test-0001!"
        created = self.client.post(
            "/users/new",
            data={
                "first_name": "New",
                "last_name": "User",
                "email": "new-user@example.invalid",
                "password": password,
            },
        )
        self.assertEqual(created.status_code, 200)
        self.assertIn(b"Authenticator setup QR code", created.data)
        duplicate = self.client.post(
            "/users/new",
            data={
                "first_name": "New",
                "last_name": "User",
                "email": "new-user@example.invalid",
                "password": password,
            },
        )
        self.assertEqual(duplicate.status_code, 400)
        with session_scope(self.app) as database:
            user = database.scalar(
                select(User).where(User.email == "new-user@example.invalid")
            )
            assert user is not None
            user_id = user.id
            task = Task(
                contract=Contract(
                    client=Client(
                        name="Timer Client",
                        contact_name="Contact",
                        contact_email="contact@example.invalid",
                    ),
                    name="Timer Contract",
                    contact_name="Contact",
                    contact_email="contact@example.invalid",
                    hourly_rate_cents=5500,
                ),
                name="Timer Task",
            )
            database.add(
                TimeEntry(
                    user=user,
                    task=task,
                    started_at=datetime(2026, 7, 15, 12, 0, 0),
                )
            )
        self.assertEqual(
            self.client.post(f"/users/{user_id}/toggle-admin").status_code, 302
        )
        self.assertEqual(
            self.client.post(f"/users/{user_id}/toggle-admin").status_code, 302
        )
        self.assertEqual(
            self.client.post(f"/users/{user_id}/toggle-enabled").status_code, 302
        )
        with session_scope(self.app) as database:
            user = database.get(User, user_id)
            entry = database.scalar(
                select(TimeEntry).where(TimeEntry.user_id == user_id)
            )
            assert user and entry
            self.assertFalse(user.is_enabled)
            self.assertIsNotNone(entry.stopped_at)
        self.assertEqual(self.client.post("/users/1/toggle-enabled").status_code, 409)
        self.assertEqual(self.client.post("/users/1/toggle-admin").status_code, 409)


class ReportAndSessionRouteTests(AppTestCase):
    USER_PASSWORD = "Session-User-Test-Password-0001!"
    USER_SECRET = "KRSXG5DSNFXGOIDB"

    def setUp(self) -> None:
        super().setUp()
        self.user = self.create_user(
            password=self.USER_PASSWORD, totp_secret=self.USER_SECRET
        )
        self.seed = self.seed_contract(entry_user_id=self.user.id)

    def test_admin_report_html_and_pdf(self) -> None:
        self.login()
        html = self.client.get(f"/reports/{self.seed.contract_id}")
        self.assertEqual(html.status_code, 200)
        self.assertIn(b"Contract Time Report", html.data)
        pdf = self.client.get(f"/reports/{self.seed.contract_id}.pdf")
        self.assertEqual(pdf.status_code, 200)
        self.assertEqual(pdf.mimetype, "application/pdf")
        self.assertTrue(pdf.data.startswith(b"%PDF-"))
        self.assertEqual(self.client.get("/reports/9999").status_code, 404)
        self.assertEqual(self.client.get("/reports/9999.pdf").status_code, 404)

    def test_session_visibility_ownership_edit_delete_and_active_guards(self) -> None:
        user_client = self.app.test_client()
        self.login(
            user_client,
            email=self.user.email,
            password=self.USER_PASSWORD,
            totp_secret=self.USER_SECRET,
        )
        page = user_client.get(f"/contracts/{self.seed.contract_id}/sessions")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn(b"Admin Operator", page.data)
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            task = database.get(Task, self.seed.other_task_id)
            assert admin and task
            admin_entry = TimeEntry(
                user=admin,
                task=task,
                started_at=datetime(2026, 7, 15, 12, 0, 0),
                stopped_at=datetime(2026, 7, 15, 13, 0, 0),
            )
            database.add(admin_entry)
            database.flush()
            admin_entry_id = admin_entry.id
        self.assertEqual(
            user_client.get(f"/sessions/{admin_entry_id}/edit").status_code, 403
        )
        self.assertEqual(
            user_client.post(f"/sessions/{admin_entry_id}/delete").status_code, 403
        )
        edited = user_client.post(
            f"/sessions/{self.seed.entry_id}/edit",
            data={
                "assignment": str(self.seed.other_task_id),
                "started_at": "2026-07-15T08:15:30",
                "stopped_at": "2026-07-15T09:45:35",
            },
        )
        self.assertEqual(edited.status_code, 302)
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None
            self.assertEqual(entry.task_id, self.seed.other_task_id)
            self.assertEqual(entry.started_at, datetime(2026, 7, 15, 13, 15, 30))
        self.assertEqual(
            user_client.post(f"/sessions/{self.seed.entry_id}/delete").status_code, 302
        )
        with session_scope(self.app) as database:
            task = database.get(Task, self.seed.other_task_id)
            assert task is not None
            active = TimeEntry(
                user_id=self.user.id,
                task=task,
                started_at=datetime(2026, 7, 15, 16, 0, 0),
            )
            database.add(active)
            database.flush()
            active_id = active.id
        self.assertEqual(
            user_client.get(f"/sessions/{active_id}/edit").status_code, 409
        )
        self.assertEqual(
            user_client.post(f"/sessions/{active_id}/delete").status_code, 409
        )

    def test_session_edit_validation_and_admin_access(self) -> None:
        self.login()
        self.assertEqual(
            self.client.get(f"/sessions/{self.seed.entry_id}/edit").status_code, 200
        )
        cases = [
            {
                "assignment": "invalid",
                "started_at": "2026-07-15T08:00:00",
                "stopped_at": "2026-07-15T09:00:00",
            },
            {
                "assignment": str(self.seed.task_id),
                "started_at": "invalid",
                "stopped_at": "2026-07-15T09:00:00",
            },
            {
                "assignment": str(self.seed.task_id),
                "started_at": "2026-07-15T10:00:00",
                "stopped_at": "2026-07-15T09:00:00",
            },
            {
                "assignment": str(self.seed.task_id),
                "started_at": "2026-03-08T02:30:00",
                "stopped_at": "2026-03-08T03:30:00",
            },
        ]
        for data in cases:
            with self.subTest(data=data):
                self.assertEqual(
                    self.client.post(
                        f"/sessions/{self.seed.entry_id}/edit", data=data
                    ).status_code,
                    303,
                )
        self.assertEqual(self.client.get("/sessions/9999/edit").status_code, 404)
        self.assertEqual(self.client.post("/sessions/9999/delete").status_code, 404)

    def test_local_datetime_rejects_dst_edges_and_accepts_normal_time(self) -> None:
        self.assertEqual(
            local_datetime_to_utc("2026-07-15T12:34:56", "Time", "America/Chicago"),
            datetime(2026, 7, 15, 17, 34, 56),
        )
        for value in ("2026-03-08T02:30:00", "2026-11-01T01:30:00"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                local_datetime_to_utc(value, "Time", "America/Chicago")
        original = datetime(2026, 11, 1, 6, 30, 0)
        self.assertEqual(
            local_datetime_to_utc(
                "2026-11-01T01:30:00",
                "Time",
                "America/Chicago",
                original_utc=original,
            ),
            original,
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
