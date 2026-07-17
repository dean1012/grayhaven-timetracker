"""End-to-end route, permission, security-header, and workflow tests."""

from __future__ import annotations

import logging
import re
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pyotp
from argon2 import PasswordHasher
from sqlalchemy import func, select, text

from grayhaven_timetracker import routes
from grayhaven_timetracker.audit import record_audit_event
from grayhaven_timetracker.auth import (
    LoginLimiter,
    reset_totp_replay_state,
    verify_password,
)
from grayhaven_timetracker.database import get_session, session_scope
from grayhaven_timetracker.models import (
    AuditEvent,
    Client,
    Contract,
    Subtask,
    Task,
    TimeEntry,
    User,
)
from grayhaven_timetracker.permissions import ROLE_PERMISSIONS
from grayhaven_timetracker.routes import local_datetime_to_utc
from tests.helpers import (
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    ADMIN_TOTP_SECRET,
    AppTestCase,
)


def next_totp(secret: str) -> str:
    """Return the next counter's code for a second MFA event in one test."""
    totp = pyotp.TOTP(secret)
    return totp.generate_otp(int(time.time()) // totp.interval + 1)


class AuthenticationRouteTests(AppTestCase):
    def test_login_without_totp_when_account_has_not_enrolled_it(self) -> None:
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.totp_secret = None
        accepted = self.client.post(
            "/login",
            data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        self.assertEqual(accepted.location, "/")

    def test_authenticated_session_has_an_absolute_lifetime(self) -> None:
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.totp_secret = None
            reset_totp_replay_state(database, admin.id)
        maximum_age = self.app.permanent_session_lifetime.total_seconds()
        invalid_ages: tuple[object, ...] = (
            None,
            "invalid",
            time.time() + 3600,
            time.time() - maximum_age - 1,
        )
        for authenticated_at in invalid_ages:
            with self.subTest(authenticated_at=authenticated_at):
                client = self.app.test_client()
                self.login(client, totp_secret="")
                with client.session_transaction() as authenticated_session:
                    if authenticated_at is None:
                        authenticated_session.pop("authenticated_at")
                    else:
                        authenticated_session["authenticated_at"] = authenticated_at
                response = client.get("/")
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response.location.startswith("/login"))

    def test_login_logout_head_and_safe_next_workflow(self) -> None:
        self.assertEqual(self.client.get("/").status_code, 302)
        self.assertIn("next=/", self.client.get("/").location)
        login_page = self.client.get("/login")
        self.assertEqual(login_page.status_code, 200)
        self.assertIn(b'class="app-body auth-page"', login_page.data)
        self.assertNotIn(b'class="app-header"', login_page.data)
        self.assertNotIn(b"SECURE WORK SESSION MANAGEMENT", login_page.data)
        self.assertNotIn(b'name="totp_digit"', login_page.data)
        self.assertIn(b"fa-envelope", login_page.data)
        self.assertIn(b"fa-lock", login_page.data)
        self.assertEqual(self.client.head("/login").status_code, 200)
        rejected = self.client.post(
            "/login", data={"email": ADMIN_EMAIL, "password": "wrong", "totp": "000000"}
        )
        self.assertEqual(rejected.status_code, 401)
        challenge = self.client.post(
            "/login",
            data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        self.assertEqual(challenge.location, "/login/authenticator")
        challenge_page = self.client.get(challenge.location)
        self.assertEqual(challenge_page.data.count(b'name="totp_digit"'), 6)
        self.assertIn(b"data-totp-bubbles", challenge_page.data)
        rejected_totp = self.client.post(
            "/login/authenticator",
            data={"totp_digit": list("000000")},
        )
        self.assertEqual(rejected_totp.status_code, 401)
        weak_hash = PasswordHasher(
            time_cost=1,
            memory_cost=1024,
            parallelism=1,
        ).hash(ADMIN_PASSWORD)
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.password_hash = weak_hash
        accepted_password = self.client.post(
            "/login?next=/profile",
            data={
                "email": f" {ADMIN_EMAIL.upper()} ",
                "password": ADMIN_PASSWORD,
            },
        )
        self.assertEqual(accepted_password.location, "/login/authenticator")
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            self.assertNotEqual(admin.password_hash, weak_hash)
        accepted_token = pyotp.TOTP(ADMIN_TOTP_SECRET).now()
        accepted = self.client.post(
            "/login/authenticator",
            data={"totp_digit": list(accepted_token)},
        )
        self.assertEqual(accepted.location, "/profile")
        self.assertEqual(self.client.get("/login").location, "/")
        self.assertEqual(self.client.get("/login/authenticator").location, "/")
        self.assertEqual(self.client.post("/logout").status_code, 302)
        self.assertEqual(self.client.get("/profile").status_code, 302)
        self.assertEqual(
            self.client.post(
                "/login", data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
            ).location,
            "/login/authenticator",
        )
        replayed = self.client.post(
            "/login/authenticator",
            data={"totp_digit": list(accepted_token)},
        )
        self.assertEqual(replayed.status_code, 401)

    def test_authenticator_challenge_expires_and_rate_limits(self) -> None:
        no_challenge = self.client.get("/login/authenticator")
        self.assertEqual(no_challenge.location, "/login")

        challenge = self.client.post(
            "/login",
            data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        self.assertEqual(challenge.location, "/login/authenticator")
        with self.client.session_transaction() as pending_session:
            pending_session["pending_login_expires_at"] = 0
        self.assertEqual(self.client.get("/login/authenticator").location, "/login")

        self.client.post(
            "/login",
            data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.session_version += 1
        self.assertEqual(self.client.get("/login/authenticator").location, "/login")

        self.client.post(
            "/login",
            data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        routes.login_limiter = LoginLimiter(limit=1)
        rejected = self.client.post(
            "/login/authenticator",
            data={"totp_digit": list("000000")},
        )
        self.assertEqual(rejected.status_code, 401)
        limited = self.client.post(
            "/login/authenticator",
            data={"totp_digit": list("000000")},
        )
        self.assertEqual(limited.status_code, 429)

    def test_restarting_password_stage_does_not_reset_totp_throttling(self) -> None:
        routes.login_limiter = LoginLimiter(limit=1)
        challenge = self.client.post(
            "/login",
            data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        self.assertEqual(challenge.location, "/login/authenticator")
        rejected = self.client.post(
            "/login/authenticator",
            data={"totp_digit": list("000000")},
        )
        self.assertEqual(rejected.status_code, 401)
        restarted = self.client.post(
            "/login",
            data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        )
        self.assertEqual(restarted.status_code, 429)

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
        self.assertEqual(
            self.client.post(
                "/login",
                data={"email": "not-an-email", "password": "wrong"},
            ).status_code,
            401,
        )

    def test_csrf_and_request_size_fail_closed(self) -> None:
        self.app.config["WTF_CSRF_ENABLED"] = True
        self.assertEqual(self.client.post("/logout").status_code, 400)
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
    def test_static_assets_cover_template_icons_and_branding_breakpoints(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        stylesheet = (project_root / "static/fontawesome.min.css").read_text(
            encoding="utf-8"
        )
        used_icons: set[str] = set()
        for template in (project_root / "templates").glob("*.html"):
            for classes in re.findall(
                r'class="([^"]*)"', template.read_text(encoding="utf-8")
            ):
                used_icons.update(
                    item
                    for item in classes.split()
                    if item.startswith("fa-") and item != "fa-solid"
                )
        missing_icons = sorted(
            icon for icon in used_icons if f".{icon}:before" not in stylesheet
        )
        self.assertEqual(missing_icons, [])

        app_stylesheet = (project_root / "static/app.css").read_text(encoding="utf-8")
        for media_query in (
            "@media (width <=400px)",
            "@media (width <=575px)",
            "@media (width >=640px)",
            "@media (width >=768px)",
            "@media (width >=1120px)",
            "@media (width >=1721px)",
        ):
            self.assertIn(media_query, app_stylesheet)
        self.assertRegex(
            app_stylesheet,
            r"(?s)@media \(width >=1721px\).*?"
            r"\.desktop-nav \{ display: flex; \}.*?"
            r"\.mobile-nav \{ display: none; \}",
        )

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
        self.app.config["TRUSTED_HOSTS"] = ["example.invalid"]
        untrusted = self.client.get("/login", base_url="https://evil.invalid")
        self.assertEqual(untrusted.status_code, 400)
        self.assertEqual(untrusted.headers["X-Frame-Options"], "DENY")
        self.assertEqual(
            self.client.get("/login", base_url="https://example.invalid").status_code,
            200,
        )

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


class AuditRouteTests(AppTestCase):
    def test_anonymous_page_scanning_does_not_expand_the_audit_database(self) -> None:
        with session_scope(self.app) as database:
            before = database.scalar(select(func.count(AuditEvent.id)))
        self.assertEqual(self.client.get("/login").status_code, 200)
        self.assertEqual(self.client.get("/missing").status_code, 404)
        with session_scope(self.app) as database:
            after = database.scalar(select(func.count(AuditEvent.id)))
        self.assertEqual(after, before)

    def test_audit_persistence_failure_does_not_replace_the_response(self) -> None:
        self.login()
        with patch(
            "grayhaven_timetracker.record_audit_event",
            side_effect=RuntimeError("simulated audit storage failure"),
        ):
            self.assertEqual(self.client.get("/").status_code, 200)

    def test_admin_can_filter_and_paginate_append_only_audit_history(self) -> None:
        self.login()
        self.assertEqual(self.client.get("/").status_code, 200)
        response = self.client.get("/audit")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Audit Log", response.data)
        self.assertIn(b"Application Started", response.data)
        self.assertIn(b"Login Succeeded", response.data)
        self.assertNotIn(b">Request<", response.data)

        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            events = database.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
            self.assertTrue(any(item.event == "application_started" for item in events))
            self.assertTrue(
                any(
                    item.event == "login_succeeded"
                    and item.actor_user_id == admin.id
                    and item.source == "admin"
                    for item in events
                )
            )
            self.assertFalse(any(item.event == "http_request" for item in events))
            record_audit_event(
                database,
                "http_request",
                source="public",
                details={"endpoint": "legacy"},
            )
            for index in range(55):
                record_audit_event(
                    database,
                    "pagination_test",
                    source="system",
                    details={"sequence": index},
                )
            admin_id = admin.id

        filtered = self.client.get("/audit?source=system&event=pagination_test&page=2")
        self.assertEqual(filtered.status_code, 200)
        self.assertIn(b"Page 2 of 2", filtered.data)
        self.assertNotIn(b"Http Request", self.client.get("/audit").data)
        self.assertEqual(
            self.client.get(f"/audit?actor={admin_id}").status_code,
            200,
        )
        for query in (
            "source=invalid",
            "event=invalid/event",
            "actor=invalid",
            "actor=0",
            "page=0",
            "page=999",
        ):
            with self.subTest(query=query):
                self.assertIn(
                    self.client.get(f"/audit?{query}").status_code, {400, 404}
                )

    def test_standard_user_cannot_view_audit_history(self) -> None:
        user = self.create_user()
        standard_client = self.app.test_client()
        self.login(
            standard_client,
            email=user.email,
            password="Standard-User-Test-Password-0001!",
            totp_secret=user.totp_secret or "",
        )
        dashboard = standard_client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"Clients &amp; Contracts", dashboard.data)
        self.assertNotIn(b'href="/audit"', dashboard.data)
        self.assertEqual(standard_client.get("/audit").status_code, 403)
        with session_scope(self.app) as database:
            self.assertFalse(
                database.scalar(
                    select(func.count(AuditEvent.id)).where(
                        AuditEvent.event == "http_request"
                    )
                )
            )


class ClientContractTaskRouteTests(AppTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.login()

    def test_report_password_confirmation_is_one_time_and_expires(self) -> None:
        store = routes.ReportPasswordConfirmationStore(ttl_seconds=120)
        token = store.issue(
            actor_user_id=1,
            client_id=2,
            report_password="Temporary-Report-Password-For-Test-0001!",
            now=1_000,
        )
        confirmation = store.consume(token, actor_user_id=1, client_id=2, now=1_119)
        assert confirmation is not None
        self.assertEqual(
            confirmation.report_password,
            "Temporary-Report-Password-For-Test-0001!",
        )
        self.assertIsNone(store.consume(token, actor_user_id=1, client_id=2, now=1_119))

        expired_token = store.issue(
            actor_user_id=1,
            client_id=2,
            report_password="Expired-Report-Password-For-Test-0001!",
            now=2_000,
        )
        self.assertIsNone(
            store.consume(expired_token, actor_user_id=1, client_id=2, now=2_120)
        )

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
        self.assertIn(b"/clients/", created.headers["Location"].encode())
        with session_scope(self.app) as database:
            client = database.scalar(select(Client).where(Client.name == "Client One"))
            assert client is not None
            client_id = client.id
            self.assertEqual(client.contact_email, "client@example.invalid")
            self.assertIsNone(client.report_password_hash)
        self.assertEqual(self.client.get(f"/clients/{client_id}").status_code, 200)
        self.assertEqual(self.client.get("/clients/9999").status_code, 404)
        new_contract_form = self.client.get(f"/contracts/new/{client_id}")
        self.assertEqual(new_contract_form.status_code, 200)
        self.assertIn(b'value="Client Contact"', new_contract_form.data)
        self.assertIn(b'value="client@example.invalid"', new_contract_form.data)
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
            contract_id = contract.id
            self.assertEqual(contract.hourly_rate_cents, 5501)
            client = database.get(Client, client_id)
            assert client is not None and client.report_password_hash is None
        self.assertEqual(self.client.get(f"/clients/{client_id}/edit").status_code, 200)
        updated_client = self.client.post(
            f"/clients/{client_id}/edit",
            data={
                "name": "Client One Updated",
                "contact_name": "New Client Contact",
                "contact_email": "new-client@example.invalid",
            },
        )
        self.assertEqual(updated_client.status_code, 302)
        self.assertEqual(
            self.client.get(f"/contracts/{contract_id}/edit").status_code, 200
        )
        self.assertEqual(
            self.client.post(
                f"/contracts/{contract_id}/edit",
                data={
                    "name": "",
                    "contact_name": "Contact",
                    "contact_email": "invalid",
                },
            ).status_code,
            400,
        )
        updated_contract = self.client.post(
            f"/contracts/{contract_id}/edit",
            data={
                "name": "Contract One Updated",
                "contact_name": "New Contract Contact",
                "contact_email": "new-contract@example.invalid",
                "hourly_rate": "999999.99",
            },
        )
        self.assertEqual(updated_contract.status_code, 302)
        with session_scope(self.app) as database:
            client = database.get(Client, client_id)
            contract = database.get(Contract, contract_id)
            assert client and contract
            self.assertEqual(client.name, "Client One Updated")
            self.assertEqual(contract.name, "Contract One Updated")
            self.assertEqual(contract.hourly_rate_cents, 5501)
        self.assertEqual(
            self.client.post(
                f"/clients/{client_id}/edit",
                data={"name": "", "contact_name": "Contact", "contact_email": "bad"},
            ).status_code,
            400,
        )
        self.assertEqual(self.client.get("/clients/9999/edit").status_code, 404)
        self.assertEqual(self.client.get("/contracts/9999/edit").status_code, 404)
        replacement_password = "Replacement-Report-Password-For-Test-0001!"
        self.assertEqual(
            self.client.get(f"/clients/{client_id}/report-password/reset").status_code,
            200,
        )
        routes.sensitive_action_limiter = LoginLimiter(limit=1)
        rejected_reset = self.client.post(
            f"/clients/{client_id}/report-password/reset",
            data={"current_password": "wrong", "totp": "000000"},
        )
        self.assertEqual(rejected_reset.status_code, 400)
        self.assertEqual(
            self.client.post(
                f"/clients/{client_id}/report-password/reset",
                data={"current_password": "wrong", "totp": "000000"},
            ).status_code,
            429,
        )
        routes.sensitive_action_limiter = LoginLimiter()
        missing_totp = self.client.post(
            f"/clients/{client_id}/report-password/reset",
            data={"current_password": ADMIN_PASSWORD},
        )
        self.assertEqual(missing_totp.status_code, 400)
        with patch(
            "grayhaven_timetracker.routes.generate_temporary_password",
            return_value=replacement_password,
        ):
            reset_password = self.client.post(
                f"/clients/{client_id}/report-password/reset",
                data={
                    "current_password": ADMIN_PASSWORD,
                    "totp": next_totp(ADMIN_TOTP_SECRET),
                },
            )
        self.assertEqual(reset_password.status_code, 302)
        confirmation_url = reset_password.headers["Location"]
        confirmation = self.client.get(confirmation_url)
        self.assertEqual(confirmation.status_code, 200)
        self.assertIn(replacement_password.encode(), confirmation.data)
        self.assertIn(b"Copy password", confirmation.data)
        self.assertIn(b"Email report password", confirmation.data)
        self.assertIn(b'data-expire-after-ms="120000"', confirmation.data)
        self.assertIn(b"data-confirmation-countdown", confirmation.data)
        refreshed = self.client.get(confirmation_url)
        self.assertEqual(refreshed.status_code, 302)
        self.assertEqual(refreshed.headers["Location"], f"/clients/{client_id}")

    def test_task_and_subtask_deletion_removes_work_data_and_retains_audit(
        self,
    ) -> None:
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
                f"/subtasks/{unused_id}/new", data={"name": ""}
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post(
                f"/tasks/{unused_id}/rename", data={"name": ""}
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post(
                f"/subtasks/{child_id}/rename", data={"name": ""}
            ).status_code,
            302,
        )
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
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.totp_secret = None

        confirmation = self.client.get(f"/subtasks/{child_id}/delete")
        self.assertEqual(confirmation.status_code, 200)
        self.assertIn(b"Audit history is retained", confirmation.data)
        self.assertEqual(
            self.client.post(
                f"/subtasks/{child_id}/delete", data={"current_password": "wrong"}
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                f"/subtasks/{child_id}/delete",
                data={"current_password": ADMIN_PASSWORD},
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post(
                f"/tasks/{unused_id}/delete",
                data={"current_password": ADMIN_PASSWORD},
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post(
                f"/tasks/{seed.task_id}/delete",
                data={"current_password": ADMIN_PASSWORD},
            ).status_code,
            302,
        )
        with session_scope(self.app) as database:
            self.assertIsNone(database.get(Task, seed.task_id))
            self.assertIsNone(database.get(Subtask, seed.subtask_id))
            self.assertIsNone(database.get(TimeEntry, seed.entry_id))
            deleted = next(
                item
                for item in database.scalars(
                    select(AuditEvent).where(AuditEvent.event == "task_deleted")
                )
                if item.details.get("task") == f"Discovery (ID: {seed.task_id})"
            )
            self.assertEqual(deleted.details["task"], f"Discovery (ID: {seed.task_id})")
            self.assertEqual(
                deleted.details["contract"],
                f"Hamilton Beach - Phase 1 (ID: {seed.contract_id})",
            )
            self.assertEqual(
                deleted.details["client"], f"Pellera (ID: {seed.client_id})"
            )

    def test_client_and_contract_deletion_remove_time_without_deleting_audit(
        self,
    ) -> None:
        seed = self.seed_contract()
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.totp_secret = None

        self.assertEqual(
            self.client.post(
                f"/contracts/{seed.contract_id}/delete",
                data={"current_password": ADMIN_PASSWORD},
            ).status_code,
            302,
        )
        with session_scope(self.app) as database:
            self.assertIsNone(database.get(Contract, seed.contract_id))
            self.assertIsNone(database.get(TimeEntry, seed.entry_id))
            deleted = next(
                item
                for item in database.scalars(
                    select(AuditEvent).where(AuditEvent.event == "contract_deleted")
                )
                if item.details.get("contract")
                == f"Hamilton Beach - Phase 1 (ID: {seed.contract_id})"
            )
            self.assertEqual(
                deleted.details["client"], f"Pellera (ID: {seed.client_id})"
            )
            self.assertEqual(
                deleted.details["contract"],
                f"Hamilton Beach - Phase 1 (ID: {seed.contract_id})",
            )

        self.assertEqual(
            self.client.post(
                f"/clients/{seed.client_id}/delete",
                data={"current_password": ADMIN_PASSWORD},
            ).status_code,
            302,
        )
        with session_scope(self.app) as database:
            self.assertIsNone(database.get(Client, seed.client_id))
            deleted = database.scalar(
                select(AuditEvent).where(AuditEvent.event == "client_deleted")
            )
            assert deleted is not None
            self.assertEqual(
                deleted.details["client"], f"Pellera (ID: {seed.client_id})"
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
        self.assertEqual(
            self.client.get(f"/clients/{self.seed.client_id}/edit").status_code, 403
        )
        self.assertEqual(
            self.client.get(f"/contracts/{self.seed.contract_id}/edit").status_code,
            403,
        )
        self.assertEqual(
            self.client.get(f"/clients/{self.seed.client_id}/delete").status_code,
            403,
        )
        self.assertEqual(
            self.client.get(f"/contracts/{self.seed.contract_id}/delete").status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                f"/clients/{self.seed.client_id}/report-link",
                data={"expires_in_days": "never"},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                f"/clients/{self.seed.client_id}/report-password/reset"
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(f"/users/{self.user.id}/reset-password").status_code,
            403,
        )
        with patch.dict(ROLE_PERMISSIONS, {"user": frozenset()}):
            self.assertEqual(
                self.client.get(
                    f"/contracts/{self.seed.contract_id}/sessions/new"
                ).status_code,
                403,
            )
            self.assertEqual(
                self.client.get(
                    f"/contracts/{self.seed.contract_id}/sessions"
                ).status_code,
                403,
            )
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
        self.assertEqual(
            self.client.post(
                "/timer/start",
                data={"task_id": other_id, "subtask_id": "invalid"},
            ).status_code,
            400,
        )


class ProfileAndUserAdministrationTests(AppTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.login()

    def test_profile_name_and_password_change_require_valid_inputs(self) -> None:
        self.assertEqual(self.client.get("/profile").status_code, 200)
        self.assertEqual(
            self.client.get("/profile/password/change-required").location,
            "/profile",
        )
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
        with patch(
            "grayhaven_timetracker.routes.record_audit_event",
            side_effect=RuntimeError("simulated semantic audit failure"),
        ):
            response = self.client.post(
                "/profile/name",
                data={"first_name": "Still", "last_name": "Available"},
            )
        self.assertEqual(response.status_code, 302)

    def test_totp_setup_confirmation_and_disable(self) -> None:
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.totp_secret = None
            reset_totp_replay_state(database, admin.id)
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
                    "totp": next_totp(pending),
                },
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post("/profile/totp/disable").location,
            "/profile",
        )

    def test_active_totp_factor_cannot_be_replaced_directly(self) -> None:
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            original_secret = admin.totp_secret
            admin.pending_totp_secret = pyotp.random_base32()
            pending_secret = admin.pending_totp_secret

        self.assertEqual(self.client.post("/profile/totp/setup").status_code, 409)
        self.assertEqual(
            self.client.post(
                "/profile/totp/confirm",
                data={"totp": pyotp.TOTP(pending_secret).now()},
            ).status_code,
            409,
        )
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            self.assertEqual(admin.totp_secret, original_secret)
            self.assertEqual(admin.pending_totp_secret, pending_secret)

    def test_user_creation_role_changes_and_disable_stops_timer(self) -> None:
        self.assertEqual(self.client.get("/users").status_code, 200)
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
        temporary_password = "Generated-Temporary-Password-For-Test-0001!"
        with patch(
            "grayhaven_timetracker.routes.generate_temporary_password",
            return_value=temporary_password,
        ):
            created = self.client.post(
                "/users/new",
                data={
                    "first_name": "New",
                    "last_name": "User",
                    "email": "new-user@example.invalid",
                },
            )
        self.assertEqual(created.status_code, 200)
        self.assertIn(b"Authenticator setup QR code", created.data)
        self.assertIn(temporary_password.encode(), created.data)
        duplicate = self.client.post(
            "/users/new",
            data={
                "first_name": "New",
                "last_name": "User",
                "email": "new-user@example.invalid",
            },
        )
        self.assertEqual(duplicate.status_code, 400)
        with patch(
            "grayhaven_timetracker.routes.find_user_by_email", return_value=None
        ):
            raced_duplicate = self.client.post(
                "/users/new",
                data={
                    "first_name": "Raced",
                    "last_name": "Duplicate",
                    "email": "new-user@example.invalid",
                },
            )
        self.assertEqual(raced_duplicate.status_code, 409)
        with session_scope(self.app) as database:
            user = database.scalar(
                select(User).where(User.email == "new-user@example.invalid")
            )
            assert user is not None
            user_id = user.id
            self.assertTrue(user.password_change_required)
            self.assertTrue(verify_password(user.password_hash, temporary_password))
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
        self.assertEqual(
            self.client.post(f"/users/{user_id}/toggle-enabled").status_code, 302
        )
        with session_scope(self.app) as database:
            user = database.get(User, user_id)
            assert user is not None
            self.assertTrue(user.is_enabled)
        self.assertEqual(self.client.post("/users/1/toggle-enabled").status_code, 409)
        self.assertEqual(self.client.post("/users/1/toggle-admin").status_code, 409)

    def test_user_identity_correction_invalidates_other_sessions(self) -> None:
        password = "Identity-User-Test-Password-0001!"
        secret = "KRSXG5DSNFXGOIDB"
        user = self.create_user(password=password, totp_secret=secret)
        user_client = self.app.test_client()
        self.login(
            user_client,
            email=user.email,
            password=password,
            totp_secret=secret,
        )

        self.assertEqual(self.client.get(f"/users/{user.id}/edit").status_code, 200)
        duplicate_email = self.client.post(
            f"/users/{user.id}/edit",
            data={
                "first_name": "Duplicate",
                "last_name": "Identity",
                "email": ADMIN_EMAIL,
            },
        )
        self.assertEqual(duplicate_email.status_code, 400)
        unchanged_email = self.client.post(
            f"/users/{user.id}/edit",
            data={
                "first_name": "Unchanged",
                "last_name": "Email",
                "email": user.email,
            },
        )
        self.assertEqual(unchanged_email.status_code, 302)
        updated = self.client.post(
            f"/users/{user.id}/edit",
            data={
                "first_name": "Corrected",
                "last_name": "Identity",
                "email": "corrected@example.invalid",
            },
        )
        self.assertEqual(updated.status_code, 302)
        self.assertIn("/login", user_client.get("/").location)
        self.login(
            user_client,
            email="corrected@example.invalid",
            password=password,
            totp_secret=secret,
            totp_token=next_totp(secret),
        )

        managed_email_change = self.client.post(
            "/users/1/edit",
            data={
                "first_name": "Admin",
                "last_name": "Operator",
                "email": "different-admin@example.invalid",
            },
        )
        self.assertEqual(managed_email_change.status_code, 400)

    def test_admin_password_reset_requires_change_and_preserves_totp(self) -> None:
        original_password = "Recovery-User-Original-Password-0001!"
        temporary_password = "Recovery-Temporary-Password-For-Test-0001!"
        permanent_password = "Recovery-Permanent-Password-For-Test-0001!"
        secret = "KRSXG5DSNFXGOIDB"
        user = self.create_user(password=original_password, totp_secret=secret)
        existing_session = self.app.test_client()
        self.login(
            existing_session,
            email=user.email,
            password=original_password,
            totp_secret=secret,
        )
        self.assertEqual(
            self.client.get(f"/users/{user.id}/reset-password").status_code, 200
        )
        routes.sensitive_action_limiter = LoginLimiter(limit=1)
        self.assertEqual(
            self.client.post(
                f"/users/{user.id}/reset-password",
                data={"current_password": "wrong", "totp": "000000"},
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                f"/users/{user.id}/reset-password",
                data={"current_password": "wrong", "totp": "000000"},
            ).status_code,
            429,
        )
        routes.sensitive_action_limiter = LoginLimiter()

        with patch(
            "grayhaven_timetracker.routes.generate_temporary_password",
            return_value=temporary_password,
        ):
            reset = self.client.post(
                f"/users/{user.id}/reset-password",
                data={
                    "current_password": ADMIN_PASSWORD,
                    "totp": next_totp(ADMIN_TOTP_SECRET),
                },
            )
        self.assertEqual(reset.status_code, 200)
        self.assertIn(temporary_password.encode(), reset.data)
        self.assertIn("/login", existing_session.get("/").location)
        self.assertEqual(self.client.post("/users/1/reset-password").status_code, 409)

        recovered = self.app.test_client()
        challenge = recovered.post(
            "/login",
            data={
                "email": user.email,
                "password": temporary_password,
            },
        )
        self.assertEqual(challenge.location, "/login/authenticator")
        rejected_totp = recovered.post(
            "/login/authenticator",
            data={"totp_digit": list("000000")},
        )
        self.assertEqual(rejected_totp.status_code, 401)
        accepted = recovered.post(
            "/login/authenticator",
            data={"totp_digit": list(next_totp(secret))},
        )
        self.assertEqual(accepted.location, "/profile/password/change-required")
        self.assertEqual(
            recovered.get("/profile/password/change-required").status_code, 200
        )
        self.assertEqual(
            recovered.get("/profile").location,
            "/profile/password/change-required",
        )
        changed = recovered.post(
            "/profile/password",
            data={
                "current_password": temporary_password,
                "new_password": permanent_password,
                "confirm_password": permanent_password,
            },
        )
        self.assertEqual(changed.location, "/")
        self.assertEqual(recovered.get("/").status_code, 200)
        with session_scope(self.app) as database:
            recovered_user = database.get(User, user.id)
            assert recovered_user is not None
            self.assertFalse(recovered_user.password_change_required)
            self.assertEqual(recovered_user.totp_secret, secret)
            self.assertTrue(
                verify_password(recovered_user.password_hash, permanent_password)
            )


class ReportAndSessionRouteTests(AppTestCase):
    USER_PASSWORD = "Session-User-Test-Password-0001!"
    USER_SECRET = "KRSXG5DSNFXGOIDB"

    def setUp(self) -> None:
        super().setUp()
        self.user = self.create_user(
            password=self.USER_PASSWORD, totp_secret=self.USER_SECRET
        )
        self.seed = self.seed_contract(entry_user_id=self.user.id)

    def test_admin_live_report(self) -> None:
        self.login()
        html = self.client.get(f"/reports/{self.seed.contract_id}")
        self.assertEqual(html.status_code, 200)
        self.assertIn(b"Client Time Report", html.data)
        self.assertIn(b"data-live-report", html.data)
        self.assertIn(
            f'data-live-url="/reports/{self.seed.contract_id}/live"'.encode(),
            html.data,
        )
        etag_match = re.search(rb'data-live-etag="([0-9a-f]{64})"', html.data)
        assert etag_match is not None
        etag = etag_match.group(1).decode()
        unchanged = self.client.get(
            f"/reports/{self.seed.contract_id}/live",
            headers={"If-None-Match": f'"{etag}"'},
        )
        self.assertEqual(unchanged.status_code, 304)
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            task = database.get(Task, self.seed.other_task_id)
            assert admin and task
            database.add(TimeEntry(user=admin, task=task, started_at=datetime.now()))
        changed = self.client.get(
            f"/reports/{self.seed.contract_id}/live",
            headers={"If-None-Match": f'"{etag}"'},
        )
        self.assertEqual(changed.status_code, 200)
        self.assertIn(b'data-active="true"', changed.data)
        with session_scope(self.app) as database:
            active_entry = database.scalar(
                select(TimeEntry).where(TimeEntry.stopped_at.is_(None))
            )
            assert active_entry is not None
            self.assertIsNone(active_entry.stopped_at)
        self.assertEqual(self.client.get("/reports/9999").status_code, 404)
        self.assertEqual(self.client.get("/reports/9999/live").status_code, 404)
        self.assertEqual(
            self.app.test_client()
            .get(f"/reports/{self.seed.contract_id}/live")
            .status_code,
            302,
        )

    def test_live_client_report_is_permanent_and_admin_shared(self) -> None:
        self.login()
        self.app.config["PUBLIC_BASE_URL"] = "https://time.example.invalid"
        with session_scope(self.app) as database:
            client = database.get(Client, self.seed.client_id)
            assert client is not None
            token = client.report_token
            client.report_password_hash = None
        client_page = self.client.get(f"/clients/{self.seed.client_id}")
        self.assertEqual(client_page.status_code, 200)
        report_url = f"https://time.example.invalid/shared/reports/{token}"
        self.assertIn(report_url.encode(), client_page.data)
        self.assertIn(b"Copy report link", client_page.data)
        self.assertIn(b"Share report link by email", client_page.data)
        mailto_body = parse_qs(
            urlsplit(routes.report_mailto(client, report_url)).query
        )["body"][0]
        self.assertIn(
            "<b>Your personalized live report is available here:</b>", mailto_body
        )
        self.assertIn(f'<a href="{report_url}">{report_url}</a>', mailto_body)
        self.assertIn(
            "<b>Please keep both your link and password confidential to protect "
            "your data.</b>",
            mailto_body,
        )
        anonymous = self.app.test_client()
        self.assertEqual(anonymous.get(f"/shared/reports/{token}").status_code, 200)
        self.assertEqual(
            anonymous.post(
                f"/shared/reports/{token}", data={"report_password": "unused"}
            ).status_code,
            401,
        )
        report_password = "Shared-Report-Password-For-Testing-0001!"
        password_mailto = parse_qs(
            urlsplit(routes.report_password_mailto(client, report_password)).query
        )
        self.assertEqual(
            password_mailto["subject"],
            ["Your live time and cost report password for Pellera has been reset"],
        )
        password_mailto_body = password_mailto["body"][0]
        self.assertIn(
            "All previously open live report sessions will need to be reauthenticated.",
            password_mailto_body,
        )
        self.assertIn(
            f"<b>Your new password is:</b> {report_password}",
            password_mailto_body,
        )
        self.assertIn(
            "<b>Please save this password, as this email will expire in 48 hours.</b>",
            password_mailto_body,
        )
        self.assertNotIn(report_url, password_mailto_body)
        with session_scope(self.app) as database:
            client = database.get(Client, self.seed.client_id)
            assert client is not None
            client.report_password_hash = routes.hash_password(report_password)
            client.report_password_version += 1
        self.assertEqual(
            anonymous.post(
                f"/shared/reports/{token}", data={"report_password": report_password}
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post(f"/clients/{self.seed.client_id}/report-link").status_code,
            404,
        )

    @unittest.skip(
        "Legacy expiration and rotation assertions replaced by permanent links"
    )
    def test_live_client_report_links_are_private_rotatable_and_revocable(
        self,
    ) -> None:
        self.login()
        first_token = "A" * 43
        second_token = "B" * 43
        unusable_token = "Z" * 43
        report_password = "Shared-Report-Password-For-Testing-0001!"
        self.app.config["PUBLIC_BASE_URL"] = "https://time.example.invalid"
        with session_scope(self.app) as database:
            client = database.get(Client, self.seed.client_id)
            assert client is not None
            client.report_token_hash = routes.report_token_hash(unusable_token)
            client.report_password_hash = None
        self.assertEqual(
            self.app.test_client().get(f"/shared/reports/{unusable_token}").status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                f"/clients/{self.seed.client_id}/report-link",
                data={"expires_in_days": "invalid"},
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                f"/clients/{self.seed.client_id}/report-link",
                data={"expires_in_days": "14"},
            ).status_code,
            400,
        )
        with (
            patch(
                "grayhaven_timetracker.routes.secrets.token_urlsafe",
                return_value=first_token,
            ),
            patch(
                "grayhaven_timetracker.routes.generate_temporary_password",
                return_value=report_password,
            ),
        ):
            created = self.client.post(
                f"/clients/{self.seed.client_id}/report-link",
                data={"expires_in_days": "never"},
            )
        self.assertEqual(created.status_code, 200)
        self.assertIn(first_token.encode(), created.data)
        self.assertGreater(created.data.count(first_token.encode()), 1)
        self.assertIn(
            f"https://time.example.invalid/shared/reports/{first_token}".encode(),
            created.data,
        )
        self.assertIn(report_password.encode(), created.data)
        self.assertIn(b"does not expire", created.data)
        with session_scope(self.app) as database:
            client = database.get(Client, self.seed.client_id)
            assert client is not None
            self.assertNotEqual(client.report_token_hash, first_token)
            self.assertEqual(
                client.report_token_hash, routes.report_token_hash(first_token)
            )
            self.assertIsNone(client.report_expires_at)
            assert client.report_password_hash is not None
            self.assertTrue(
                verify_password(client.report_password_hash, report_password)
            )

        anonymous = self.app.test_client()
        logging.disable(logging.NOTSET)
        try:
            with self.assertLogs(
                "grayhaven_timetracker.access", level=logging.INFO
            ) as captured:
                shared = anonymous.get(f"/shared/reports/{first_token}")
        finally:
            logging.disable(logging.CRITICAL)
        self.assertEqual(shared.status_code, 200)
        self.assertIn(b"CLIENT REPORT ACCESS", shared.data)
        self.assertEqual(
            getattr(captured.records[-1], "path", None),
            "/shared/reports/[redacted]",
        )
        routes.shared_report_limiter = LoginLimiter(limit=1)
        rejected = anonymous.post(
            f"/shared/reports/{first_token}",
            data={"report_password": "incorrect"},
        )
        self.assertEqual(rejected.status_code, 401)
        self.assertEqual(
            anonymous.post(
                f"/shared/reports/{first_token}",
                data={"report_password": "incorrect"},
            ).status_code,
            429,
        )
        routes.shared_report_limiter = LoginLimiter()
        authenticated = anonymous.post(
            f"/shared/reports/{first_token}",
            data={"report_password": report_password},
        )
        self.assertEqual(authenticated.status_code, 302)
        self.assertEqual(
            authenticated.headers["Location"], f"/shared/reports/{first_token}"
        )
        shared = anonymous.get(f"/shared/reports/{first_token}")
        self.assertEqual(shared.status_code, 200)
        report_cookie_name = routes.shared_report_cookie_name(client)
        self.assertIsNotNone(
            anonymous.get_cookie(
                report_cookie_name,
                path=routes.SHARED_REPORT_COOKIE_PATH,
            )
        )
        self.assertIn(b"Live Client Report", shared.data)
        self.assertIn(b"Estimated Cost", shared.data)
        self.assertNotIn(b"Equivalent Cost", shared.data)
        self.assertNotIn(b"morgan@example.invalid", shared.data)
        with anonymous.session_transaction() as application_session:
            application_session.clear()
        self.assertIn(
            b"Live Client Report",
            anonymous.get(f"/shared/reports/{first_token}").data,
        )
        shared_etag_match = re.search(rb'data-live-etag="([0-9a-f]{64})"', shared.data)
        assert shared_etag_match is not None
        shared_etag = shared_etag_match.group(1).decode()
        self.assertEqual(
            self.app.test_client()
            .get(f"/shared/reports/{first_token}/live")
            .status_code,
            302,
        )
        live = anonymous.get(
            f"/shared/reports/{first_token}/live",
            headers={"If-None-Match": f'"{shared_etag}"'},
        )
        self.assertEqual(live.status_code, 304)
        self.assertEqual(live.headers.get("ETag"), f'"{shared_etag}"')
        anonymous.delete_cookie(
            report_cookie_name,
            path=routes.SHARED_REPORT_COOKIE_PATH,
        )
        self.assertEqual(
            anonymous.get(f"/shared/reports/{first_token}/live").status_code,
            302,
        )
        self.assertEqual(
            anonymous.post(
                f"/shared/reports/{first_token}",
                data={"report_password": report_password},
            ).status_code,
            302,
        )

        with patch(
            "grayhaven_timetracker.routes.secrets.token_urlsafe",
            return_value=second_token,
        ):
            self.app.config["PUBLIC_BASE_URL"] = None
            rotated = self.client.post(
                f"/clients/{self.seed.client_id}/report-link",
                data={"expires_in_days": "7"},
            )
        self.assertEqual(rotated.status_code, 200)
        self.assertEqual(
            anonymous.get(f"/shared/reports/{first_token}").status_code, 404
        )
        self.assertEqual(
            anonymous.get(f"/shared/reports/{second_token}").status_code, 200
        )
        replacement_password = "New-Shared-Report-Password-For-Test-0001!"
        with patch(
            "grayhaven_timetracker.routes.generate_temporary_password",
            return_value=replacement_password,
        ):
            password_reset = self.client.post(
                f"/clients/{self.seed.client_id}/report-password/reset",
                data={
                    "current_password": ADMIN_PASSWORD,
                    "totp": next_totp(ADMIN_TOTP_SECRET),
                },
            )
        self.assertEqual(password_reset.status_code, 200)
        password_prompt = anonymous.get(f"/shared/reports/{second_token}")
        self.assertIn(b"CLIENT REPORT ACCESS", password_prompt.data)
        self.assertEqual(
            anonymous.post(
                f"/shared/reports/{second_token}",
                data={"report_password": report_password},
            ).status_code,
            401,
        )
        self.assertEqual(
            anonymous.post(
                f"/shared/reports/{second_token}",
                data={"report_password": replacement_password},
            ).status_code,
            302,
        )
        with session_scope(self.app) as database:
            client = database.get(Client, self.seed.client_id)
            assert client and client.report_expires_at
            self.assertGreater(client.report_expires_at, datetime.now())
            client.report_expires_at = datetime.now() - timedelta(seconds=1)
        self.assertEqual(
            anonymous.get(f"/shared/reports/{second_token}").status_code, 404
        )
        revoked = self.client.post(f"/clients/{self.seed.client_id}/report-link/revoke")
        self.assertEqual(revoked.status_code, 302)
        with session_scope(self.app) as database:
            client = database.get(Client, self.seed.client_id)
            assert client is not None
            self.assertIsNone(client.report_token_hash)
            self.assertIsNone(client.report_expires_at)
            audit_events = database.scalars(select(AuditEvent)).all()
            self.assertTrue(
                any(item.path == "/shared/reports/[redacted]" for item in audit_events)
            )
            for item in audit_events:
                audit_text = f"{item.path or ''}{item.details_json}"
                self.assertNotIn(first_token, audit_text)
                self.assertNotIn(second_token, audit_text)
                self.assertNotIn(report_password, audit_text)
                self.assertNotIn(replacement_password, audit_text)
        self.assertEqual(anonymous.get("/shared/reports/short").status_code, 404)

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

    def test_manual_sessions_enforce_ownership_time_and_overlap_rules(self) -> None:
        user_client = self.app.test_client()
        self.login(
            user_client,
            email=self.user.email,
            password=self.USER_PASSWORD,
            totp_secret=self.USER_SECRET,
        )
        self.assertEqual(
            user_client.get(
                f"/contracts/{self.seed.contract_id}/sessions/new"
            ).status_code,
            200,
        )
        self.assertEqual(
            user_client.get("/contracts/9999/sessions/new").status_code,
            404,
        )
        self.assertEqual(
            user_client.get("/contracts/9999/sessions").status_code,
            404,
        )
        invalid_cases = [
            {
                "assignment": "9999",
                "started_at": "2026-07-14T10:00:00",
                "stopped_at": "2026-07-14T10:30:00",
            },
            {
                "assignment": f"{self.seed.other_task_id}:{self.seed.subtask_id}",
                "started_at": "2026-07-14T10:00:00",
                "stopped_at": "2026-07-14T10:30:00",
            },
            {
                "assignment": str(self.seed.other_task_id),
                "started_at": "2026-07-14T10:30:00",
                "stopped_at": "2026-07-14T10:00:00",
            },
        ]
        for data in invalid_cases:
            with self.subTest(data=data):
                self.assertEqual(
                    user_client.post(
                        f"/contracts/{self.seed.contract_id}/sessions/new",
                        data=data,
                    ).status_code,
                    400,
                )
        created = user_client.post(
            f"/contracts/{self.seed.contract_id}/sessions/new",
            data={
                "user_id": "1",
                "assignment": f"{self.seed.task_id}:{self.seed.subtask_id}",
                "started_at": "2026-07-15T10:00:00",
                "stopped_at": "2026-07-15T10:30:00",
            },
        )
        self.assertEqual(created.status_code, 302)
        overlap = user_client.post(
            f"/contracts/{self.seed.contract_id}/sessions/new",
            data={
                "assignment": str(self.seed.other_task_id),
                "started_at": "2026-07-15T10:15:00",
                "stopped_at": "2026-07-15T10:45:00",
            },
        )
        self.assertEqual(overlap.status_code, 400)
        future = user_client.post(
            f"/contracts/{self.seed.contract_id}/sessions/new",
            data={
                "assignment": str(self.seed.other_task_id),
                "started_at": "2099-01-01T10:00:00",
                "stopped_at": "2099-01-01T10:30:00",
            },
        )
        self.assertEqual(future.status_code, 400)

        self.login()
        for invalid_user_id in ("invalid", "9999"):
            with self.subTest(invalid_user_id=invalid_user_id):
                self.assertEqual(
                    self.client.post(
                        f"/contracts/{self.seed.contract_id}/sessions/new",
                        data={
                            "user_id": invalid_user_id,
                            "assignment": str(self.seed.other_task_id),
                            "started_at": "2026-07-14T10:00:00",
                            "stopped_at": "2026-07-14T10:30:00",
                        },
                    ).status_code,
                    400,
                )
        admin_created = self.client.post(
            f"/contracts/{self.seed.contract_id}/sessions/new",
            data={
                "user_id": "1",
                "assignment": str(self.seed.other_task_id),
                "started_at": "2026-07-15T10:00:00",
                "stopped_at": "2026-07-15T10:30:00",
            },
        )
        self.assertEqual(admin_created.status_code, 302)
        with session_scope(self.app) as database:
            matching_entries = database.scalars(
                select(TimeEntry).where(
                    TimeEntry.started_at == datetime(2026, 7, 15, 15, 0, 0)
                )
            ).all()
            self.assertEqual(
                {entry.user_id for entry in matching_entries}, {1, self.user.id}
            )

    def test_session_edit_validation_and_admin_access(self) -> None:
        self.login()
        self.assertEqual(
            self.client.get(f"/contracts/{self.seed.contract_id}/sessions").status_code,
            200,
        )
        self.assertEqual(
            self.client.get(f"/sessions/{self.seed.entry_id}/edit").status_code, 200
        )
        with session_scope(self.app) as database:
            task = database.get(Task, self.seed.other_task_id)
            assert task is not None
            database.add(
                TimeEntry(
                    user_id=self.user.id,
                    task=task,
                    started_at=datetime(2026, 7, 15, 14, 0, 0),
                    stopped_at=datetime(2026, 7, 15, 15, 0, 0),
                )
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
            {
                "assignment": str(self.seed.task_id),
                "started_at": "2099-01-01T10:00:00",
                "stopped_at": "2099-01-01T10:30:00",
            },
            {
                "assignment": str(self.seed.task_id),
                "started_at": "2026-07-15T09:15:00",
                "stopped_at": "2026-07-15T09:45:00",
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
        with self.assertRaises(ValueError):
            local_datetime_to_utc(
                "2026-11-01T01:30:00",
                "Time",
                "America/Chicago",
                original_utc=datetime(2026, 11, 1, 5, 30, 0),
            )


if __name__ == "__main__":
    import unittest

    unittest.main()
