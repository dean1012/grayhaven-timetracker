"""End-to-end route, permission, security-header, and workflow tests."""

from __future__ import annotations

import logging
import re
import time
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pyotp
from argon2 import PasswordHasher
from flask import g
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import Conflict, Forbidden

from grayhaven_timetracker import routes
from grayhaven_timetracker.audit import record_audit_event
from grayhaven_timetracker.auth import (
    LoginLimiter,
    reset_totp_replay_state,
    set_session_invalidation_notice,
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

    def test_session_invalidation_notices_cover_disabled_password_and_privilege_changes(
        self,
    ) -> None:
        disabled = self.create_user(email="disabled@example.invalid")
        disabled_client = self.app.test_client()
        self.login(
            disabled_client,
            email=disabled.email,
            password="Standard-User-Test-Password-0001!",
            totp_secret="KRSXG5DSNFXGOIDB",
        )
        with session_scope(self.app) as database:
            user = database.get(User, disabled.id)
            assert user is not None
            user.is_enabled = False
        self.assertIn("/login", disabled_client.get("/").location)

        notice_user = self.create_user(email="notice@example.invalid")
        notice_client = self.app.test_client()
        self.login(
            notice_client,
            email=notice_user.email,
            password="Standard-User-Test-Password-0001!",
            totp_secret="KRSXG5DSNFXGOIDB",
        )
        with self.app.app_context(), session_scope(self.app) as database:
            g.database_session = database
            user = database.get(User, notice_user.id)
            assert user is not None
            user.session_version += 1
            set_session_invalidation_notice(user, "password_changed")
            set_session_invalidation_notice(user, "password_changed_again")
        self.assertIn("/login", notice_client.get("/").location)

        privilege_user = self.create_user(email="privilege@example.invalid")
        privilege_client = self.app.test_client()
        self.login(
            privilege_client,
            email=privilege_user.email,
            password="Standard-User-Test-Password-0001!",
            totp_secret="KRSXG5DSNFXGOIDB",
        )
        with session_scope(self.app) as database:
            user = database.get(User, privilege_user.id)
            assert user is not None
            user.role = "admin"
            user.session_version += 1
        self.assertIn("/login", privilege_client.get("/").location)

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
                    if item.startswith("fa-") and item != "fa-solid" and "{" not in item
                )
        missing_icons = sorted(
            icon for icon in used_icons if f".{icon}:before" not in stylesheet
        )
        self.assertEqual(missing_icons, [])

        app_stylesheet = (project_root / "static/app.css").read_text(encoding="utf-8")
        for media_query in (
            "@media (width <=400px)",
            "@media (width <=575px)",
            "@media (width <1440px)",
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
        self.assertIn(".responsive-table tbody > tr > td::before", app_stylesheet)
        self.assertIn(
            ".active-timer-actions .timer-stop-form",
            app_stylesheet,
        )
        self.assertIn("flex: 1 1 0", app_stylesheet)
        self.assertNotIn("overflow-x: auto", app_stylesheet)
        self.assertNotRegex(
            app_stylesheet,
            r"\.(?:session-table|my-session-table|user-table|audit-table)\s*\{[^}]*min-width",
        )
        self.assertNotIn(
            ".report-page-public .report-detail { display: none; }",
            app_stylesheet,
        )

        responsive_templates = {
            "sessions.html": (
                "responsive-table session-table",
                'data-label="Actions"',
            ),
            "my_sessions.html": (
                "responsive-table my-session-table",
                'data-label="Invoice"',
            ),
            "users.html": ("responsive-table user-table", 'data-label="TOTP"'),
            "audit_log.html": (
                "responsive-table audit-table",
                'data-label="Details"',
            ),
            "_report_content.html": (
                "responsive-table report-session-table",
                'data-label="Cost"',
            ),
        }
        for filename, markers in responsive_templates.items():
            template = (project_root / "templates" / filename).read_text(
                encoding="utf-8"
            )
            with self.subTest(template=filename):
                for marker in markers:
                    self.assertIn(marker, template)

        active_timer_template = (
            project_root / "templates" / "active_timer.html"
        ).read_text(encoding="utf-8")
        self.assertIn('class="icon-button timer-action"', active_timer_template)
        self.assertIn('class="timer-stop-form"', active_timer_template)

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
        live = self.client.get("/login", headers={"X-Grayhaven-Live-Refresh": "1"})
        self.assertIsNotNone(live.headers.get("ETag"))
        unchanged = self.client.get(
            "/login",
            headers={
                "X-Grayhaven-Live-Refresh": "1",
                "If-None-Match": live.headers["ETag"],
            },
        )
        self.assertEqual(unchanged.status_code, 304)
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

    def test_audit_details_include_readable_labels_and_ignore_empty_changes(
        self,
    ) -> None:
        self.login()
        seed = self.seed_contract()
        with self.app.test_request_context("/"):
            with session_scope(self.app) as database:
                g.database_session = database
                routes.audit("empty_change", actor_id=1, changes={})
                routes.audit(
                    "label_detail_test",
                    actor_id=1,
                    client_id=seed.client_id,
                    contract_id=9999,
                    task_id=seed.task_id,
                    time_entry_id=seed.entry_id,
                    source_ip="192.0.2.10",
                )
        with session_scope(self.app) as database:
            event = database.scalar(
                select(AuditEvent)
                .where(AuditEvent.event == "label_detail_test")
                .order_by(AuditEvent.id.desc())
            )
            assert event is not None
            self.assertEqual(event.details["client"], f"Pellera (ID: {seed.client_id})")
            self.assertEqual(event.details["contract"], "Deleted record (ID: 9999)")
            self.assertEqual(
                event.details["time_entry"], f"Time entry (ID: {seed.entry_id})"
            )
            self.assertEqual(event.ip_address, "192.0.2.10")

    def test_stale_parent_helpers_resolve_matching_audit_details(self) -> None:
        self.login()
        seed = self.seed_contract()
        with self.app.test_request_context("/"):
            with session_scope(self.app) as database:
                g.database_session = database
                record_audit_event(
                    database,
                    "contract_deleted",
                    source="admin",
                    details={"contract": "Missing Parent (ID: 699)"},
                )
                record_audit_event(
                    database,
                    "contract_deleted",
                    source="admin",
                    details={
                        "contract": "Deleted Contract (ID: 700)",
                        "client": f"Pellera (ID: {seed.client_id})",
                    },
                )
                record_audit_event(
                    database,
                    "time_entry_created",
                    source="admin",
                    details={"time entry": "Missing Parent (ID: 700)"},
                )
                record_audit_event(
                    database,
                    "time_entry_created",
                    source="admin",
                    details={
                        "time entry": "Time entry (ID: 701)",
                        "contract": f"Hamilton Beach (ID: {seed.contract_id})",
                    },
                )
                self.assertEqual(
                    routes.deleted_resource_parent_id(
                        ("contract_deleted",), "contract", 700, "client"
                    ),
                    seed.client_id,
                )
                self.assertEqual(
                    routes.created_resource_parent_id("time entry", 701, "contract"),
                    seed.contract_id,
                )
                self.assertIsNone(
                    routes.deleted_resource_parent_id(
                        ("contract_deleted",), "contract", 999, "client"
                    )
                )

    def test_admin_can_filter_and_paginate_append_only_audit_history(self) -> None:
        self.login()
        self.assertEqual(self.client.get("/").status_code, 200)
        response = self.client.get("/audit")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Audit Log", response.data)
        self.assertIn(b"Application Started", response.data)
        self.assertIn(b"Login Succeeded", response.data)
        self.assertNotIn(b">Request<", response.data)
        self.assertIn(b"responsive-table audit-table", response.data)
        self.assertIn(b'data-label="Details"', response.data)

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
        self.assertIn(b"Page 2 of 3", filtered.data)
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
        ):
            with self.subTest(query=query):
                self.assertIn(
                    self.client.get(f"/audit?{query}").status_code, {400, 404}
                )
        self.assertEqual(self.client.get("/audit?page=999").status_code, 302)

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
        with self.assertRaises(ValueError):
            routes.ReportPasswordConfirmationStore(ttl_seconds=0)
        with self.assertRaises(ValueError):
            routes.ReportPasswordConfirmationStore(maximum_items=0)
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
        mismatch_token = store.issue(
            actor_user_id=1,
            client_id=2,
            report_password="Mismatch-Report-Password-For-Test-0001!",
            now=1_200,
        )
        self.assertIsNone(
            store.consume(mismatch_token, actor_user_id=9, client_id=2, now=1_201)
        )

        expired_token = store.issue(
            actor_user_id=1,
            client_id=2,
            report_password="Expired-Report-Password-For-Test-0001!",
            now=2_000,
        )
        self.assertIsNone(
            store.consume(expired_token, actor_user_id=1, client_id=2, now=2_120)
        )

        bounded = routes.ReportPasswordConfirmationStore(
            ttl_seconds=120, maximum_items=1
        )
        first = bounded.issue(
            actor_user_id=1,
            client_id=1,
            report_password="First-Report-Password-For-Test-0001!",
            now=3_000,
        )
        second = bounded.issue(
            actor_user_id=1,
            client_id=1,
            report_password="Second-Report-Password-For-Test-0001!",
            now=3_001,
        )
        self.assertIsNone(
            bounded.consume(first, actor_user_id=1, client_id=1, now=3_002)
        )
        self.assertIsNotNone(
            bounded.consume(second, actor_user_id=1, client_id=1, now=3_002)
        )
        discarded = bounded.issue(
            actor_user_id=1,
            client_id=1,
            report_password="Discarded-Report-Password-For-Test-0001!",
            now=3_100,
        )
        bounded._discard(discarded)
        self.assertIsNone(
            bounded.consume(discarded, actor_user_id=1, client_id=1, now=3_101)
        )
        collision_store = routes.ReportPasswordConfirmationStore()
        with patch(
            "grayhaven_timetracker.routes.secrets.token_urlsafe",
            side_effect=["collision", "collision", "replacement"],
        ):
            collision_store.issue(
                actor_user_id=1,
                client_id=1,
                report_password="Collision-Report-Password-For-Test-0001!",
                now=4_000,
            )
            replacement = collision_store.issue(
                actor_user_id=1,
                client_id=1,
                report_password="Replacement-Report-Password-For-Test-0001!",
                now=4_001,
            )
        self.assertEqual(replacement, "replacement")

    def test_assignment_and_overlap_helpers_accept_good_and_reject_bad_values(
        self,
    ) -> None:
        seed = self.seed_contract()
        with self.app.test_request_context("/"):
            with session_scope(self.app) as database:
                g.database_session = database
                task, subtask = routes.parse_assignment(
                    f"{seed.task_id}:{seed.subtask_id}", seed.contract_id
                )
                self.assertEqual(task.id, seed.task_id)
                assert subtask is not None
                self.assertEqual(subtask.id, seed.subtask_id)
                for value in ("bad", "9999", f"{seed.task_id}:9999"):
                    with self.subTest(value=value), self.assertRaises(ValueError):
                        routes.parse_assignment(value, seed.contract_id)
                self.assertTrue(
                    routes.time_entry_overlaps(
                        1,
                        datetime(2026, 7, 15, 1, 45),
                        datetime(2026, 7, 15, 2, 0),
                    )
                )
                self.assertFalse(
                    routes.time_entry_overlaps(
                        1,
                        datetime(2026, 7, 15, 1, 30),
                        datetime(2026, 7, 15, 2, 37),
                        exclude_entry_id=seed.entry_id,
                    )
                )
                user = database.get(User, 1)
                assert user is not None
                g.current_user = user
                entry = database.get(TimeEntry, seed.entry_id)
                assert entry is not None
                self.assertTrue(
                    routes.time_entry_allowed(
                        entry, "time_entry:view_own", "time_entry:view_any"
                    )
                )
                self.assertIsNone(routes.active_time_entry_for_current_user())

    def test_route_helpers_cover_invalid_local_values_and_stale_parents(self) -> None:
        seed = self.seed_contract()
        with self.app.test_request_context("/"):
            with session_scope(self.app) as database:
                g.database_session = database
                user = database.get(User, 1)
                assert user is not None
                g.current_user = user
                self.assertIsNone(
                    routes.deleted_resource_parent_id(
                        ("missing",), "thing", 1, "parent"
                    )
                )
                self.assertIsNone(
                    routes.created_resource_parent_id("time entry", 9999, "contract")
                )
                self.assertIsNone(routes.active_time_entry_for_current_user())
                for value in ("", "1:2:3", "1:x"):
                    with self.subTest(value=value), self.assertRaises(ValueError):
                        routes.parse_assignment(value, seed.contract_id)
                for value in ("not-a-date", "2026-02-30T10:00"):
                    with self.subTest(value=value), self.assertRaises(ValueError):
                        routes.local_datetime_to_utc(
                            value, "Start time", "America/Chicago"
                        )

        with session_scope(self.app) as database:
            record_audit_event(
                database,
                "contract_deleted",
                source="admin",
                details={
                    "contract": "No Parent ID (ID: 9910)",
                    "client": "Client without an ID",
                },
            )
            record_audit_event(
                database,
                "time_entry_created",
                source="admin",
                details={
                    "time entry": "No Parent ID (ID: 9911)",
                    "contract": "Contract without an ID",
                },
            )
            record_audit_event(
                database,
                "contract_deleted",
                source="admin",
                details={
                    "contract": "Match Contract (ID: 9900)",
                    "client": f"Pellera (ID: {seed.client_id})",
                },
            )
            record_audit_event(
                database,
                "time_entry_created",
                source="admin",
                details={
                    "time entry": "Time entry (ID: 9900)",
                    "contract": f"Hamilton Beach - Phase 1 (ID: {seed.contract_id})",
                },
            )
        with self.app.app_context(), session_scope(self.app) as database:
            g.database_session = database
            self.assertEqual(
                routes.deleted_resource_parent_id(
                    ("contract_deleted",), "contract", 9900, "client"
                ),
                seed.client_id,
            )
            self.assertEqual(
                routes.created_resource_parent_id("time entry", 9900, "contract"),
                seed.contract_id,
            )
            self.assertIsNone(
                routes.deleted_resource_parent_id(
                    ("contract_deleted",), "contract", 9910, "client"
                )
            )
            self.assertIsNone(
                routes.created_resource_parent_id("time entry", 9911, "contract")
            )
        with session_scope(self.app) as database:
            record_audit_event(
                database,
                "contract_deleted",
                source="admin",
                details={
                    "contract": "Gone Contract (ID: 9901)",
                    "client": f"Pellera (ID: {seed.client_id})",
                },
            )
            record_audit_event(
                database,
                "task_deleted",
                source="admin",
                details={
                    "task": "Gone Task (ID: 9902)",
                    "contract": "Gone Contract (ID: 9903)",
                },
            )
            record_audit_event(
                database,
                "subtask_deleted",
                source="admin",
                details={
                    "subtask": "Gone Subtask (ID: 9904)",
                    "contract": "Gone Contract (ID: 9905)",
                },
            )
            record_audit_event(
                database,
                "time_entry_created",
                source="admin",
                details={
                    "time entry": "Time entry (ID: 9906)",
                    "contract": f"Hamilton Beach - Phase 1 (ID: {seed.contract_id})",
                },
            )
        self.assertIn(
            f"/clients/{seed.client_id}", self.client.get("/reports/9901").location
        )
        self.assertIn("stale=task_deleted", self.client.get("/tasks/9902").location)
        self.assertIn(
            "stale=subtask_deleted", self.client.get("/subtasks/9904").location
        )
        self.assertIn(
            f"/contracts/{seed.contract_id}/sessions",
            self.client.get("/sessions/9906").location,
        )

        stale = self.client.get("/contracts/9999")
        self.assertEqual(stale.status_code, 302)
        self.assertIn("stale=contract_deleted", stale.location)
        self.assertEqual(
            self.client.get(f"/reports/{seed.contract_id}/missing").status_code,
            404,
        )

    def test_duplicate_contract_task_and_subtask_routes(self) -> None:
        seed = self.seed_contract()
        duplicate_contract = self.client.post(
            f"/contracts/new/{seed.client_id}",
            data={
                "name": "hamilton beach - phase 1",
                "contact_name": "Contact",
                "contact_email": "contact@example.invalid",
                "hourly_rate": "55",
            },
        )
        self.assertEqual(duplicate_contract.status_code, 400)
        duplicate_task = self.client.post(
            f"/tasks/{seed.contract_id}/new", data={"name": "discovery"}
        )
        self.assertEqual(duplicate_task.status_code, 302)
        duplicate_subtask = self.client.post(
            f"/subtasks/{seed.task_id}/new", data={"name": "server 1"}
        )
        self.assertEqual(duplicate_subtask.status_code, 302)
        with session_scope(self.app) as database:
            database.add(Subtask(task_id=seed.task_id, name="Second Subtask"))
        task = self.client.post(
            f"/tasks/{seed.other_task_id}/rename", data={"name": "Discovery"}
        )
        self.assertEqual(task.status_code, 302)
        subtask = self.client.post(
            f"/subtasks/{seed.subtask_id}/rename", data={"name": "Second Subtask"}
        )
        self.assertEqual(subtask.status_code, 302)

    def test_commit_races_return_conflict_responses(self) -> None:
        seed = self.seed_contract()
        with patch(
            "sqlalchemy.orm.Session.commit",
            side_effect=IntegrityError("duplicate", {}, Exception("duplicate")),
        ):
            response = self.client.post(
                "/clients/new",
                data={
                    "name": "Raced Client",
                    "contact_name": "Contact",
                    "contact_email": "contact@example.invalid",
                },
            )
        self.assertEqual(response.status_code, 409)

        with session_scope(self.app) as database:
            client = database.get(Client, seed.client_id)
            assert client is not None
            other = Client(
                name="Other Client",
                contact_name="Contact",
                contact_email="other@example.invalid",
            )
            database.add(other)
            database.flush()
            other_id = other.id
            second_contract = Contract(
                client_id=seed.client_id,
                name="Second Contract",
                contact_name="Contact",
                contact_email="second@example.invalid",
                hourly_rate_cents=5500,
            )
            database.add(second_contract)
            database.flush()
        duplicate_edit = self.client.post(
            f"/clients/{other_id}/edit",
            data={
                "name": "Pellera",
                "contact_name": "Contact",
                "contact_email": "other@example.invalid",
            },
        )
        self.assertEqual(duplicate_edit.status_code, 400)
        duplicate_contract_edit = self.client.post(
            f"/contracts/{seed.contract_id}/edit",
            data={
                "name": "Second Contract",
                "contact_name": "Contact",
                "contact_email": "contact@example.invalid",
            },
        )
        self.assertEqual(duplicate_contract_edit.status_code, 400)
        for path, data in (
            (
                f"/clients/{seed.client_id}/edit",
                {
                    "name": "Raced Client",
                    "contact_name": "Contact",
                    "contact_email": "contact@example.invalid",
                },
            ),
            (
                f"/contracts/{seed.contract_id}/edit",
                {
                    "name": "Raced Contract",
                    "contact_name": "Contact",
                    "contact_email": "contact@example.invalid",
                },
            ),
        ):
            with patch(
                "sqlalchemy.orm.Session.commit",
                side_effect=IntegrityError("duplicate", {}, Exception("duplicate")),
            ):
                response = self.client.post(
                    path,
                    data=data
                    | ({"hourly_rate": "55"} if "/contracts/" in path else {}),
                )
            self.assertEqual(response.status_code, 409)

        for path, payload in (
            (
                f"/contracts/new/{seed.client_id}",
                {
                    "name": "Raced Contract",
                    "contact_name": "Contact",
                    "contact_email": "contact@example.invalid",
                    "hourly_rate": "55",
                },
            ),
            (f"/tasks/{seed.contract_id}/new", {"name": "Raced Task"}),
            (f"/subtasks/{seed.task_id}/new", {"name": "Raced Subtask"}),
        ):
            with patch(
                "sqlalchemy.orm.Session.commit",
                side_effect=IntegrityError("duplicate", {}, Exception("duplicate")),
            ):
                response = self.client.post(path, data=payload)
            self.assertIn(response.status_code, (302, 409))

    def test_sensitive_delete_forms_require_reason_and_reauthentication(self) -> None:
        seed = self.seed_contract()
        self.assertEqual(
            self.client.get(f"/clients/{seed.client_id}/delete").status_code, 200
        )
        self.assertEqual(
            self.client.post(
                f"/clients/{seed.client_id}/delete",
                data={"current_password": ADMIN_PASSWORD},
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                f"/clients/{seed.client_id}/delete",
                data={"current_password": "wrong", "correction_reason": "Reject"},
            ).status_code,
            400,
        )
        for path in (
            f"/contracts/{seed.contract_id}/delete",
            f"/tasks/{seed.task_id}/delete",
            f"/subtasks/{seed.subtask_id}/delete",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)
                self.assertEqual(
                    self.client.post(
                        path, data={"current_password": ADMIN_PASSWORD}
                    ).status_code,
                    400,
                )
                self.assertEqual(
                    self.client.post(
                        path,
                        data={
                            "current_password": "wrong",
                            "correction_reason": "Reject",
                        },
                    ).status_code,
                    400,
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
        duplicate = self.client.post(
            "/clients/new",
            data={
                "name": "client one",
                "contact_name": "Another Contact",
                "contact_email": "another@example.invalid",
            },
        )
        self.assertEqual(duplicate.status_code, 400)
        anonymous = self.app.test_client()
        self.assertEqual(anonymous.get("/shared/reports/short").status_code, 404)
        self.assertEqual(
            anonymous.get(f"/shared/reports/{'A' * 32}").status_code,
            404,
        )
        with session_scope(self.app) as database:
            client = database.scalar(select(Client).where(Client.name == "Client One"))
            assert client is not None
            client_id = client.id
            self.assertEqual(client.contact_email, "client@example.invalid")
            self.assertIsNone(client.report_password_hash)
        self.assertEqual(self.client.get(f"/clients/{client_id}").status_code, 200)
        self.assertEqual(self.client.get("/clients/9999").status_code, 302)
        self.assertEqual(
            self.client.get("/clients/9999").location, "/?stale=client_deleted"
        )
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
        self.assertEqual(self.client.get("/clients/9999/edit").status_code, 302)
        self.assertEqual(
            self.client.get("/clients/9999/edit").location,
            "/?stale=client_deleted",
        )
        self.assertEqual(self.client.get("/contracts/9999/edit").status_code, 302)
        self.assertEqual(
            self.client.get("/contracts/9999/edit").location,
            "/?stale=contract_deleted",
        )
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
        with self.client.session_transaction() as browser_session:
            browser_session["report_password_confirmation_client_id"] = client_id
            browser_session["report_password_confirmation_token"] = "unissued-token"
        self.assertEqual(
            self.client.get(
                f"/clients/{client_id}/report-password/confirmation"
            ).status_code,
            302,
        )

    def test_task_and_subtask_deletion_removes_work_data_and_retains_audit(
        self,
    ) -> None:
        seed = self.seed_contract()
        self.assertEqual(
            self.client.get(f"/contracts/{seed.contract_id}").status_code, 200
        )
        self.assertEqual(self.client.get("/contracts/9999").status_code, 302)
        self.assertEqual(
            self.client.get("/contracts/9999").location,
            "/?stale=contract_deleted",
        )
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
                data={
                    "current_password": ADMIN_PASSWORD,
                    "correction_reason": "Remove test subtask",
                },
            ).status_code,
            302,
        )
        stale_subtask = self.client.get(f"/subtasks/{child_id}/delete")
        self.assertEqual(stale_subtask.status_code, 302)
        self.assertIn(f"/contracts/{seed.contract_id}", stale_subtask.location)
        self.assertEqual(
            self.client.post(
                f"/tasks/{unused_id}/delete",
                data={
                    "current_password": ADMIN_PASSWORD,
                    "correction_reason": "Remove unused test task",
                },
            ).status_code,
            302,
        )
        stale_task = self.client.get(f"/tasks/{unused_id}/delete")
        self.assertEqual(stale_task.status_code, 302)
        self.assertIn(f"/contracts/{seed.contract_id}", stale_task.location)
        self.assertEqual(
            self.client.post(
                f"/tasks/{seed.task_id}/delete",
                data={
                    "current_password": ADMIN_PASSWORD,
                    "correction_reason": "Remove test task",
                },
            ).status_code,
            302,
        )
        stale_task = self.client.get(f"/tasks/{seed.task_id}/delete")
        self.assertEqual(stale_task.status_code, 302)
        self.assertIn(f"/contracts/{seed.contract_id}", stale_task.location)
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
                data={
                    "current_password": ADMIN_PASSWORD,
                    "correction_reason": "Remove test contract",
                },
            ).status_code,
            302,
        )
        stale_contract = self.client.get(f"/contracts/{seed.contract_id}/delete")
        self.assertEqual(stale_contract.status_code, 302)
        self.assertIn(f"/clients/{seed.client_id}", stale_contract.location)
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
                data={
                    "current_password": ADMIN_PASSWORD,
                    "correction_reason": "Remove test client",
                },
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
            404,
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

    def test_delete_handlers_reject_non_admins_after_permission_dispatch(self) -> None:
        with self.app.app_context(), session_scope(self.app) as database:
            g.database_session = database
            g.current_user = database.get(User, self.user.id)
            with (
                self.app.test_request_context(f"/tasks/{self.seed.task_id}/delete"),
                self.assertRaises(Forbidden),
            ):
                routes.delete_task.__wrapped__(self.seed.task_id)
            with self.app.test_request_context(
                f"/subtasks/{self.seed.subtask_id}/delete"
            ):
                g.database_session = database
                with self.assertRaises(Forbidden):
                    routes.delete_subtask.__wrapped__(self.seed.subtask_id)

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
        self.login(
            password=new_password,
            totp_secret=ADMIN_TOTP_SECRET,
            totp_token=next_totp(ADMIN_TOTP_SECRET),
        )
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
        self.assertEqual(self.client.post("/profile/totp/setup").status_code, 200)
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
        with self.client.session_transaction() as browser_session:
            browser_session["totp_setup_expires_at"] = 0
        self.assertEqual(
            self.client.post(
                "/profile/totp/confirm", data={"totp": "000000"}
            ).status_code,
            302,
        )
        setup = self.client.post("/profile/totp/setup")
        self.assertEqual(setup.status_code, 200)
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin and admin.pending_totp_secret
            pending = admin.pending_totp_secret
        self.assertEqual(
            self.client.post(
                "/profile/totp/confirm", data={"totp": pyotp.TOTP(pending).now()}
            ).status_code,
            302,
        )
        self.login(totp_secret=pending, totp_token=next_totp(pending))
        self.assertEqual(
            self.client.post(
                "/profile/totp/disable",
                data={"current_password": "wrong", "totp": "000000"},
            ).status_code,
            400,
        )
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            reset_totp_replay_state(database, admin.id)
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
        self.login(totp_secret="")
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
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.totp_secret = None
            reset_totp_replay_state(database, admin.id)
        users_page = self.client.get("/users")
        self.assertEqual(users_page.status_code, 200)
        self.assertIn(b"responsive-table user-table", users_page.data)
        self.assertIn(b'data-label="TOTP"', users_page.data)
        self.assertEqual(self.client.get("/users?page=invalid").status_code, 400)
        self.assertEqual(self.client.get("/users?page=0").status_code, 400)
        self.assertEqual(self.client.get("/users?page=99").status_code, 302)
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
        self.assertEqual(
            self.client.post(
                "/users/new",
                data={
                    "first_name": "Invalid",
                    "last_name": "Role",
                    "email": "invalid-role@example.invalid",
                    "role": "owner",
                },
            ).status_code,
            400,
        )
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
        self.assertIn(temporary_password.encode(), created.data)
        self.assertNotIn(b"Authenticator setup QR code", created.data)
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
            self.client.post(
                f"/users/{user_id}/toggle-admin",
                data={"current_password": ADMIN_PASSWORD},
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post(
                f"/users/{user_id}/toggle-admin",
                data={"current_password": ADMIN_PASSWORD},
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post(
                f"/users/{user_id}/toggle-enabled",
                data={"current_password": ADMIN_PASSWORD},
            ).status_code,
            302,
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
            self.client.get(f"/users/{user_id}/toggle-enabled").status_code, 200
        )
        self.assertEqual(
            self.client.get(f"/users/{user_id}/toggle-admin").status_code, 200
        )
        self.assertEqual(
            self.client.post(
                f"/users/{user_id}/toggle-enabled",
                data={"current_password": "wrong"},
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                f"/users/{user_id}/toggle-admin",
                data={"current_password": "wrong"},
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                f"/users/{user_id}/toggle-enabled",
                data={"current_password": ADMIN_PASSWORD},
            ).status_code,
            302,
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
        self.assertEqual(managed_email_change.status_code, 302)
        with patch(
            "sqlalchemy.orm.Session.commit",
            side_effect=IntegrityError("duplicate", {}, Exception("duplicate")),
        ):
            raced = self.client.post(
                f"/users/{user.id}/edit",
                data={
                    "first_name": "Raced",
                    "last_name": "Identity",
                    "email": "raced@example.invalid",
                },
            )
        self.assertEqual(raced.status_code, 409)

    def test_admin_can_disable_another_users_totp_with_reauthentication(self) -> None:
        target = self.create_user(
            email="totp-target@example.invalid",
            first_name="TOTP",
            last_name="Target",
            totp_secret="KRSXG5DSNFXGOIDB",
        )
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.totp_secret = None
            reset_totp_replay_state(database, admin.id)
        disable_url = f"/users/{target.id}/disable-totp"
        self.assertEqual(self.client.post("/users/1/disable-totp").status_code, 409)
        self.assertEqual(self.client.get(disable_url).status_code, 200)
        self.assertEqual(
            self.client.post(
                disable_url,
                data={"current_password": "wrong"},
            ).status_code,
            400,
        )
        disabled = self.client.post(
            disable_url,
            data={"current_password": ADMIN_PASSWORD},
        )
        self.assertEqual(disabled.status_code, 302)
        with session_scope(self.app) as database:
            user = database.get(User, target.id)
            assert user is not None
            self.assertIsNone(user.totp_secret)
        self.assertEqual(self.client.get(disable_url).status_code, 302)

    def test_last_enabled_administrator_guards_fail_closed(self) -> None:
        actor = self.create_user(
            email="guard-actor@example.invalid",
            role="user",
            totp_secret=None,
        )
        for endpoint, view in (
            ("toggle-enabled", routes.toggle_user_enabled),
            ("toggle-admin", routes.toggle_user_admin),
        ):
            with self.subTest(endpoint=endpoint), self.app.app_context():
                with session_scope(self.app) as database:
                    g.database_session = database
                    g.current_user = database.get(User, actor.id)
                    with (
                        self.app.test_request_context(
                            f"/users/1/{endpoint}",
                            method="POST",
                            data={
                                "current_password": "Standard-User-Test-Password-0001!"
                            },
                        ),
                        self.assertRaises(Conflict),
                    ):
                        view.__wrapped__(1)

    def test_sensitive_user_actions_rate_limit_repeated_rejections(self) -> None:
        target = self.create_user(
            email="rate-target@example.invalid",
            totp_secret="KRSXG5DSNFXGOIDB",
        )
        for path in (
            f"/users/{target.id}/disable-totp",
            f"/users/{target.id}/toggle-enabled",
            f"/users/{target.id}/toggle-admin",
        ):
            with self.subTest(path=path):
                routes.sensitive_action_limiter = LoginLimiter(limit=1)
                data = {"current_password": "wrong"}
                self.assertEqual(self.client.post(path, data=data).status_code, 400)
                self.assertEqual(self.client.post(path, data=data).status_code, 429)
                routes.sensitive_action_limiter = LoginLimiter()

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
                follow_redirects=True,
            )
        self.assertEqual(reset.status_code, 200)
        self.assertIn(temporary_password.encode(), reset.data)
        self.assertIn("/login", existing_session.get("/").location)
        self.assertEqual(self.client.post("/users/1/reset-password").status_code, 409)
        self.assertEqual(
            self.client.get(f"/users/{user.id}/reset-password/confirmation").location,
            "/users",
        )
        with self.client.session_transaction() as browser_session:
            browser_session["user_password_confirmation_user_id"] = user.id
            browser_session["user_password_confirmation_token"] = "unissued-token"
        self.assertEqual(
            self.client.get(
                f"/users/{user.id}/reset-password/confirmation"
            ).status_code,
            302,
        )

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
        self.assertEqual(changed.location, "/login")
        self.assertEqual(recovered.get("/").status_code, 302)
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
        self.assertIn(b"responsive-table report-task-summary-table", html.data)
        self.assertIn(b"responsive-table report-session-table", html.data)
        self.assertIn(b'data-label="Cost" data-report-session-cost', html.data)
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
        self.assertEqual(self.client.get("/reports/9999").status_code, 302)
        self.assertEqual(
            self.client.get("/reports/9999").location,
            "/?stale=contract_deleted",
        )
        self.assertEqual(self.client.get("/reports/9999/live").status_code, 302)
        self.assertEqual(
            self.client.get("/reports/9999/live").location,
            "/?stale=contract_deleted",
        )
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
            anonymous.get(f"/shared/reports/{token}/live").status_code, 302
        )
        self.assertEqual(
            anonymous.get(f"/shared/reports/{token}/live").location,
            f"/shared/reports/{token}",
        )
        self.app.config["WTF_CSRF_ENABLED"] = True
        csrf_rejected = anonymous.post(
            f"/shared/reports/{token}", data={"report_password": "unused"}
        )
        self.assertEqual(csrf_rejected.status_code, 302)
        self.assertEqual(csrf_rejected.location, f"/shared/reports/{token}")
        self.app.config["WTF_CSRF_ENABLED"] = False
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
        bad_client = self.app.test_client()
        routes.shared_report_limiter = LoginLimiter(limit=1)
        self.assertEqual(
            bad_client.post(
                f"/shared/reports/{token}", data={"report_password": "wrong"}
            ).status_code,
            401,
        )
        self.assertEqual(
            bad_client.post(
                f"/shared/reports/{token}", data={"report_password": "wrong"}
            ).status_code,
            429,
        )
        routes.shared_report_limiter = LoginLimiter()
        self.assertEqual(
            anonymous.post(
                f"/shared/reports/{token}", data={"report_password": report_password}
            ).status_code,
            302,
        )
        shared = anonymous.get(f"/shared/reports/{token}")
        self.assertEqual(shared.status_code, 200)
        self.assertIn(b"Live Client Report", shared.data)
        live = anonymous.get(f"/shared/reports/{token}/live")
        self.assertEqual(live.status_code, 200)
        live_etag = live.headers["ETag"]
        self.assertEqual(
            anonymous.get(
                f"/shared/reports/{token}/live",
                headers={"If-None-Match": live_etag},
            ).status_code,
            304,
        )
        self.assertEqual(
            self.client.post(f"/clients/{self.seed.client_id}/report-link").status_code,
            404,
        )

    def test_session_payment_status_requires_metadata_and_is_reversible(self) -> None:
        self.login()
        status_url = f"/sessions/{self.seed.entry_id}/status"
        self.assertEqual(self.client.get(status_url).status_code, 200)

        routes.sensitive_action_limiter = LoginLimiter(limit=1)
        rejected_status = {
            "billing_status": "pending_invoice",
            "correction_reason": "Reject status credentials",
            "current_password": "wrong",
        }
        self.assertEqual(
            self.client.post(status_url, data=rejected_status).status_code, 400
        )
        self.assertEqual(
            self.client.post(status_url, data=rejected_status).status_code, 429
        )
        routes.sensitive_action_limiter = LoginLimiter()

        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            reset_totp_replay_state(database, admin.id)
        invalid_status = self.client.post(
            status_url,
            data={
                "billing_status": "invalid",
                "correction_reason": "Reject invalid status",
                "current_password": ADMIN_PASSWORD,
                "totp_digit": list(pyotp.TOTP(ADMIN_TOTP_SECRET).now()),
            },
        )
        self.assertEqual(invalid_status.status_code, 400)
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            reset_totp_replay_state(database, admin.id)
        invoiced = self.client.post(
            status_url,
            data={
                "billing_status": "invoiced",
                "invoice_number": "INV-001",
                "invoice_date": "2026-07-17",
                "correction_reason": "Record invoice",
                "current_password": ADMIN_PASSWORD,
                "totp_digit": list(pyotp.TOTP(ADMIN_TOTP_SECRET).now()),
            },
        )
        self.assertEqual(invoiced.status_code, 302)
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None
            self.assertEqual(entry.billing_status, "invoiced")
            self.assertEqual(entry.invoice_number, "INV-001")
            self.assertEqual(entry.invoice_date, date(2026, 7, 17))

        self.assertEqual(
            self.client.get(f"/sessions/{self.seed.entry_id}/edit").status_code, 409
        )
        self.assertEqual(
            self.client.post(f"/sessions/{self.seed.entry_id}/delete").status_code, 409
        )
        self.assertEqual(
            self.client.get(f"/tasks/{self.seed.task_id}/delete").status_code, 409
        )

        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            reset_totp_replay_state(database, admin.id)
        pending = self.client.post(
            status_url,
            data={
                "billing_status": "pending_invoice",
                "correction_reason": "Correct invoice assignment",
                "current_password": ADMIN_PASSWORD,
                "totp_digit": list(pyotp.TOTP(ADMIN_TOTP_SECRET).now()),
            },
        )
        self.assertEqual(pending.status_code, 302)
        with session_scope(self.app) as database:
            entry = database.get(TimeEntry, self.seed.entry_id)
            assert entry is not None
            self.assertEqual(entry.billing_status, "pending_invoice")
            self.assertIsNone(entry.invoice_number)
            self.assertIsNone(entry.invoice_date)
            audit_events = database.scalars(
                select(AuditEvent).where(
                    AuditEvent.event == "time_entry_status_updated"
                )
            ).all()
            self.assertTrue(audit_events)
            details = audit_events[-1].details
            self.assertEqual(details["changes"]["Status"]["from"], "Invoiced")
            self.assertEqual(details["changes"]["Status"]["to"], "Pending Invoice")
            self.assertEqual(details["correction_reason"], "Correct invoice assignment")

    def test_payment_status_rejects_missing_and_malformed_metadata(self) -> None:
        self.login()
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.totp_secret = None
            reset_totp_replay_state(database, admin.id)
        status_url = f"/sessions/{self.seed.entry_id}/status"
        self.assertEqual(self.client.get("/sessions/9999/status").status_code, 404)
        with session_scope(self.app) as database:
            task = database.get(Task, self.seed.task_id)
            user = database.get(User, self.user.id)
            assert task is not None and user is not None
            active = TimeEntry(
                user_id=user.id, task_id=task.id, started_at=datetime.now()
            )
            database.add(active)
            database.flush()
            active_id = active.id
        self.assertEqual(
            self.client.get(f"/sessions/{active_id}/status").status_code, 409
        )
        with session_scope(self.app) as database:
            database.delete(database.get(TimeEntry, active_id))
        base = {
            "current_password": ADMIN_PASSWORD,
            "correction_reason": "Reject bad metadata",
        }
        invalid_cases = (
            {"billing_status": "invoiced"},
            {"billing_status": "invoiced", "invoice_number": "INV-2"},
            {
                "billing_status": "invoiced",
                "invoice_number": "INV-2",
                "invoice_date": "not-a-date",
            },
            {"billing_status": "client_paid", "client_paid_date": "2026-07-17"},
            {
                "billing_status": "disbursed",
                "disbursement_date": "2026-07-17",
                "transaction_number": "TX-1",
            },
        )
        for extra in invalid_cases:
            with self.subTest(extra=extra):
                response = self.client.post(status_url, data={**base, **extra})
                self.assertEqual(response.status_code, 400)

        invoiced = self.client.post(
            status_url,
            data={
                **base,
                "billing_status": "invoiced",
                "invoice_number": "INV-2",
                "invoice_date": "2026-07-17",
            },
        )
        self.assertEqual(invoiced.status_code, 302)
        self.assertEqual(
            self.client.post(
                status_url,
                data={**base, "billing_status": "client_paid"},
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                status_url,
                data={
                    **base,
                    "billing_status": "client_paid",
                    "client_paid_date": "not-a-date",
                },
            ).status_code,
            400,
        )
        paid = self.client.post(
            status_url,
            data={
                **base,
                "billing_status": "client_paid",
                "client_paid_date": "2026-07-18",
            },
        )
        self.assertEqual(paid.status_code, 302)
        for extra in (
            {"billing_status": "disbursed", "transaction_number": "TX-1"},
            {
                "billing_status": "disbursed",
                "disbursement_date": "not-a-date",
                "transaction_number": "TX-1",
            },
            {"billing_status": "disbursed", "disbursement_date": "2026-07-19"},
        ):
            with self.subTest(extra=extra):
                self.assertEqual(
                    self.client.post(status_url, data={**base, **extra}).status_code,
                    400,
                )

    def test_admin_can_update_and_delete_a_pending_session_with_reason(self) -> None:
        self.login()
        edit_url = f"/sessions/{self.seed.entry_id}/edit"
        redirected = self.client.get(edit_url)
        self.assertEqual(redirected.status_code, 302)
        self.assertIn("original_contract_id", redirected.location)
        with session_scope(self.app) as database:
            second = Contract(
                client_id=self.seed.client_id,
                name="Original Parent Contract",
                contact_name="Contact",
                contact_email="parent@example.invalid",
                hourly_rate_cents=5500,
            )
            database.add(second)
            database.flush()
            second_id = second.id
        moved_existing = self.client.get(f"{edit_url}?original_contract_id={second_id}")
        self.assertIn(f"/contracts/{second_id}/sessions", moved_existing.location)
        self.assertEqual(
            self.client.get(f"{edit_url}?original_contract_id=invalid").status_code,
            404,
        )
        moved = self.client.get(f"{edit_url}?original_contract_id=9999")
        self.assertEqual(moved.status_code, 302)
        self.assertIn("stale=time_entry_moved", moved.location)
        with session_scope(self.app) as database:
            task = database.get(Task, self.seed.other_task_id)
            assert task is not None
            active = TimeEntry(
                user_id=self.user.id,
                task=task,
                started_at=datetime.now(),
            )
            database.add(active)
            database.flush()
            active_id = active.id
        self.assertEqual(
            self.client.get(f"/sessions/{active_id}/edit").status_code, 409
        )
        self.assertEqual(
            self.client.get(f"/sessions/{active_id}/delete").status_code,
            409,
        )
        with session_scope(self.app) as database:
            database.delete(database.get(TimeEntry, active_id))
        invalid_update = self.client.post(
            f"{edit_url}?original_contract_id={self.seed.contract_id}",
            data={
                "user_id": "9999",
                "client_id": str(self.seed.client_id),
                "contract_id": str(self.seed.contract_id),
                "assignment": str(self.seed.task_id),
                "started_at": "2026-07-15T08:00:00",
                "stopped_at": "2026-07-15T09:00:00",
                "correction_reason": "Reject invalid reassignment",
            },
        )
        self.assertEqual(invalid_update.status_code, 400)
        with patch(
            "sqlalchemy.orm.Session.commit",
            side_effect=IntegrityError("overlap", {}, Exception("overlap")),
        ):
            raced_update = self.client.post(
                f"{edit_url}?original_contract_id={self.seed.contract_id}",
                data={
                    "user_id": "1",
                    "client_id": str(self.seed.client_id),
                    "contract_id": str(self.seed.contract_id),
                    "assignment": str(self.seed.task_id),
                    "started_at": "2026-07-15T08:00:00",
                    "stopped_at": "2026-07-15T09:00:00",
                    "correction_reason": "Race test",
                },
            )
        self.assertEqual(raced_update.status_code, 409)
        update = self.client.post(
            f"{edit_url}?original_contract_id={self.seed.contract_id}",
            data={
                "user_id": "1",
                "client_id": str(self.seed.client_id),
                "contract_id": str(self.seed.contract_id),
                "assignment": str(self.seed.task_id),
                "started_at": "2026-07-15T08:00:00",
                "stopped_at": "2026-07-15T09:00:00",
                "correction_reason": "Correct pending session timing",
            },
        )
        self.assertEqual(update.status_code, 302)
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            admin.totp_secret = None
        delete_url = f"/sessions/{self.seed.entry_id}/delete"
        self.assertEqual(self.client.get(delete_url).status_code, 200)
        self.assertEqual(
            self.client.post(
                delete_url,
                data={"current_password": ADMIN_PASSWORD},
            ).status_code,
            400,
        )
        routes.sensitive_action_limiter = LoginLimiter(limit=1)
        self.assertEqual(
            self.client.post(
                delete_url,
                data={
                    "current_password": "wrong",
                    "correction_reason": "Reject invalid delete",
                },
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                delete_url,
                data={
                    "current_password": "wrong",
                    "correction_reason": "Reject invalid delete",
                },
            ).status_code,
            429,
        )
        routes.sensitive_action_limiter = LoginLimiter()
        deleted = self.client.post(
            delete_url,
            data={
                "current_password": ADMIN_PASSWORD,
                "correction_reason": "Remove corrected test session",
            },
        )
        self.assertEqual(deleted.status_code, 302)
        with session_scope(self.app) as database:
            self.assertIsNone(database.get(TimeEntry, self.seed.entry_id))

    def test_my_sessions_lists_pending_and_finalized_rows_with_pagination(self) -> None:
        self.login()
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            task = database.get(Task, self.seed.other_task_id)
            assert admin is not None and task is not None
            database.add_all(
                [
                    TimeEntry(
                        user=admin,
                        task=task,
                        started_at=datetime(2026, 7, 10, 8, 0),
                        stopped_at=datetime(2026, 7, 10, 9, 0),
                    ),
                    TimeEntry(
                        user=admin,
                        task=task,
                        started_at=datetime(2026, 7, 11, 8, 0),
                        stopped_at=datetime(2026, 7, 11, 9, 0),
                        billing_status="invoiced",
                        invoice_number="INV-100",
                        invoice_date=date(2026, 7, 11),
                    ),
                    TimeEntry(
                        user=admin,
                        task=task,
                        started_at=datetime(2026, 7, 12, 8, 0),
                        stopped_at=datetime(2026, 7, 12, 9, 0),
                        billing_status="client_paid",
                        invoice_number="INV-101",
                        invoice_date=date(2026, 7, 12),
                        client_paid_date=date(2026, 7, 13),
                    ),
                    TimeEntry(
                        user=admin,
                        task=task,
                        started_at=datetime(2026, 7, 13, 8, 0),
                        billing_status="disbursed",
                        invoice_number="INV-102",
                        invoice_date=date(2026, 7, 13),
                        client_paid_date=date(2026, 7, 14),
                        disbursement_date=date(2026, 7, 15),
                        transaction_number="TX-102",
                    ),
                ]
            )
        page = self.client.get("/sessions")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"My Sessions", page.data)
        self.assertIn(b"responsive-table my-session-table", page.data)
        self.assertIn(b'data-label="Invoice"', page.data)
        self.assertIn(b"Pending Invoice", page.data)
        self.assertIn(b"Invoiced", page.data)
        self.assertIn(b"Client Paid", page.data)
        self.assertIn(b"Disbursed", page.data)
        for query in ("page=invalid", "finalized_page=invalid", "page=0"):
            with self.subTest(query=query):
                self.assertEqual(self.client.get(f"/sessions?{query}").status_code, 400)
        redirected = self.client.get("/sessions?page=99&finalized_page=99")
        self.assertEqual(redirected.status_code, 302)
        self.assertIn("/sessions?page=1", redirected.location)

    def test_session_assignment_apis_reject_missing_or_archived_resources(self) -> None:
        self.login()
        contracts = self.client.get(f"/api/clients/{self.seed.client_id}/contracts")
        self.assertEqual(contracts.status_code, 200)
        self.assertEqual(contracts.json[0]["id"], self.seed.contract_id)
        assignments = self.client.get(
            f"/api/contracts/{self.seed.contract_id}/assignments"
        )
        self.assertEqual(assignments.status_code, 200)
        self.assertEqual(assignments.json[0]["name"], "Discovery")
        self.assertEqual(
            self.client.get("/api/contracts/9999/assignments").status_code, 404
        )
        with session_scope(self.app) as database:
            contract = database.get(Contract, self.seed.contract_id)
            assert contract is not None
            contract.archived_at = datetime.now()
        self.assertEqual(
            self.client.get(
                f"/api/contracts/{self.seed.contract_id}/assignments"
            ).status_code,
            409,
        )

    def test_shared_report_cookie_rejects_tampering_and_version_changes(self) -> None:
        seed = self.seed
        with session_scope(self.app) as database:
            client = database.get(Client, seed.client_id)
            assert client is not None
        with self.app.test_request_context("/"):
            response = self.app.response_class()
            routes.set_shared_report_cookie(response, client)
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        with self.app.test_request_context("/", headers={"Cookie": cookie}):
            self.assertTrue(routes.shared_report_cookie_allowed(client))
        with self.app.test_request_context(
            "/", headers={"Cookie": f"{cookie}tampered"}
        ):
            self.assertFalse(routes.shared_report_cookie_allowed(client))
        client.report_password_version += 1
        with self.app.test_request_context("/", headers={"Cookie": cookie}):
            self.assertFalse(routes.shared_report_cookie_allowed(client))

    def test_archiving_contract_stops_timers_and_disables_operations(self) -> None:
        self.login()
        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            task = database.get(Task, self.seed.other_task_id)
            assert admin is not None and task is not None
            active = TimeEntry(user=admin, task=task, started_at=datetime.now())
            database.add(active)
            database.flush()
            active_id = active.id
            reset_totp_replay_state(database, admin.id)

        archive_url = f"/contracts/{self.seed.contract_id}/archive"
        active_contract_page = self.client.get(f"/contracts/{self.seed.contract_id}")
        self.assertIn(b'class="icon-button timer-action"', active_contract_page.data)
        self.assertIn(b'class="timer-stop-form"', active_contract_page.data)
        self.assertEqual(self.client.get(archive_url).status_code, 200)
        routes.sensitive_action_limiter = LoginLimiter(limit=1)
        rejected = self.client.post(
            archive_url,
            data={"current_password": "wrong-password", "totp": "000000"},
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(
            self.client.post(
                archive_url,
                data={"current_password": "wrong-password", "totp": "000000"},
            ).status_code,
            429,
        )
        routes.sensitive_action_limiter = LoginLimiter()
        archived = self.client.post(
            archive_url,
            data={
                "current_password": ADMIN_PASSWORD,
                "totp_digit": list(pyotp.TOTP(ADMIN_TOTP_SECRET).now()),
            },
        )
        self.assertEqual(archived.status_code, 302)
        with session_scope(self.app) as database:
            contract = database.get(Contract, self.seed.contract_id)
            active = database.get(TimeEntry, active_id)
            assert contract is not None and active is not None
            self.assertIsNotNone(contract.archived_at)
            self.assertIsNotNone(active.stopped_at)

        contract_page = self.client.get(f"/contracts/{self.seed.contract_id}")
        self.assertEqual(contract_page.status_code, 200)
        self.assertIn(b"This contract is archived", contract_page.data)
        self.assertNotIn(b'title="New Task"', contract_page.data)
        sessions_page = self.client.get(f"/contracts/{self.seed.contract_id}/sessions")
        self.assertIn(b"All session controls are disabled", sessions_page.data)
        self.assertIn(b"responsive-table session-table", sessions_page.data)
        self.assertIn(b'data-label="Actions"', sessions_page.data)
        archived_report = self.client.get(f"/reports/{self.seed.client_id}")
        self.assertIn(
            b"No active contracts are currently available for this client.",
            archived_report.data,
        )

        with session_scope(self.app) as database:
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert admin is not None
            reset_totp_replay_state(database, admin.id)
        activated = self.client.post(
            archive_url,
            data={
                "current_password": ADMIN_PASSWORD,
                "totp_digit": list(pyotp.TOTP(ADMIN_TOTP_SECRET).now()),
            },
        )
        self.assertEqual(activated.status_code, 302)
        with session_scope(self.app) as database:
            contract = database.get(Contract, self.seed.contract_id)
            assert contract is not None
            self.assertIsNone(contract.archived_at)

    @unittest.skip(
        "Legacy expiration and rotation assertions replaced by permanent links"
    )
    def _obsolete_legacy_report_expiration_and_rotation_test(
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
        self.assertEqual(edited.status_code, 403)
        self.assertEqual(
            user_client.post(f"/sessions/{self.seed.entry_id}/delete").status_code, 403
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
            user_client.get(f"/sessions/{active_id}/edit").status_code, 403
        )
        self.assertEqual(
            user_client.post(f"/sessions/{active_id}/delete").status_code, 403
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
            302,
        )
        self.assertEqual(
            user_client.get("/contracts/9999/sessions").status_code,
            302,
        )
        invalid_cases = [
            {
                "assignment": "9999",
                "started_at": "2026-07-14T10:00:00",
                "stopped_at": "2026-07-14T10:30:00",
                "correction_reason": "Invalid assignment test",
            },
            {
                "assignment": f"{self.seed.other_task_id}:{self.seed.subtask_id}",
                "started_at": "2026-07-14T10:00:00",
                "stopped_at": "2026-07-14T10:30:00",
                "correction_reason": "Invalid assignment test",
            },
            {
                "assignment": str(self.seed.other_task_id),
                "started_at": "2026-07-14T10:30:00",
                "stopped_at": "2026-07-14T10:00:00",
                "correction_reason": "Invalid time test",
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
                "correction_reason": "Record test session",
            },
        )
        self.assertEqual(created.status_code, 302)
        with patch(
            "sqlalchemy.orm.Session.commit",
            side_effect=IntegrityError("overlap", {}, Exception("overlap")),
        ):
            raced = user_client.post(
                f"/contracts/{self.seed.contract_id}/sessions/new",
                data={
                    "user_id": "1",
                    "assignment": str(self.seed.other_task_id),
                    "started_at": "2026-07-16T10:00:00",
                    "stopped_at": "2026-07-16T10:30:00",
                    "correction_reason": "Race test",
                },
            )
        self.assertEqual(raced.status_code, 409)
        overlap = user_client.post(
            f"/contracts/{self.seed.contract_id}/sessions/new",
            data={
                "assignment": str(self.seed.other_task_id),
                "started_at": "2026-07-15T10:15:00",
                "stopped_at": "2026-07-15T10:45:00",
                "correction_reason": "Overlap test",
            },
        )
        self.assertEqual(overlap.status_code, 400)
        future = user_client.post(
            f"/contracts/{self.seed.contract_id}/sessions/new",
            data={
                "assignment": str(self.seed.other_task_id),
                "started_at": "2099-01-01T10:00:00",
                "stopped_at": "2099-01-01T10:30:00",
                "correction_reason": "Future test",
            },
        )
        self.assertEqual(future.status_code, 400)

        self.login()
        self.assertEqual(
            self.client.get(
                f"/contracts/{self.seed.contract_id}/sessions?page=invalid"
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.get(
                f"/contracts/{self.seed.contract_id}/sessions?page=0"
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.get(
                f"/contracts/{self.seed.contract_id}/sessions?page=99"
            ).status_code,
            302,
        )
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
                            "correction_reason": "Invalid user test",
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
                "correction_reason": "Record admin test session",
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
        edit_redirect = self.client.get(f"/sessions/{self.seed.entry_id}/edit")
        self.assertEqual(edit_redirect.status_code, 302)
        self.assertEqual(
            self.client.get(edit_redirect.location).status_code,
            200,
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
                "correction_reason": "Invalid assignment test",
            },
            {
                "assignment": str(self.seed.task_id),
                "started_at": "invalid",
                "stopped_at": "2026-07-15T09:00:00",
                "correction_reason": "Invalid time test",
            },
            {
                "assignment": str(self.seed.task_id),
                "started_at": "2026-07-15T10:00:00",
                "stopped_at": "2026-07-15T09:00:00",
                "correction_reason": "Invalid time test",
            },
            {
                "assignment": str(self.seed.task_id),
                "started_at": "2026-03-08T02:30:00",
                "stopped_at": "2026-03-08T03:30:00",
                "correction_reason": "DST edge test",
            },
            {
                "assignment": str(self.seed.task_id),
                "started_at": "2099-01-01T10:00:00",
                "stopped_at": "2099-01-01T10:30:00",
                "correction_reason": "Future time test",
            },
            {
                "assignment": str(self.seed.task_id),
                "started_at": "2026-07-15T09:15:00",
                "stopped_at": "2026-07-15T09:45:00",
                "correction_reason": "Overlap test",
            },
        ]
        for data in cases:
            with self.subTest(data=data):
                self.assertEqual(
                    self.client.post(
                        f"/sessions/{self.seed.entry_id}/edit", data=data
                    ).status_code,
                    400,
                )
        valid_ids = {
            "user_id": "1",
            "client_id": str(self.seed.client_id),
            "contract_id": str(self.seed.contract_id),
            "assignment": str(self.seed.task_id),
            "correction_reason": "Reach session time validation",
        }
        with session_scope(self.app) as database:
            task = database.get(Task, self.seed.other_task_id)
            admin = database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            assert task is not None and admin is not None
            database.add(
                TimeEntry(
                    user_id=admin.id,
                    task_id=task.id,
                    started_at=datetime(2026, 7, 15, 14, 0, 0),
                    stopped_at=datetime(2026, 7, 15, 15, 0, 0),
                )
            )
        for times in (
            {"started_at": "2026-07-15T10:00:00", "stopped_at": "2026-07-15T09:00:00"},
            {"started_at": "2099-01-01T10:00:00", "stopped_at": "2099-01-01T10:30:00"},
            {"started_at": "2026-07-15T09:15:00", "stopped_at": "2026-07-15T09:45:00"},
        ):
            with self.subTest(times=times):
                self.assertEqual(
                    self.client.post(
                        f"/sessions/{self.seed.entry_id}/edit",
                        data={**valid_ids, **times},
                    ).status_code,
                    400,
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
