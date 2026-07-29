"""Deterministic passkey route, state, fallback, and audit coverage."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from flask import session
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse
from webauthn.helpers.structs import CredentialDeviceType

from grayhaven_timetracker import routes
from grayhaven_timetracker.database import session_scope
from grayhaven_timetracker.models import (
    AuditEvent,
    PasskeyCredential,
    PasskeyIdentity,
    User,
    WebAuthnChallenge,
)
from grayhaven_timetracker.passkeys import (
    PasskeyError,
    _action_context_hash,
    consume_challenge,
    credential_id_from_payload,
    verify_authentication,
    verify_registration,
)
from tests.helpers import ADMIN_EMAIL, ADMIN_PASSWORD, AppTestCase


class PasskeyRouteTests(AppTestCase):
    credential_id = b"deterministic-credential-id"
    user_handle = b"deterministic-random-user-handle"

    def seed_passkey(self, user_id: int | None = None, *, name: str = "Laptop") -> int:
        with session_scope(self.app) as database:
            user = (
                database.get(User, user_id)
                if user_id is not None
                else database.scalar(select(User).where(User.email == ADMIN_EMAIL))
            )
            assert user is not None
            identity = database.get(PasskeyIdentity, user.id)
            if identity is None:
                identity = PasskeyIdentity(
                    user_id=user.id,
                    user_handle=self.user_handle + str(user.id).encode(),
                    created_at=routes.now_utc(),
                )
                database.add(identity)
            credential = PasskeyCredential(
                user_id=user.id,
                credential_id=self.credential_id
                + str(user.id).encode()
                + name.encode(),
                public_key=b"public-key-data",
                sign_count=1,
                device_type="single_device",
                backed_up=False,
                aaguid="00000000-0000-0000-0000-000000000000",
                name=name,
                rp_id="localhost",
                created_at=routes.now_utc(),
                last_used_at=None,
            )
            database.add(credential)
            database.flush()
            return credential.id

    def assertion_payload(
        self, credential_id: bytes, user_handle: bytes | None
    ) -> dict[str, object]:
        return {
            "id": bytes_to_base64url(credential_id),
            "rawId": bytes_to_base64url(credential_id),
            "type": "public-key",
            "response": {
                "authenticatorData": "AA",
                "clientDataJSON": "AA",
                "signature": "AA",
                "userHandle": (
                    bytes_to_base64url(user_handle) if user_handle is not None else None
                ),
            },
        }

    @staticmethod
    def verified_authentication() -> SimpleNamespace:
        return SimpleNamespace(
            new_sign_count=2,
            credential_device_type=CredentialDeviceType.MULTI_DEVICE,
            credential_backed_up=True,
        )

    def test_passkey_login_succeeds_without_password_or_totp_and_replay_fails(
        self,
    ) -> None:
        credential_id = self.seed_passkey()
        with session_scope(self.app) as database:
            credential = database.get(PasskeyCredential, credential_id)
            assert credential is not None
            identity = database.get(PasskeyIdentity, credential.user_id)
            assert identity is not None
            payload = self.assertion_payload(
                credential.credential_id, identity.user_handle
            )

        options = self.client.post("/login/passkey/options?next=/profile").get_json()
        envelope = {"challengeId": options["challengeId"], "credential": payload}
        with patch(
            "grayhaven_timetracker.routes.verify_authentication",
            return_value=self.verified_authentication(),
        ) as verify:
            response = self.client.post("/login/passkey/verify", json=envelope)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["redirect"], "/profile")
        self.assertIsInstance(verify.call_args.kwargs["expected_challenge"], bytes)
        self.assertTrue(verify.call_args.kwargs["require_user_handle"])
        with self.client.session_transaction() as browser_session:
            self.assertIn("user_id", browser_session)
        self.assertEqual(
            self.client.post("/login/passkey/verify", json=envelope).status_code, 401
        )
        with session_scope(self.app) as database:
            credential = database.get(PasskeyCredential, credential_id)
            assert credential is not None
            self.assertEqual(credential.sign_count, 2)
            self.assertTrue(credential.backed_up)
            events = database.scalars(
                select(AuditEvent).where(
                    AuditEvent.event.in_(
                        {
                            "passkey_authentication_succeeded",
                            "passkey_authentication_rejected",
                        }
                    )
                )
            ).all()
            self.assertEqual(len(events), 2)
            serialized = " ".join(event.details_json for event in events)
            self.assertNotIn(bytes_to_base64url(credential.credential_id), serialized)
            self.assertNotIn("public-key-data", serialized)
            login_event = database.scalar(
                select(AuditEvent)
                .where(AuditEvent.event == "login_succeeded")
                .order_by(AuditEvent.id.desc())
            )
            assert login_event is not None
            self.assertEqual(login_event.details["factor"], "passkey")
        audit_page = self.client.get("/audit")
        self.assertEqual(audit_page.status_code, 200)
        self.assertIn(b"<dt>factor</dt><dd>passkey</dd>", audit_page.data)

    def test_login_options_redirect_authenticated_users_and_honor_ip_limit(
        self,
    ) -> None:
        self.login()
        authenticated = self.client.post("/login/passkey/options")
        self.assertEqual(authenticated.status_code, 200)
        self.assertEqual(authenticated.get_json()["redirect"], "/")
        self.client.post("/logout")

        routes.login_ip_limiter = routes.LoginLimiter(limit=1)
        routes.login_ip_limiter.record_failure("127.0.0.1")
        for path in ("/login/passkey/options", "/login/passkey/verify"):
            with self.subTest(path=path):
                response = self.client.post(path, json={})
                self.assertEqual(response.status_code, 429)
        with session_scope(self.app) as database:
            events = database.scalars(
                select(AuditEvent).where(AuditEvent.event == "login_rate_limited")
            ).all()
            self.assertEqual(len(events), 2)
            self.assertTrue(
                all('"stage":"passkey"' in event.details_json for event in events)
            )

    def test_login_rejects_expired_wrong_origin_and_disabled_account(self) -> None:
        credential_id = self.seed_passkey()
        with session_scope(self.app) as database:
            credential = database.get(PasskeyCredential, credential_id)
            assert credential is not None
            identity = database.get(PasskeyIdentity, credential.user_id)
            assert identity is not None
            payload = self.assertion_payload(
                credential.credential_id, identity.user_handle
            )

        expired = self.client.post("/login/passkey/options").get_json()
        with session_scope(self.app) as database:
            challenge = database.get(WebAuthnChallenge, expired["challengeId"])
            assert challenge is not None
            challenge.expires_at = routes.now_utc() - timedelta(seconds=1)
        self.assertEqual(
            self.client.post(
                "/login/passkey/verify",
                json={"challengeId": expired["challengeId"], "credential": payload},
            ).status_code,
            401,
        )
        with session_scope(self.app) as database:
            self.assertIsNone(database.get(WebAuthnChallenge, expired["challengeId"]))

        wrong_origin = self.client.post("/login/passkey/options").get_json()
        with patch(
            "grayhaven_timetracker.routes.verify_authentication",
            side_effect=InvalidAuthenticationResponse("Unexpected origin"),
        ):
            self.assertEqual(
                self.client.post(
                    "/login/passkey/verify",
                    json={
                        "challengeId": wrong_origin["challengeId"],
                        "credential": payload,
                    },
                ).status_code,
                401,
            )

        disabled_user = self.create_user(
            email="disabled@example.invalid", enabled=False, totp_secret=""
        )
        disabled_credential_id = self.seed_passkey(disabled_user.id)
        with session_scope(self.app) as database:
            disabled_credential = database.get(
                PasskeyCredential, disabled_credential_id
            )
            assert disabled_credential is not None
            disabled_identity = database.get(PasskeyIdentity, disabled_user.id)
            assert disabled_identity is not None
            disabled_payload = self.assertion_payload(
                disabled_credential.credential_id, disabled_identity.user_handle
            )
        disabled = self.client.post("/login/passkey/options").get_json()
        with patch("grayhaven_timetracker.routes.verify_authentication") as verify:
            self.assertEqual(
                self.client.post(
                    "/login/passkey/verify",
                    json={
                        "challengeId": disabled["challengeId"],
                        "credential": disabled_payload,
                    },
                ).status_code,
                401,
            )
            verify.assert_not_called()

    def test_discoverable_login_rejects_missing_user_handle(self) -> None:
        credential_id = self.seed_passkey()
        with session_scope(self.app) as database:
            credential = database.get(PasskeyCredential, credential_id)
            assert credential is not None
            payload = self.assertion_payload(credential.credential_id, None)
        options = self.client.post("/login/passkey/options").get_json()
        with patch(
            "grayhaven_timetracker.passkeys.verify_authentication_response",
            return_value=self.verified_authentication(),
        ) as verifier:
            response = self.client.post(
                "/login/passkey/verify",
                json={
                    "challengeId": options["challengeId"],
                    "credential": payload,
                },
            )
        self.assertEqual(response.status_code, 401)
        verifier.assert_not_called()

    def test_challenge_is_bound_to_browser_session(self) -> None:
        credential_id = self.seed_passkey()
        with session_scope(self.app) as database:
            credential = database.get(PasskeyCredential, credential_id)
            assert credential is not None
            identity = database.get(PasskeyIdentity, credential.user_id)
            assert identity is not None
            payload = self.assertion_payload(
                credential.credential_id, identity.user_handle
            )
        options = self.client.post("/login/passkey/options").get_json()
        with self.client.session_transaction() as browser_session:
            browser_session["webauthn_session_binding"] = "x" * 48
        self.assertEqual(
            self.client.post(
                "/login/passkey/verify",
                json={"challengeId": options["challengeId"], "credential": payload},
            ).status_code,
            401,
        )

    def test_sensitive_action_passkey_grants_only_pending_path(self) -> None:
        credential_id = self.seed_passkey()
        self.login()
        with self.client.session_transaction() as browser_session:
            user_id = browser_session["user_id"]
            browser_session.update(
                {
                    "pending_sensitive_action_user_id": user_id,
                    "pending_sensitive_action_session_version": 1,
                    "pending_sensitive_action_expires_at": time.time() + 300,
                    "pending_sensitive_action_path": "/profile/password/change",
                    "pending_sensitive_action_cancel_url": "/profile",
                }
            )
        with session_scope(self.app) as database:
            credential = database.get(PasskeyCredential, credential_id)
            assert credential is not None
            identity = database.get(PasskeyIdentity, credential.user_id)
            assert identity is not None
            payload = self.assertion_payload(credential.credential_id, None)
        options = self.client.post("/reauthenticate/passkey/options").get_json()
        with patch(
            "grayhaven_timetracker.passkeys.verify_authentication_response",
            return_value=self.verified_authentication(),
        ) as verify:
            response = self.client.post(
                "/reauthenticate/passkey/verify",
                json={"challengeId": options["challengeId"], "credential": payload},
            )
        self.assertEqual(response.get_json()["redirect"], "/profile/password/change")
        self.assertTrue(verify.called)
        with self.client.session_transaction() as browser_session:
            self.assertEqual(
                browser_session["sensitive_action_authorized_path"],
                "/profile/password/change",
            )
        with session_scope(self.app) as database:
            event = database.scalar(
                select(AuditEvent)
                .where(
                    AuditEvent.event == "sensitive_action_reauthentication_succeeded"
                )
                .order_by(AuditEvent.id.desc())
            )
            assert event is not None
            self.assertEqual(event.details["factor"], "passkey")
        audit_page = self.client.get("/audit")
        self.assertEqual(audit_page.status_code, 200)
        self.assertIn(b"<dt>factor</dt><dd>passkey</dd>", audit_page.data)

    def test_sensitive_action_challenge_cannot_authorize_replacement_path(
        self,
    ) -> None:
        credential_id = self.seed_passkey()
        self.login()
        with self.client.session_transaction() as browser_session:
            user_id = browser_session["user_id"]
            browser_session.update(
                {
                    "pending_sensitive_action_user_id": user_id,
                    "pending_sensitive_action_session_version": 1,
                    "pending_sensitive_action_expires_at": time.time() + 300,
                    "pending_sensitive_action_path": "/profile/password/change",
                    "pending_sensitive_action_cancel_url": "/profile",
                }
            )
        with session_scope(self.app) as database:
            credential = database.get(PasskeyCredential, credential_id)
            assert credential is not None
            payload = self.assertion_payload(credential.credential_id, None)
        old_options = self.client.post("/reauthenticate/passkey/options").get_json()
        with self.client.session_transaction() as browser_session:
            browser_session["pending_sensitive_action_path"] = "/profile/passkeys"
        with patch("grayhaven_timetracker.routes.verify_authentication") as verify:
            rejected = self.client.post(
                "/reauthenticate/passkey/verify",
                json={
                    "challengeId": old_options["challengeId"],
                    "credential": payload,
                },
            )
        self.assertEqual(rejected.status_code, 401)
        verify.assert_not_called()
        with self.client.session_transaction() as browser_session:
            self.assertNotIn("sensitive_action_authorized_path", browser_session)

        replacement = self.client.post("/reauthenticate/passkey/options").get_json()
        with patch(
            "grayhaven_timetracker.routes.verify_authentication",
            return_value=self.verified_authentication(),
        ):
            accepted = self.client.post(
                "/reauthenticate/passkey/verify",
                json={
                    "challengeId": replacement["challengeId"],
                    "credential": payload,
                },
            )
        self.assertEqual(accepted.get_json()["redirect"], "/profile/passkeys")

    def test_options_replace_stale_state_and_limit_public_issuance(self) -> None:
        first = self.client.post("/login/passkey/options").get_json()
        second = self.client.post("/login/passkey/options").get_json()
        with session_scope(self.app) as database:
            self.assertIsNone(database.get(WebAuthnChallenge, first["challengeId"]))
            self.assertIsNotNone(database.get(WebAuthnChallenge, second["challengeId"]))
            self.assertEqual(len(database.scalars(select(WebAuthnChallenge)).all()), 1)
        routes.passkey_options_limiter = routes.LoginLimiter(limit=1, window_seconds=60)
        third = self.client.post(
            "/login/passkey/options",
            environ_overrides={"REMOTE_ADDR": "192.0.2.8"},
        )
        limited = self.client.post(
            "/login/passkey/options",
            environ_overrides={"REMOTE_ADDR": "192.0.2.8"},
        )
        self.assertEqual(third.status_code, 200)
        self.assertEqual(limited.status_code, 429)

    def test_challenge_rejects_wrong_ceremony_and_user_and_is_consumed(
        self,
    ) -> None:
        self.login()
        with self.client.session_transaction() as browser_session:
            user_id = browser_session["user_id"]
            browser_session.update(
                {
                    "sensitive_action_authorized_path": "/profile/passkeys",
                    "sensitive_action_authorized_session_version": 1,
                    "sensitive_action_authorized_until": time.time() + 300,
                }
            )
        first = self.client.post("/profile/passkeys/options").get_json()
        with self.client.session_transaction() as browser_session:
            binding = browser_session["webauthn_session_binding"]
        with self.app.test_request_context("/"):
            session["webauthn_session_binding"] = binding
            with session_scope(self.app) as database, self.assertRaises(PasskeyError):
                consume_challenge(
                    database,
                    first["challengeId"],
                    ceremony="authentication",
                    user_id=user_id,
                )
        with session_scope(self.app) as database:
            self.assertIsNone(database.get(WebAuthnChallenge, first["challengeId"]))

        second = self.client.post("/profile/passkeys/options").get_json()
        with self.app.test_request_context("/"):
            session["webauthn_session_binding"] = binding
            with session_scope(self.app) as database, self.assertRaises(PasskeyError):
                consume_challenge(
                    database,
                    second["challengeId"],
                    ceremony="registration",
                    user_id=user_id + 1,
                )
        with session_scope(self.app) as database:
            self.assertIsNone(database.get(WebAuthnChallenge, second["challengeId"]))

    def test_missing_unknown_and_wrong_account_credentials_are_rejected(
        self,
    ) -> None:
        malformed = self.client.post(
            "/login/passkey/verify",
            data="not-json",
            content_type="application/json",
        )
        self.assertEqual(malformed.status_code, 401)
        self.assertEqual(
            self.client.post("/login/passkey/verify", json={}).status_code,
            401,
        )
        unknown_options = self.client.post("/login/passkey/options").get_json()
        unknown = self.client.post(
            "/login/passkey/verify",
            json={
                "challengeId": unknown_options["challengeId"],
                "credential": self.assertion_payload(b"unknown", b"handle"),
            },
        )
        self.assertEqual(unknown.status_code, 401)

        self.seed_passkey()
        other = self.create_user(totp_secret="")
        other_passkey_id = self.seed_passkey(other.id)
        self.login()
        with self.client.session_transaction() as browser_session:
            user_id = browser_session["user_id"]
            browser_session.update(
                {
                    "pending_sensitive_action_user_id": user_id,
                    "pending_sensitive_action_session_version": 1,
                    "pending_sensitive_action_expires_at": time.time() + 300,
                    "pending_sensitive_action_path": "/profile/passkeys",
                    "pending_sensitive_action_cancel_url": "/profile",
                }
            )
        with session_scope(self.app) as database:
            other_passkey = database.get(PasskeyCredential, other_passkey_id)
            assert other_passkey is not None
            wrong_account_payload = self.assertion_payload(
                other_passkey.credential_id, None
            )
        options = self.client.post("/reauthenticate/passkey/options").get_json()
        rejected = self.client.post(
            "/reauthenticate/passkey/verify",
            json={
                "challengeId": options["challengeId"],
                "credential": wrong_account_payload,
            },
        )
        self.assertEqual(rejected.status_code, 401)

    def test_no_passkeys_and_passkey_failures_use_existing_limits(self) -> None:
        self.login()
        with self.client.session_transaction() as browser_session:
            user_id = browser_session["user_id"]
            browser_session.update(
                {
                    "pending_sensitive_action_user_id": user_id,
                    "pending_sensitive_action_session_version": 1,
                    "pending_sensitive_action_expires_at": time.time() + 300,
                    "pending_sensitive_action_path": "/profile/passkeys",
                    "pending_sensitive_action_cancel_url": "/profile",
                }
            )
        self.assertEqual(
            self.client.post("/reauthenticate/passkey/options").status_code,
            409,
        )
        routes.sensitive_action_limiter = routes.LoginLimiter(limit=1)
        rejected = self.client.post(
            "/reauthenticate/passkey/verify",
            json={"challengeId": "x" * 32, "credential": {}},
        )
        self.assertEqual(rejected.status_code, 401)
        self.assertEqual(
            self.client.post("/reauthenticate/passkey/options").status_code,
            429,
        )

    def test_sensitive_options_and_verification_reject_missing_pending_action(
        self,
    ) -> None:
        self.login()
        for path in (
            "/reauthenticate/passkey/options",
            "/reauthenticate/passkey/verify",
        ):
            with self.subTest(path=path):
                response = self.client.post(path, json={})
                self.assertEqual(response.status_code, 400)
                self.assertIn("expired", response.get_json()["error"])

    def test_management_and_registration_require_scoped_authorization(self) -> None:
        passkey_id = self.seed_passkey()
        with session_scope(self.app) as database:
            credential = database.get(PasskeyCredential, passkey_id)
            assert credential is not None
            credential.created_at = datetime(2026, 1, 15, 18, 30)
            credential.last_used_at = datetime(2026, 7, 29, 18, 30)
        self.login()
        management = self.client.get("/profile/passkeys")
        self.assertEqual(management.status_code, 302)
        self.assertIn("/reauthenticate?", management.location)
        for path in ("/profile/passkeys/options", "/profile/passkeys/verify"):
            with self.subTest(path=path):
                self.assertEqual(self.client.post(path, json={}).status_code, 403)

        self.authorize_sensitive_action("/profile/passkeys")
        rendered = self.client.get("/profile/passkeys")
        self.assertEqual(rendered.status_code, 200)
        self.assertIn(b"Laptop", rendered.data)
        self.assertIn(b"Added 2026-01-15 12:30:00 PM CST", rendered.data)
        self.assertIn(b"last used 2026-07-29 01:30:00 PM CDT", rendered.data)
        self.assertIn(b"Add Passkey", rendered.data)
        self.assertIn(b"Cancel Passkey", rendered.data)

        remove_path = f"/profile/passkeys/{passkey_id}/remove"
        redirect = self.client.get(remove_path)
        self.assertEqual(redirect.status_code, 302)
        self.assertIn("/reauthenticate?", redirect.location)
        self.authorize_sensitive_action(remove_path)
        confirmation = self.client.get(remove_path)
        self.assertEqual(confirmation.status_code, 200)
        self.assertIn(b"Remove Passkey", confirmation.data)

    def test_registration_rejects_non_string_name_and_commit_race(self) -> None:
        self.login()
        self.authorize_sensitive_action("/profile/passkeys")
        options = self.client.post("/profile/passkeys/options").get_json()
        non_string = self.client.post(
            "/profile/passkeys/verify",
            json={
                "challengeId": options["challengeId"],
                "credential": {"id": "AA", "rawId": "AA"},
                "name": 42,
            },
        )
        self.assertEqual(non_string.status_code, 400)
        self.assertEqual(
            non_string.get_json()["error"], "Enter a name for this passkey."
        )

        options = self.client.post("/profile/passkeys/options").get_json()
        verified = SimpleNamespace(
            credential_id=b"raced-registration-credential",
            credential_public_key=b"public-key",
            sign_count=0,
            credential_device_type=CredentialDeviceType.SINGLE_DEVICE,
            credential_backed_up=False,
            aaguid="00000000-0000-0000-0000-000000000000",
        )
        with (
            patch(
                "grayhaven_timetracker.routes.verify_registration",
                return_value=verified,
            ),
            patch(
                "sqlalchemy.orm.Session.commit",
                side_effect=(
                    None,
                    IntegrityError("duplicate", {}, Exception("duplicate")),
                ),
            ),
            patch("sqlalchemy.orm.Session.rollback") as rollback,
            patch("grayhaven_timetracker.routes.audit") as audit,
        ):
            raced = self.client.post(
                "/profile/passkeys/verify",
                json={
                    "challengeId": options["challengeId"],
                    "credential": {"id": "AA", "rawId": "AA"},
                    "name": "Raced key",
                },
            )
        self.assertEqual(raced.status_code, 409)
        self.assertEqual(
            raced.get_json()["error"], "That passkey is already registered."
        )
        rollback.assert_called_once_with()
        audit.assert_called_once_with(
            "passkey_enrollment_rejected",
            user_id=1,
            source_ip="127.0.0.1",
            reason="duplicate",
        )

    def test_registration_multiple_management_and_safe_audit(self) -> None:
        self.login()
        with self.client.session_transaction() as browser_session:
            user_id = browser_session["user_id"]
            browser_session.update(
                {
                    "sensitive_action_authorized_path": "/profile/passkeys",
                    "sensitive_action_authorized_session_version": 1,
                    "sensitive_action_authorized_until": time.time() + 300,
                }
            )
        options = self.client.post("/profile/passkeys/options").get_json()
        verified = SimpleNamespace(
            credential_id=b"new-registration-credential",
            credential_public_key=b"new-public-key",
            sign_count=0,
            credential_device_type=CredentialDeviceType.SINGLE_DEVICE,
            credential_backed_up=False,
            aaguid="00000000-0000-0000-0000-000000000000",
        )
        with patch(
            "grayhaven_timetracker.routes.verify_registration", return_value=verified
        ):
            response = self.client.post(
                "/profile/passkeys/verify",
                json={
                    "challengeId": options["challengeId"],
                    "credential": {"id": "AA", "rawId": "AA"},
                    "name": "Security key",
                },
            )
        self.assertEqual(response.get_json()["redirect"], "/profile")
        self.seed_passkey(user_id, name="Phone")
        with session_scope(self.app) as database:
            credentials = database.scalars(
                select(PasskeyCredential).where(PasskeyCredential.user_id == user_id)
            ).all()
            self.assertEqual(
                {item.name for item in credentials}, {"Security key", "Phone"}
            )
            enrollment = database.scalar(
                select(AuditEvent).where(AuditEvent.event == "passkey_enrolled")
            )
            assert enrollment is not None
            self.assertNotIn("new-registration-credential", enrollment.details_json)
            self.assertNotIn("new-public-key", enrollment.details_json)

    def test_registration_rejects_invalid_duplicate_and_failed_verification(
        self,
    ) -> None:
        existing_id = self.seed_passkey()
        self.login()
        with self.client.session_transaction() as browser_session:
            browser_session.update(
                {
                    "sensitive_action_authorized_path": "/profile/passkeys",
                    "sensitive_action_authorized_session_version": 1,
                    "sensitive_action_authorized_until": time.time() + 300,
                }
            )
        invalid_options = self.client.post("/profile/passkeys/options").get_json()
        invalid = self.client.post(
            "/profile/passkeys/verify",
            json={
                "challengeId": invalid_options["challengeId"],
                "credential": {"id": "AA", "rawId": "AA"},
                "name": "   ",
            },
        )
        self.assertEqual(invalid.status_code, 400)

        rejected_options = self.client.post("/profile/passkeys/options").get_json()
        with patch(
            "grayhaven_timetracker.routes.verify_registration",
            side_effect=InvalidAuthenticationResponse("bad registration"),
        ):
            rejected = self.client.post(
                "/profile/passkeys/verify",
                json={
                    "challengeId": rejected_options["challengeId"],
                    "credential": {"id": "AA", "rawId": "AA"},
                    "name": "Security key",
                },
            )
        self.assertEqual(rejected.status_code, 400)

        with session_scope(self.app) as database:
            existing = database.get(PasskeyCredential, existing_id)
            assert existing is not None
            duplicate_id = existing.credential_id
        duplicate_options = self.client.post("/profile/passkeys/options").get_json()
        duplicate_verification = SimpleNamespace(
            credential_id=duplicate_id,
            credential_public_key=b"duplicate-public-key",
            sign_count=0,
            credential_device_type=CredentialDeviceType.SINGLE_DEVICE,
            credential_backed_up=False,
            aaguid="00000000-0000-0000-0000-000000000000",
        )
        with patch(
            "grayhaven_timetracker.routes.verify_registration",
            return_value=duplicate_verification,
        ):
            duplicate = self.client.post(
                "/profile/passkeys/verify",
                json={
                    "challengeId": duplicate_options["challengeId"],
                    "credential": {"id": "AA", "rawId": "AA"},
                    "name": "Duplicate",
                },
            )
        self.assertEqual(duplicate.status_code, 400)
        with session_scope(self.app) as database:
            rejected_events = database.scalars(
                select(AuditEvent).where(
                    AuditEvent.event == "passkey_enrollment_rejected"
                )
            ).all()
            self.assertEqual(len(rejected_events), 3)
            serialized = " ".join(event.details_json for event in rejected_events)
            self.assertNotIn(bytes_to_base64url(duplicate_id), serialized)
            self.assertNotIn("duplicate-public-key", serialized)

    def test_user_can_remove_only_owned_passkey_after_reauthentication(self) -> None:
        passkey_id = self.seed_passkey()
        other = self.create_user(totp_secret="")
        other_passkey_id = self.seed_passkey(other.id)
        self.login()
        self.assertEqual(
            self.client.get(f"/profile/passkeys/{other_passkey_id}/remove").status_code,
            404,
        )
        path = f"/profile/passkeys/{passkey_id}/remove"
        with self.client.session_transaction() as browser_session:
            browser_session.update(
                {
                    "sensitive_action_authorized_path": path,
                    "sensitive_action_authorized_session_version": 1,
                    "sensitive_action_authorized_until": time.time() + 300,
                }
            )
        response = self.client.post(path)
        self.assertEqual(response.location, "/profile")
        with session_scope(self.app) as database:
            self.assertIsNone(database.get(PasskeyCredential, passkey_id))
            event = database.scalar(
                select(AuditEvent).where(AuditEvent.event == "passkey_removed")
            )
            self.assertIsNotNone(event)

    def test_admin_wipe_all_invalidates_target_sessions_without_details(self) -> None:
        target = self.create_user(totp_secret="")
        self.seed_passkey(target.id, name="First")
        self.seed_passkey(target.id, name="Second")
        target_client = self.app.test_client()
        self.login(
            target_client,
            email=target.email,
            password="Standard-User-Test-Password-0001!",
            totp_secret="",
        )
        self.login()
        directory = self.client.get("/users")
        self.assertIn(b"Configured", directory.data)
        self.assertNotIn(b"First", directory.data)
        self.assertNotIn(b"Second", directory.data)
        path = f"/users/{target.id}/wipe-passkeys"
        with self.client.session_transaction() as browser_session:
            browser_session.update(
                {
                    "sensitive_action_authorized_path": path,
                    "sensitive_action_authorized_session_version": 1,
                    "sensitive_action_authorized_until": time.time() + 300,
                }
            )
        response = self.client.post(path)
        self.assertEqual(response.location, "/users")
        with session_scope(self.app) as database:
            self.assertEqual(
                database.scalars(
                    select(PasskeyCredential).where(
                        PasskeyCredential.user_id == target.id
                    )
                ).all(),
                [],
            )
            refreshed = database.get(User, target.id)
            assert refreshed is not None
            self.assertEqual(refreshed.session_version, 2)
            event = database.scalar(
                select(AuditEvent).where(AuditEvent.event == "passkeys_wiped")
            )
            assert event is not None
            details = json.loads(event.details_json)
            self.assertNotIn("passkey_count", details)
        invalidated = target_client.get("/clients/new")
        self.assertIn("auth_notice=passkeys_wiped", invalidated.location)

    def test_admin_wipe_rejects_self_and_skips_empty_accounts(self) -> None:
        self.seed_passkey()
        empty = self.create_user(totp_secret="")
        self.login()
        with self.client.session_transaction() as browser_session:
            admin_id = browser_session["user_id"]
        self.assertEqual(
            self.client.get(f"/users/{admin_id}/wipe-passkeys").status_code,
            409,
        )
        empty_response = self.client.get(f"/users/{empty.id}/wipe-passkeys")
        self.assertEqual(empty_response.status_code, 302)
        self.assertEqual(empty_response.location, "/users")

    def test_admin_wipe_requires_reauthentication_and_renders_confirmation(
        self,
    ) -> None:
        target = self.create_user(totp_secret="")
        self.seed_passkey(target.id)
        self.login()
        path = f"/users/{target.id}/wipe-passkeys"
        redirect = self.client.get(path)
        self.assertEqual(redirect.status_code, 302)
        self.assertIn("/reauthenticate?", redirect.location)
        self.authorize_sensitive_action(path)
        confirmation = self.client.get(path)
        self.assertEqual(confirmation.status_code, 200)
        self.assertIn(b"Wipe All Passkeys", confirmation.data)

    def test_password_totp_fallbacks_and_automatic_scoped_passkeys(self) -> None:
        login_page = self.client.get("/login")
        self.assertIn(b'name="password"', login_page.data)
        self.assertIn(b'autocomplete="username webauthn"', login_page.data)
        self.assertIn(b"data-conditional-passkey-login", login_page.data)
        self.assertNotIn(b"Use a Passkey", login_page.data)
        self.assertNotIn(b"Cancel Passkey", login_page.data)
        self.assertIn(
            "publickey-credentials-get=(self)",
            login_page.headers["Permissions-Policy"],
        )
        with session_scope(self.app) as database:
            self.assertEqual(database.scalars(select(WebAuthnChallenge)).all(), [])

        routes.passkey_options_limiter = routes.LoginLimiter(limit=1, window_seconds=60)
        self.assertEqual(
            self.client.post("/login/passkey/options").status_code,
            200,
        )
        self.assertEqual(
            self.client.post("/login/passkey/options").status_code,
            429,
        )
        self.assertFalse(routes.login_ip_limiter.blocked("127.0.0.1"))
        self.login()
        self.assertEqual(self.client.get("/").status_code, 200)
        with self.client.session_transaction() as browser_session:
            user_id = browser_session["user_id"]
            browser_session.update(
                {
                    "pending_sensitive_action_user_id": user_id,
                    "pending_sensitive_action_session_version": 1,
                    "pending_sensitive_action_expires_at": time.time() + 300,
                    "pending_sensitive_action_path": "/profile/password/change",
                    "pending_sensitive_action_cancel_url": "/profile",
                }
            )
        page = self.client.get(
            "/reauthenticate?next=/profile/password/change&cancel=/profile"
        )
        self.assertIn(
            b"Use your passkey or enter your password to continue.", page.data
        )
        self.assertIn(b'name="password" autocomplete="current-password"', page.data)
        self.assertNotRegex(page.data, rb'<input[^>]*name="password"[^>]*autofocus')
        self.assertIn(b'name="cancel"', page.data)
        self.assertIn(b"data-account-scoped-passkey-authentication", page.data)
        self.assertNotIn(b"Use a Passkey", page.data)
        self.assertNotIn(b"Cancel Passkey", page.data)
        password = self.client.post(
            "/reauthenticate?next=/profile/password/change&cancel=/profile",
            data={"password": ADMIN_PASSWORD},
        )
        self.assertEqual(password.location, "/reauthenticate/authenticator")
        authenticator = self.client.get(password.location)
        self.assertIn(b"data-totp-bubbles", authenticator.data)

        shared_report_login = (
            Path(__file__).resolve().parents[1]
            / "templates"
            / "shared_report_login.html"
        ).read_text(encoding="utf-8")
        self.assertIn('name="report_password"', shared_report_login)
        self.assertNotIn("webauthn", shared_report_login)
        self.assertNotIn("conditional-passkey", shared_report_login)

    def test_passkey_management_styles_cover_desktop_and_mobile_structure(
        self,
    ) -> None:
        stylesheet = (
            Path(__file__).resolve().parents[1] / "static" / "app.css"
        ).read_text(encoding="utf-8")
        self.assertIn(".passkey-choice {", stylesheet)
        self.assertIn(".plain-list li {", stylesheet)
        self.assertIn(".plain-list .button {", stylesheet)
        self.assertIn(
            ".plain-list .button { grid-row: auto; grid-column: 1;",
            stylesheet,
        )


class PasskeyVerificationBoundaryTests(AppTestCase):
    def test_action_context_and_credential_id_reject_untrusted_boundaries(self) -> None:
        for context in ("relative", "/" + "x" * 512, "/profile\nother"):
            with self.subTest(context=context), self.assertRaises(PasskeyError):
                _action_context_hash(context)

        invalid_payloads: tuple[object, ...] = (
            None,
            [],
            {},
            {"id": None},
            {"id": ""},
            {"id": "A" * 2049},
            {"id": "a"},
            {"id": bytes_to_base64url(b"x" * 1025)},
        )
        for payload in invalid_payloads:
            with (
                self.subTest(payload=type(payload).__name__),
                self.assertRaises(PasskeyError),
            ):
                credential_id_from_payload(payload)

    def test_verification_uses_only_configured_origin_and_rp_id(self) -> None:
        user = self.create_user(totp_secret="")
        credential = PasskeyCredential(
            user_id=user.id,
            credential_id=b"credential",
            public_key=b"public-key",
            sign_count=3,
            device_type="single_device",
            backed_up=False,
            aaguid="00000000-0000-0000-0000-000000000000",
            name="Device",
            rp_id="localhost",
            created_at=routes.now_utc(),
            last_used_at=None,
        )
        identity = PasskeyIdentity(
            user_id=user.id,
            user_handle=b"expected-user-handle",
            created_at=routes.now_utc(),
        )
        payload = {
            "response": {
                "userHandle": bytes_to_base64url(identity.user_handle),
            }
        }
        verified = SimpleNamespace(new_sign_count=4)
        with (
            self.app.test_request_context("/"),
            patch(
                "grayhaven_timetracker.passkeys.verify_authentication_response",
                return_value=verified,
            ) as verifier,
        ):
            result = verify_authentication(
                payload,
                credential,
                identity,
                expected_challenge=b"challenge",
                require_user_handle=True,
            )
        self.assertIs(result, verified)
        self.assertEqual(verifier.call_args.kwargs["expected_rp_id"], "localhost")
        self.assertEqual(
            verifier.call_args.kwargs["expected_origin"], "http://localhost:8000"
        )
        self.assertTrue(verifier.call_args.kwargs["require_user_verification"])

        credential.rp_id = "other.example.invalid"
        with self.app.test_request_context("/"), self.assertRaises(PasskeyError):
            verify_authentication(
                payload,
                credential,
                identity,
                expected_challenge=b"challenge",
                require_user_handle=True,
            )
        credential.rp_id = "localhost"
        payload["response"]["userHandle"] = bytes_to_base64url(b"wrong-handle")
        with self.app.test_request_context("/"), self.assertRaises(PasskeyError):
            verify_authentication(
                payload,
                credential,
                identity,
                expected_challenge=b"challenge",
                require_user_handle=True,
            )

    def test_user_handle_requirement_depends_on_authentication_mode(self) -> None:
        user = self.create_user(totp_secret="")
        credential = PasskeyCredential(
            user_id=user.id,
            credential_id=b"credential",
            public_key=b"public-key",
            sign_count=0,
            device_type="single_device",
            backed_up=False,
            aaguid="00000000-0000-0000-0000-000000000000",
            name="Device",
            rp_id="localhost",
            created_at=routes.now_utc(),
            last_used_at=None,
        )
        identity = PasskeyIdentity(
            user_id=user.id,
            user_handle=b"expected-user-handle",
            created_at=routes.now_utc(),
        )
        missing = {"response": {"userHandle": None}}
        wrong = {"response": {"userHandle": bytes_to_base64url(b"wrong-user-handle")}}
        verified = SimpleNamespace(new_sign_count=1)
        with (
            self.app.test_request_context("/"),
            patch(
                "grayhaven_timetracker.passkeys.verify_authentication_response",
                return_value=verified,
            ) as verifier,
        ):
            with self.assertRaises(PasskeyError):
                verify_authentication(
                    missing,
                    credential,
                    identity,
                    expected_challenge=b"challenge",
                    require_user_handle=True,
                )
            self.assertIs(
                verify_authentication(
                    missing,
                    credential,
                    identity,
                    expected_challenge=b"challenge",
                    require_user_handle=False,
                ),
                verified,
            )
            self.assertEqual(verifier.call_count, 1)
            for required in (True, False):
                with self.subTest(required=required), self.assertRaises(PasskeyError):
                    verify_authentication(
                        wrong,
                        credential,
                        identity,
                        expected_challenge=b"challenge",
                        require_user_handle=required,
                    )

            for malformed in (
                None,
                {"response": None},
                {"response": {"userHandle": "a"}},
            ):
                with self.subTest(malformed=malformed), self.assertRaises(PasskeyError):
                    verify_authentication(
                        malformed,
                        credential,
                        identity,
                        expected_challenge=b"challenge",
                        require_user_handle=True,
                    )

    def test_registration_requires_configured_origin_and_user_verification(
        self,
    ) -> None:
        verified = SimpleNamespace(credential_id=b"new")
        with (
            self.app.test_request_context("/"),
            patch(
                "grayhaven_timetracker.passkeys.verify_registration_response",
                return_value=verified,
            ) as verifier,
        ):
            result = verify_registration({"id": "AA"}, expected_challenge=b"challenge")
        self.assertIs(result, verified)
        self.assertEqual(verifier.call_args.kwargs["expected_rp_id"], "localhost")
        self.assertEqual(
            verifier.call_args.kwargs["expected_origin"], "http://localhost:8000"
        )
        self.assertTrue(verifier.call_args.kwargs["require_user_verification"])
