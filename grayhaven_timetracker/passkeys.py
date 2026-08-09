"""Trusted WebAuthn option, challenge, and verification helpers."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from flask import current_app, session
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.authentication.verify_authentication_response import (
    VerifiedAuthentication,
)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

from .models import PasskeyCredential, PasskeyIdentity, User, WebAuthnChallenge

CHALLENGE_TTL_SECONDS = 300
MAX_ACTION_CONTEXT_LENGTH = 512
SESSION_BINDING_KEY = "webauthn_session_binding"


class PasskeyError(ValueError):
    """Raised when passkey ceremony state is malformed, stale, or mismatched."""


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def _session_binding() -> str:
    value = session.get(SESSION_BINDING_KEY)
    if not isinstance(value, str) or len(value) < 32:
        value = secrets.token_urlsafe(32)
        session[SESSION_BINDING_KEY] = value
    return value


def _binding_hash() -> bytes:
    return hashlib.sha256(_session_binding().encode()).digest()


def _action_context_hash(action_context: str | None) -> bytes | None:
    if action_context is None:
        return None
    if (
        not action_context.startswith("/")
        or len(action_context) > MAX_ACTION_CONTEXT_LENGTH
        or any(ord(character) < 32 for character in action_context)
    ):
        raise PasskeyError("The passkey action was not accepted.")
    return hashlib.sha256(action_context.encode()).digest()


def _rp_id() -> str:
    return cast(str, current_app.config["WEBAUTHN_RP_ID"])


def _origin() -> str:
    return cast(str, current_app.config["WEBAUTHN_ORIGIN"])


def _options_payload(options: Any, challenge_id: str) -> dict[str, Any]:
    payload = cast(dict[str, Any], json.loads(options_to_json(options)))
    payload["challengeId"] = challenge_id
    return payload


def _issue_challenge(
    database: Session,
    *,
    ceremony: str,
    challenge: bytes,
    user_id: int | None,
    action_context: str | None = None,
) -> str:
    now = _now()
    binding_hash = _binding_hash()
    context_hash = _action_context_hash(action_context)
    database.execute(
        delete(WebAuthnChallenge).where(WebAuthnChallenge.expires_at <= now)
    )
    database.execute(
        delete(WebAuthnChallenge).where(
            WebAuthnChallenge.ceremony == ceremony,
            WebAuthnChallenge.user_id == user_id,
            WebAuthnChallenge.session_binding_hash == binding_hash,
        )
    )
    challenge_id = secrets.token_urlsafe(32)
    database.add(
        WebAuthnChallenge(
            id=challenge_id,
            challenge=challenge,
            ceremony=ceremony,
            user_id=user_id,
            session_binding_hash=binding_hash,
            action_context_hash=context_hash,
            created_at=now,
            expires_at=now + timedelta(seconds=CHALLENGE_TTL_SECONDS),
        )
    )
    database.commit()
    return challenge_id


def consume_challenge(
    database: Session,
    challenge_id: object,
    *,
    ceremony: str,
    user_id: int | None,
    action_context: str | None = None,
) -> bytes:
    """Consume matching ceremony state before attempting cryptographic verification."""
    if not isinstance(challenge_id, str) or not 32 <= len(challenge_id) <= 64:
        raise PasskeyError("The passkey challenge was not accepted.")
    item = database.get(WebAuthnChallenge, challenge_id)
    if item is None:
        raise PasskeyError("The passkey challenge expired or was already used.")
    if item.expires_at <= _now():
        database.delete(item)
        database.commit()
        raise PasskeyError("The passkey challenge expired or was already used.")
    context_hash = _action_context_hash(action_context)
    if (
        item.ceremony != ceremony
        or item.user_id != user_id
        or not secrets.compare_digest(item.session_binding_hash, _binding_hash())
        or item.action_context_hash != context_hash
    ):
        database.delete(item)
        database.commit()
        raise PasskeyError("The passkey challenge was not accepted.")
    challenge = bytes(item.challenge)
    database.delete(item)
    database.commit()
    return challenge


def credential_id_from_payload(payload: object) -> bytes:
    """Extract a bounded credential identifier without trusting other response data."""
    if not isinstance(payload, dict):
        raise PasskeyError("The passkey response was not accepted.")
    encoded = payload.get("rawId") or payload.get("id")
    if not isinstance(encoded, str) or not 1 <= len(encoded) <= 2048:
        raise PasskeyError("The passkey response was not accepted.")
    try:
        value = base64url_to_bytes(encoded)
    except Exception as exc:
        raise PasskeyError("The passkey response was not accepted.") from exc
    if not 1 <= len(value) <= 1024:
        raise PasskeyError("The passkey response was not accepted.")
    return value


def _assert_user_handle(payload: object, expected: bytes, *, required: bool) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("response"), dict):
        raise PasskeyError("The passkey response was not accepted.")
    encoded = payload["response"].get("userHandle")
    if encoded is None and not required:
        return
    if not isinstance(encoded, str):
        raise PasskeyError("The passkey response did not identify an account.")
    try:
        supplied = base64url_to_bytes(encoded)
    except Exception as exc:
        raise PasskeyError("The passkey response was not accepted.") from exc
    if not secrets.compare_digest(supplied, expected):
        raise PasskeyError("The passkey response was not accepted.")


def registration_options(database: Session, user: User) -> dict[str, Any]:
    identity = database.get(PasskeyIdentity, user.id)
    if identity is None:
        identity = PasskeyIdentity(
            user_id=user.id, user_handle=secrets.token_bytes(32), created_at=_now()
        )
        database.add(identity)
        database.flush()
    rp_id = _rp_id()
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name="Grayhaven Systems LLC Time Tracker",
        user_id=identity.user_handle,
        user_name=user.email,
        user_display_name=user.full_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            require_resident_key=True,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=credential.credential_id)
            for credential in database.scalars(
                select(PasskeyCredential).where(
                    PasskeyCredential.user_id == user.id,
                    PasskeyCredential.rp_id == rp_id,
                )
            )
        ],
    )
    challenge_id = _issue_challenge(
        database,
        ceremony="registration",
        challenge=options.challenge,
        user_id=user.id,
    )
    return _options_payload(options, challenge_id)


def authentication_options(
    database: Session,
    *,
    user: User | None = None,
    ceremony: str = "authentication",
    action_context: str | None = None,
) -> dict[str, Any]:
    rp_id = _rp_id()
    allow_credentials = None
    if user is not None:
        allow_credentials = [
            PublicKeyCredentialDescriptor(id=credential.credential_id)
            for credential in database.scalars(
                select(PasskeyCredential).where(
                    PasskeyCredential.user_id == user.id,
                    PasskeyCredential.rp_id == rp_id,
                )
            )
        ]
        if not allow_credentials:
            raise PasskeyError("No passkeys are available for this account.")
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    challenge_id = _issue_challenge(
        database,
        ceremony=ceremony,
        challenge=options.challenge,
        user_id=user.id if user else None,
        action_context=action_context,
    )
    return _options_payload(options, challenge_id)


def verify_registration(
    payload: object, *, expected_challenge: bytes
) -> VerifiedRegistration:
    return verify_registration_response(
        credential=cast(dict[str, Any], payload),
        expected_challenge=expected_challenge,
        expected_rp_id=_rp_id(),
        expected_origin=_origin(),
        require_user_verification=True,
    )


def verify_authentication(
    payload: object,
    credential: PasskeyCredential,
    identity: PasskeyIdentity,
    *,
    expected_challenge: bytes,
    require_user_handle: bool,
) -> VerifiedAuthentication:
    if credential.rp_id != _rp_id():
        raise PasskeyError("This passkey belongs to a different relying party.")
    _assert_user_handle(payload, identity.user_handle, required=require_user_handle)
    return verify_authentication_response(
        credential=cast(dict[str, Any], payload),
        expected_challenge=expected_challenge,
        expected_rp_id=_rp_id(),
        expected_origin=_origin(),
        credential_public_key=credential.public_key,
        credential_current_sign_count=credential.sign_count,
        require_user_verification=True,
    )
