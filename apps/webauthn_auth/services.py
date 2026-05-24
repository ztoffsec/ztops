"""Service layer for the WebAuthn ceremonies.

Wraps the Duo `webauthn` library so that the view layer never deals with
the protocol directly: views call into ``start_registration`` /
``finish_registration`` / ``start_authentication`` /
``finish_authentication`` and get back simple Python types.

Challenges are stored in the Django session (Redis-backed). The view
layer never sees the raw challenge bytes — the ceremony is initiated
and completed by passing the request through these helpers.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .models import WebAuthnCredential

if TYPE_CHECKING:
    from django.http import HttpRequest

User = get_user_model()


class WebAuthnError(Exception):
    """Raised by service functions when the ceremony cannot complete.

    The message is suitable for surfacing to the operator's terminal;
    DO NOT relay it directly to an HTTP response body unless you have
    audited that the string does not leak whether a user exists.
    """


_SESSION_REG_CHALLENGE = "webauthn_reg_challenge"
_SESSION_REG_USER = "webauthn_reg_user"
_SESSION_AUTH_CHALLENGE = "webauthn_auth_challenge"
_SESSION_AUTH_USER = "webauthn_auth_user"


# --- base64url helpers (sessions hold JSON, so bytes get encoded) -------------


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# --- registration ceremony ---------------------------------------------------


def start_registration(user: Any, request: HttpRequest) -> dict[str, Any]:
    """Generate a registration challenge and stash it in the session.

    Returns the registration options as a JSON-serializable dict ready
    for the browser's ``navigator.credentials.create()``.
    """
    existing_ids = list(user.credentials.values_list("credential_id", flat=True))

    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=str(user.id).encode("utf-8"),
        user_name=user.email,
        user_display_name=user.display_name,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=bytes(cred_id)) for cred_id in existing_ids
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        attestation=AttestationConveyancePreference.NONE,
    )

    request.session[_SESSION_REG_CHALLENGE] = _b64u_encode(options.challenge)
    request.session[_SESSION_REG_USER] = str(user.id)

    return json.loads(options_to_json(options))


def finish_registration(
    request: HttpRequest,
    credential: dict[str, Any],
) -> WebAuthnCredential:
    """Verify a registration response and persist the new credential."""
    challenge_b64 = request.session.pop(_SESSION_REG_CHALLENGE, None)
    user_id = request.session.pop(_SESSION_REG_USER, None)
    if not challenge_b64 or not user_id:
        msg = "no registration ceremony in progress"
        raise WebAuthnError(msg)

    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist as exc:
        msg = "registration target user no longer exists"
        raise WebAuthnError(msg) from exc

    challenge = _b64u_decode(challenge_b64)

    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_RP_ORIGINS,
        )
    except Exception as exc:
        msg = f"registration verification failed: {exc}"
        raise WebAuthnError(msg) from exc

    transports = credential.get("response", {}).get("transports", [])
    aaguid_str = getattr(verified, "aaguid", None)
    aaguid_value = (
        aaguid_str if aaguid_str and aaguid_str != "00000000-0000-0000-0000-000000000000" else None
    )

    cred: WebAuthnCredential = WebAuthnCredential.objects.create(
        user=user,
        credential_id=bytes(verified.credential_id),
        public_key=bytes(verified.credential_public_key),
        sign_count=verified.sign_count or 0,
        aaguid=aaguid_value,
        transports=transports,
    )
    return cred


# --- authentication ceremony -------------------------------------------------


def start_authentication(email: str, request: HttpRequest) -> dict[str, Any]:
    """Generate an authentication challenge for the user with ``email``.

    Raises WebAuthnError if no usable credentials exist. Callers MUST
    map that error to the same generic response as "wrong email" — do
    not leak whether the email is registered.
    """
    try:
        user = User.objects.get(email=email, is_active=True)
    except User.DoesNotExist as exc:
        msg = "no credentials available"
        raise WebAuthnError(msg) from exc

    cred_ids = list(user.credentials.values_list("credential_id", flat=True))
    if not cred_ids:
        msg = "no credentials available"
        raise WebAuthnError(msg)

    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=bytes(cred_id)) for cred_id in cred_ids
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    request.session[_SESSION_AUTH_CHALLENGE] = _b64u_encode(options.challenge)
    request.session[_SESSION_AUTH_USER] = str(user.id)

    return json.loads(options_to_json(options))


def finish_authentication(request: HttpRequest, credential: dict[str, Any]) -> Any:
    """Verify the assertion and update sign_count + last_used_at.

    Returns the authenticated User on success.
    """
    challenge_b64 = request.session.pop(_SESSION_AUTH_CHALLENGE, None)
    user_id = request.session.pop(_SESSION_AUTH_USER, None)
    if not challenge_b64 or not user_id:
        msg = "no authentication ceremony in progress"
        raise WebAuthnError(msg)

    challenge = _b64u_decode(challenge_b64)
    credential_id = _b64u_decode(credential["id"])

    try:
        cred = WebAuthnCredential.objects.select_related("user").get(
            user_id=user_id,
            credential_id=credential_id,
        )
    except WebAuthnCredential.DoesNotExist as exc:
        msg = "credential not registered to this user"
        raise WebAuthnError(msg) from exc

    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_RP_ORIGINS,
            credential_public_key=bytes(cred.public_key),
            credential_current_sign_count=cred.sign_count,
        )
    except Exception as exc:
        msg = f"authentication verification failed: {exc}"
        raise WebAuthnError(msg) from exc

    # Sign-count clone detection: an authenticator should never present
    # a count <= our stored value. The lib's verify already checks this
    # for non-zero counters, but be explicit.
    if cred.sign_count > 0 and verified.new_sign_count <= cred.sign_count:
        msg = "possible credential clone detected (sign_count regression)"
        raise WebAuthnError(msg)

    cred.sign_count = verified.new_sign_count
    cred.last_used_at = timezone.now()
    cred.save(update_fields=["sign_count", "last_used_at"])

    return cred.user
