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
            # REQUIRED on both so every new enrollment is usernameless-capable:
            # the credential is discoverable (resident on the authenticator,
            # so the browser can list it without the server providing the
            # credential id) and user-verified at use time (PIN / biometric,
            # so a stolen device cannot impersonate the owner). The combination
            # is what mitigates the user-enumeration window at sign-in: with
            # no email field, there is nothing to probe.
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.REQUIRED,
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


# --- usernameless / discoverable-credential authentication --------------------
#
# The email-keyed flow above identifies the user before the ceremony starts and
# the server returns the user's credential ids in `allow_credentials`. That
# means the sign-in page must accept an email, which is the surface the
# friend's concern targets: an attacker can probe email values to learn which
# accounts exist (mitigated today by uniform error wording + tighter rate
# limits, but the input field still exists).
#
# The usernameless flow below removes the email surface entirely. The server
# starts the ceremony with NO knowledge of the user. The browser picks any
# resident credential for this RP_ID, runs the assertion, and returns the
# `userHandle` (the user id we wrote into the credential at registration) plus
# the credential id. Identity is resolved on the server only after the
# signature has been verified against the public key stored for that
# credential id. There is no per-user state to leak: the input is just a
# random challenge bound to the session.
#
# Security properties enforced here:
#   - empty allow_credentials list -> browser-side discovery
#   - user_verification REQUIRED -> stolen device cannot sign in without PIN
#   - challenge is single-use, pop()'d from the session before verify
#   - credential lookup is by credential_id alone; user resolved via the FK
#   - the assertion's userHandle MUST match the credential's user id, both
#     as a sanity check (defends against an authenticator that mis-reports
#     its userHandle) and to fail closed if the data ever drifts
#   - the new ceremony key is separate from the email-keyed key, so a
#     ceremony started one way cannot be finished the other way


def start_authentication_usernameless(request: HttpRequest) -> dict[str, Any]:
    """Generate an authentication challenge with no allow-credentials list.

    The browser shows every discoverable passkey for this RP_ID and the
    user picks one. Identity is resolved on finish, from the assertion's
    userHandle plus the credential id. No email surface, no per-user
    state in the request body.
    """
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        # Empty list => the browser searches its discoverable credentials.
        allow_credentials=[],
        # REQUIRED is what gives the usernameless flow its security: even
        # if an attacker has physical possession of the device, they must
        # present a verified user (PIN or biometric).
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    request.session[_SESSION_AUTH_CHALLENGE] = _b64u_encode(options.challenge)
    # No user id is bound to the session yet. Make sure any stale one is
    # cleared so a finish call cannot accidentally pick up the wrong path
    # (defense against a confused-deputy bug between the two flows).
    request.session.pop(_SESSION_AUTH_USER, None)

    return json.loads(options_to_json(options))


def finish_authentication_usernameless(
    request: HttpRequest,
    credential: dict[str, Any],
) -> Any:
    """Verify a discoverable-credential assertion and return the User.

    Lookups happen by credential id alone; the user is resolved through
    the credential's FK. The assertion's ``userHandle`` is cross-checked
    against the credential's user id so a tampered or mis-reporting
    authenticator cannot impersonate a different account, even though
    the signature itself is what carries the security.
    """
    challenge_b64 = request.session.pop(_SESSION_AUTH_CHALLENGE, None)
    if not challenge_b64:
        msg = "no authentication ceremony in progress"
        raise WebAuthnError(msg)

    # The usernameless flow must NEVER have a user pinned to the session.
    # If one is present here it means a parallel email-keyed start happened
    # in the same session; refuse the finish to keep the flows isolated.
    if request.session.pop(_SESSION_AUTH_USER, None):
        msg = "ceremony mode mismatch"
        raise WebAuthnError(msg)

    challenge = _b64u_decode(challenge_b64)
    credential_id = _b64u_decode(credential["id"])

    try:
        cred = WebAuthnCredential.objects.select_related("user").get(
            credential_id=credential_id,
        )
    except WebAuthnCredential.DoesNotExist as exc:
        msg = "credential not registered"
        raise WebAuthnError(msg) from exc

    if not cred.user.is_active:
        msg = "credential owner is inactive"
        raise WebAuthnError(msg)

    # Cross-check the userHandle from the assertion against the credential's
    # user id. The signature verification below is the cryptographic gate,
    # this match catches non-cryptographic regressions (data drift, an
    # authenticator returning the wrong handle) and a misconfigured library.
    user_handle_b64 = (credential.get("response") or {}).get("userHandle")
    if not user_handle_b64:
        msg = "assertion missing userHandle"
        raise WebAuthnError(msg)
    try:
        user_handle = _b64u_decode(user_handle_b64).decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        msg = "malformed userHandle"
        raise WebAuthnError(msg) from exc
    if user_handle != str(cred.user_id):
        msg = "userHandle does not match credential owner"
        raise WebAuthnError(msg)

    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_RP_ORIGINS,
            credential_public_key=bytes(cred.public_key),
            credential_current_sign_count=cred.sign_count,
            # require_user_verification mirrors the start-side
            # UserVerificationRequirement.REQUIRED: the server refuses
            # assertions where the UV bit is not set, so a downgrade
            # attack at the browser layer cannot succeed.
            require_user_verification=True,
        )
    except Exception as exc:
        msg = f"authentication verification failed: {exc}"
        raise WebAuthnError(msg) from exc

    # Sign-count clone detection (same as the email-keyed path).
    if cred.sign_count > 0 and verified.new_sign_count <= cred.sign_count:
        msg = "possible credential clone detected (sign_count regression)"
        raise WebAuthnError(msg)

    cred.sign_count = verified.new_sign_count
    cred.last_used_at = timezone.now()
    cred.save(update_fields=["sign_count", "last_used_at"])

    return cred.user
