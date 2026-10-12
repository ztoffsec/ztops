"""WebAuthn ceremony HTTP endpoints.

Seven views:

- `enroll_page` (GET): renders the HTML+JS page that drives the
  in-browser ceremony for an enrollment-token holder. Sets the CSRF
  cookie so the subsequent fetch()-based POSTs can carry the header.
- `registration_start` (POST): given a valid enrollment token, returns
  the registration options for `navigator.credentials.create()`.
- `registration_finish` (POST): verifies the attestation, stores the
  credential, marks the enrollment token used.
- `login_start_usernameless` (POST): returns authentication options
  with no `allowCredentials` list, so the browser picks any resident
  credential for this RP_ID. No email surface.
- `login_finish_usernameless` (POST): verifies the assertion, resolves
  identity from the credential id + userHandle, and creates a Django
  session bound to the authenticated user.
- `step_up_start` / `step_up_finish` (POST, signed-in users only): a fresh
  passkey assertion from the session's own user, producing a one-shot,
  purpose-bound, short-lived grant (e.g. required to mint an API token).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from django.contrib.auth import login as django_login
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.decorators.http import require_POST, require_safe
from django_ratelimit.decorators import ratelimit

from apps.audit.models import AuditAction
from apps.audit.services import audit
from core.security.crypto import verify_token
from core.security.ratelimit_keys import client_ip, enroll_token, session_user

from .models import EnrollmentToken
from .services import (
    WebAuthnError,
    finish_authentication_usernameless,
    finish_registration,
    finish_step_up,
    start_authentication_usernameless,
    start_registration,
    start_step_up,
)

if TYPE_CHECKING:
    from django.http import HttpRequest


def _lookup_active_token(raw_token: str) -> EnrollmentToken | None:
    """Look up an unexpired, unused token by its prefix and verify the hash.

    Unlike `EnrollmentToken.consume`, this does NOT mark the token used —
    `registration_start` needs to validate the token without burning it
    (otherwise a transient network error would lock the operator out).
    The token is burned at the end of `registration_finish`.
    """
    if not raw_token:
        return None

    prefix = raw_token[:16]
    for candidate in EnrollmentToken.objects.filter(
        token_prefix=prefix,
        used_at__isnull=True,
        expires_at__gt=timezone.now(),
    ):
        if verify_token(raw_token, candidate.token_hash):
            return candidate
    return None


@require_safe
@ensure_csrf_cookie
@ratelimit(key=client_ip, rate="10/m", block=True)
@ratelimit(key=enroll_token, rate="10/m", block=True)
def enroll_page(request: HttpRequest, token: str) -> HttpResponse:
    et = _lookup_active_token(token)
    if et is None:
        return HttpResponse(
            "Enrollment token is invalid, expired, or already used.",
            status=404,
            content_type="text/plain",
        )
    return render(
        request,
        "public/webauthn/enroll.html",
        {"token": token, "email": et.user.email, "display_name": et.user.display_name},
    )


@csrf_protect
@require_POST
@ratelimit(key=client_ip, rate="5/m", block=True)
@ratelimit(key=enroll_token, rate="5/m", block=True)
def registration_start(request: HttpRequest, token: str) -> JsonResponse:
    et = _lookup_active_token(token)
    if et is None:
        return JsonResponse({"error": "invalid_token"}, status=403)
    options = start_registration(et.user, request)
    return JsonResponse(options)


@csrf_protect
@require_POST
@ratelimit(key=client_ip, rate="5/m", block=True)
@ratelimit(key=enroll_token, rate="5/m", block=True)
def registration_finish(request: HttpRequest, token: str) -> JsonResponse:
    et = _lookup_active_token(token)
    if et is None:
        return JsonResponse({"error": "invalid_token"}, status=403)

    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid_json"}, status=400)

    try:
        cred = finish_registration(request, body)
    except WebAuthnError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    et.mark_used()
    audit(
        action=AuditAction.CREDENTIAL_REGISTERED,
        actor=et.user,
        request=request,
        target_kind="credential",
        target_id=str(cred.id),
        target_label=et.user.email,
        metadata={"transports": list(cred.transports)},
    )
    return JsonResponse({"ok": True, "credential_id": str(cred.id)})


# --- usernameless (discoverable-credential) sign-in --------------------------
#
# The browser discovers the credential from its own store of resident keys for
# this RP_ID. No request body for start (the challenge is server-generated,
# session-bound); no email surface, no per-user rate-limit key.
#
# Security envelope:
#   - login_start_usernameless: POST + @csrf_protect + per-IP @ratelimit.
#     No body parsed; nothing in the request can route the lookup, so
#     there is nothing to enumerate.
#   - login_finish_usernameless: POST + @csrf_protect + per-IP @ratelimit.
#     Any WebAuthnError collapses to the generic `authentication_failed`,
#     so an attacker cannot tell which leg of the verify failed.


@csrf_protect
@require_POST
@ratelimit(key=client_ip, rate="5/m", block=True)
def login_start_usernameless(request: HttpRequest) -> JsonResponse:
    """Begin a usernameless authentication ceremony.

    Returns the public-key options the browser feeds to
    ``navigator.credentials.get()``. No email, no body required.
    """
    try:
        options = start_authentication_usernameless(request)
    except WebAuthnError:
        # Any ceremony-start failure collapses to the same generic code.
        return JsonResponse({"error": "authentication_failed"}, status=400)
    return JsonResponse(options)


@csrf_protect
@require_POST
@ratelimit(key=client_ip, rate="10/m", block=True)
def login_finish_usernameless(request: HttpRequest) -> JsonResponse:
    """Finish a usernameless authentication ceremony.

    The body carries the assertion plus the discovered ``userHandle``.
    Identity is resolved on the server side by the credential id, then
    cross-checked against the userHandle and the cryptographic signature
    (see ``finish_authentication_usernameless``).
    """
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid_json"}, status=400)

    try:
        user = finish_authentication_usernameless(request, body)
    except WebAuthnError:
        # Every ceremony-finish failure collapses to the same code so
        # DevTools / logs never reveal the reason (no-such-credential,
        # tampered userHandle, signature mismatch, replay, clone).
        return JsonResponse({"error": "authentication_failed"}, status=400)

    user.backend = "apps.accounts.backends.WebAuthnAuthBackend"
    django_login(request, user)

    audit(
        action=AuditAction.USER_SIGNED_IN,
        actor=user,
        request=request,
        target_kind="user",
        target_id=str(user.id),
        target_label=user.email,
    )
    return JsonResponse({"ok": True, "redirect": "/super/dashboard/"})


# --- step-up (fresh passkey assertion from an already signed-in user) -------
#
# JSON-only endpoints. Unauthenticated callers get a JSON 401 (not a login
# redirect) because they are only ever driven by fetch(). CSRF-protected,
# POST-only, rate-limited per IP and per user. Every ceremony failure
# collapses to the same generic code.


def _require_session_user(request: HttpRequest) -> JsonResponse | None:
    if not request.user.is_authenticated or not request.user.is_active:
        return JsonResponse({"error": "authentication_required"}, status=401)
    return None


@csrf_protect
@require_POST
@ratelimit(key=client_ip, rate="10/m", block=True)
@ratelimit(key=session_user, rate="10/m", block=True)
def step_up_start(request: HttpRequest) -> JsonResponse:
    if (denied := _require_session_user(request)) is not None:
        return denied
    try:
        body = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid_json"}, status=400)
    purpose = body.get("purpose") if isinstance(body, dict) else None
    try:
        options = start_step_up(request.user, request, str(purpose or ""))
    except WebAuthnError:
        return JsonResponse({"error": "step_up_failed"}, status=400)
    return JsonResponse(options)


@csrf_protect
@require_POST
@ratelimit(key=client_ip, rate="10/m", block=True)
@ratelimit(key=session_user, rate="10/m", block=True)
def step_up_finish(request: HttpRequest) -> JsonResponse:
    if (denied := _require_session_user(request)) is not None:
        return denied
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid_json"}, status=400)
    if not isinstance(body, dict):
        return JsonResponse({"error": "step_up_failed"}, status=400)
    try:
        purpose = finish_step_up(request.user, request, body)
    except WebAuthnError:
        return JsonResponse({"error": "step_up_failed"}, status=400)

    audit(
        action=AuditAction.STEP_UP_VERIFIED,
        actor=request.user,
        request=request,
        target_kind="user",
        target_id=str(request.user.id),
        target_label=request.user.email,
        metadata={"purpose": purpose},
    )
    return JsonResponse({"ok": True})
