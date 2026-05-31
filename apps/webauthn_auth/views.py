"""WebAuthn ceremony HTTP endpoints.

Five views:

- `enroll_page` (GET): renders the HTML+JS page that drives the
  in-browser ceremony for an enrollment-token holder. Sets the CSRF
  cookie so the subsequent fetch()-based POSTs can carry the header.
- `registration_start` (POST): given a valid enrollment token, returns
  the registration options for `navigator.credentials.create()`.
- `registration_finish` (POST): verifies the attestation, stores the
  credential, marks the enrollment token used.
- `login_start` (POST): given an email, returns authentication options.
  Does not leak whether the email exists.
- `login_finish` (POST): verifies the assertion and creates a Django
  session bound to the authenticated user.
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
from core.security.ratelimit_keys import client_ip, enroll_token, login_email

from .models import EnrollmentToken
from .services import (
    WebAuthnError,
    finish_authentication,
    finish_registration,
    start_authentication,
    start_registration,
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


@csrf_protect
@require_POST
@ratelimit(key=client_ip, rate="10/m", block=True)
@ratelimit(key=login_email, rate="5/m", block=True)
def login_start(request: HttpRequest) -> JsonResponse:
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid_json"}, status=400)

    email = (body.get("email") or "").strip()
    if not email:
        return JsonResponse({"error": "email_required"}, status=400)

    try:
        options = start_authentication(email, request)
    except WebAuthnError:
        # Do not distinguish "no such user" from "user has no credentials"
        # from any other ceremony-start failure. The frontend renders a
        # fixed generic message regardless; the neutral code keeps DevTools
        # and server logs from accidentally hinting at the cause too.
        return JsonResponse({"error": "authentication_failed"}, status=400)

    return JsonResponse(options)


@csrf_protect
@require_POST
@ratelimit(key=client_ip, rate="10/m", block=True)
def login_finish(request: HttpRequest) -> JsonResponse:
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid_json"}, status=400)

    try:
        user = finish_authentication(request, body)
    except WebAuthnError:
        # Same generic response for every ceremony-finish failure
        # (signature mismatch, expired challenge, replayed credential,
        # tampered payload). The specifics stay in the WebAuthnError
        # exception which propagates to the server log via Django's
        # request handler; the JSON body never echoes them back.
        return JsonResponse({"error": "authentication_failed"}, status=400)

    # Mark which backend "authenticated" the user so django_login skips
    # the authenticate() loop. The backend's own authenticate() returns
    # None — login through WebAuthn is the only valid path.
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
