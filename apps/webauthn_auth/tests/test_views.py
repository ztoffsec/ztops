"""Tests for the WebAuthn HTTP views.

These exercise the URL routing, CSRF behavior, and error-shape contract
of the view layer. Cryptographic verification is owned by the `webauthn`
library (and exercised in test_services); here we mock the service-layer
calls to focus on the view's responsibilities.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from django.core.cache import cache
from django.test import override_settings

from apps.accounts.models import Role, User
from apps.webauthn_auth.models import EnrollmentToken, WebAuthnCredential

if TYPE_CHECKING:
    from django.test import Client


@pytest.fixture
def enrolled_token() -> tuple[User, str]:
    user = User.objects.create_user(
        email="view@example.com",
        display_name="V",
        role=Role.SUPERADMIN,
    )
    _, raw = EnrollmentToken.issue(user)
    return user, raw


@pytest.mark.django_db
def test_enroll_page_renders_for_valid_token(
    client: Client, enrolled_token: tuple[User, str]
) -> None:
    _, raw = enrolled_token
    response = client.get(f"/webauthn/enroll/{raw}/")
    assert response.status_code == 200
    assert b"Register your passkey" in response.content
    assert b"view@example.com" in response.content
    # CSRF cookie set so the subsequent POST can authenticate.
    assert "csrftoken" in response.cookies


@pytest.mark.django_db
def test_enroll_page_404s_for_unknown_token(client: Client) -> None:
    response = client.get("/webauthn/enroll/zto_enr_doesnotexist/")
    assert response.status_code == 404


@pytest.mark.django_db
def test_registration_start_rejects_invalid_token(client: Client) -> None:
    response = client.post(
        "/webauthn/register/start/zto_enr_bogus/", content_type="application/json"
    )
    assert response.status_code == 403
    assert response.json()["error"] == "invalid_token"


@pytest.mark.django_db
def test_registration_start_returns_options_for_valid_token(
    client: Client,
    enrolled_token: tuple[User, str],
) -> None:
    _, raw = enrolled_token
    # First GET to set CSRF cookie.
    client.get(f"/webauthn/enroll/{raw}/")
    response = client.post(
        f"/webauthn/register/start/{raw}/",
        content_type="application/json",
    )
    assert response.status_code == 200
    data = response.json()
    assert "challenge" in data
    assert data["rp"]["id"]
    assert data["user"]["name"] == "view@example.com"


@pytest.mark.django_db
def test_login_start_does_not_leak_user_existence(client: Client) -> None:
    # Same error shape whether the email is unknown or exists without credentials.
    User.objects.create_user(email="noccc@example.com", display_name="NC")

    for email in ("noccc@example.com", "neverexisted@example.com"):
        response = client.post(
            "/webauthn/login/start/",
            data=json.dumps({"email": email}),
            content_type="application/json",
        )
        assert response.status_code == 400
        assert response.json() == {"error": "no_credentials_available"}


@pytest.mark.django_db
def test_login_start_requires_email_field(client: Client) -> None:
    response = client.post(
        "/webauthn/login/start/",
        data=json.dumps({}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert response.json()["error"] == "email_required"


@pytest.mark.django_db
def test_login_finish_logs_user_into_session_on_success(client: Client) -> None:
    user = User.objects.create_user(email="ses@example.com", display_name="S")
    WebAuthnCredential.objects.create(user=user, credential_id=b"validid", public_key=b"pk")
    # Pre-seed session as if start_authentication had succeeded.
    session = client.session
    session["webauthn_auth_user"] = str(user.id)
    session["webauthn_auth_challenge"] = "Y2hhbGxlbmdl"
    session.save()

    fake_verified = type("V", (), {"new_sign_count": 1})

    with patch(
        "apps.webauthn_auth.services.verify_authentication_response",
        return_value=fake_verified,
    ):
        response = client.post(
            "/webauthn/login/finish/",
            data=json.dumps({"id": "dmFsaWRpZA"}),  # base64url(b'validid')
            content_type="application/json",
        )

    assert response.status_code == 200
    assert response.json()["ok"] is True
    # The session now has the auth user id (`_auth_user_id` is Django's key).
    assert client.session.get("_auth_user_id") == str(user.id)


@pytest.mark.django_db
@override_settings(RATELIMIT_ENABLE=True)
def test_login_start_rate_limited_returns_429(client: Client) -> None:
    """ZT-002: per-email throttle on login_start. The 6th call within the
    window (rate 5/m, keyed on the JSON-body email) is mapped to HTTP 429
    with a Retry-After header by RatelimitTo429Middleware.

    The email is read from the JSON body, not request.POST — this asserts
    the key function parses the body (otherwise every login would share one
    'no-email' bucket and this test would still pass for the wrong reason,
    so we also confirm a *different* email is not throttled).
    """
    cache.clear()  # Redis counters persist across runs; start clean.

    def hit(email: str):
        return client.post(
            "/webauthn/login/start/",
            data=json.dumps({"email": email}),
            content_type="application/json",
        )

    # 5 allowed (each 400 — unknown email), 6th over the per-email cap.
    for _ in range(5):
        assert hit("flood@example.com").status_code == 400
    blocked = hit("flood@example.com")
    assert blocked.status_code == 429
    assert blocked["Retry-After"] == "60"

    # A different email is its own bucket — not collateral-damaged. Proves the
    # key is per-email (parsed from the body), not a single global bucket.
    assert hit("other@example.com").status_code == 400
