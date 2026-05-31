"""Tests for the WebAuthn HTTP views.

These exercise the URL routing, CSRF behavior, and error-shape contract
of the view layer. Cryptographic verification is owned by the `webauthn`
library (and exercised in test_services); here we mock the service-layer
calls to focus on the view's responsibilities.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from django.core.cache import cache
from django.test import Client, override_settings

from apps.accounts.models import Role, User
from apps.webauthn_auth.models import EnrollmentToken, WebAuthnCredential

if TYPE_CHECKING:
    pass


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


# ---- sign-in views (usernameless / discoverable credentials) --------------


def _b64u(s: str | bytes) -> str:
    data = s.encode("utf-8") if isinstance(s, str) else s
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.mark.django_db
def test_login_start_usernameless_returns_options_without_body(client: Client) -> None:
    """No request body required; the challenge is server-generated and
    session-bound."""
    response = client.post("/webauthn/login/start-usernameless/")
    assert response.status_code == 200
    body = response.json()
    assert body.get("challenge")
    # Empty allow-credentials => browser-side discoverable credential search.
    assert body.get("allowCredentials") in (None, [])


@pytest.mark.django_db
def test_login_start_usernameless_rejects_get(client: Client) -> None:
    response = client.get("/webauthn/login/start-usernameless/")
    assert response.status_code == 405


@pytest.mark.django_db
def test_login_finish_usernameless_logs_user_in_on_success(client: Client) -> None:
    user = User.objects.create_user(email="ul@example.com", display_name="UL")
    WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"ul-id",
        public_key=b"pk",
        sign_count=0,
    )
    session = client.session
    session["webauthn_auth_challenge"] = _b64u(b"challenge")
    # No webauthn_auth_user => usernameless flow.
    session.save()

    fake = type("V", (), {"new_sign_count": 1})
    with patch(
        "apps.webauthn_auth.services.verify_authentication_response",
        return_value=fake,
    ):
        response = client.post(
            "/webauthn/login/finish-usernameless/",
            data=json.dumps(
                {
                    "id": _b64u(b"ul-id"),
                    "response": {"userHandle": _b64u(str(user.id))},
                },
            ),
            content_type="application/json",
        )

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert client.session.get("_auth_user_id") == str(user.id)


@pytest.mark.django_db
def test_login_finish_usernameless_returns_generic_on_failure(client: Client) -> None:
    """Every WebAuthnError flavor (no ceremony, missing handle, mismatch,
    bad signature, replay, clone) must collapse to the same generic code
    so the response surface cannot enumerate failure causes."""
    # No session state => service raises "no authentication ceremony".
    response = client.post(
        "/webauthn/login/finish-usernameless/",
        data=json.dumps({"id": _b64u(b"x"), "response": {"userHandle": _b64u("x")}}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert response.json() == {"error": "authentication_failed"}


@pytest.mark.django_db
def test_login_finish_usernameless_malformed_json_returns_400(client: Client) -> None:
    response = client.post(
        "/webauthn/login/finish-usernameless/",
        data="not-json",
        content_type="application/json",
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_json"


@pytest.mark.django_db
def test_login_finish_usernameless_rejects_get(client: Client) -> None:
    response = client.get("/webauthn/login/finish-usernameless/")
    assert response.status_code == 405


@pytest.mark.django_db
@override_settings(RATELIMIT_ENABLE=True)
def test_login_start_usernameless_rate_limited(client: Client) -> None:
    """Per-IP throttle on the usernameless start. 6th hit returns 429."""
    cache.clear()
    for _ in range(5):
        assert client.post("/webauthn/login/start-usernameless/").status_code == 200
    blocked = client.post("/webauthn/login/start-usernameless/")
    assert blocked.status_code == 429
    assert blocked["Retry-After"] == "60"


@pytest.mark.django_db
def test_login_finish_usernameless_requires_csrf(client: Client) -> None:
    """The finish view is CSRF-protected; a cross-origin POST without the
    token must be rejected even though the endpoint is anonymous."""
    csrf_client = Client(enforce_csrf_checks=True)
    response = csrf_client.post(
        "/webauthn/login/finish-usernameless/",
        data=json.dumps({"id": "x", "response": {"userHandle": "x"}}),
        content_type="application/json",
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_full_usernameless_flow_through_test_client(client: Client) -> None:
    """End-to-end through Django's test client: hit /start-usernameless/,
    feed the returned challenge through a mocked signature verify, hit
    /finish-usernameless/. The session moves from anonymous to logged-in."""
    user = User.objects.create_user(email="e2e@example.com", display_name="E")
    WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"e2e-cred",
        public_key=b"pk",
        sign_count=0,
    )

    # 1) Start: server stores the challenge in the session.
    start = client.post("/webauthn/login/start-usernameless/")
    assert start.status_code == 200
    assert client.session.get("webauthn_auth_challenge")
    assert "webauthn_auth_user" not in client.session  # usernameless => no user pinned

    # 2) Finish: signature verify is mocked, but every other check (session
    # state, credential lookup, userHandle binding, sign_count) runs.
    fake = type("V", (), {"new_sign_count": 1})
    with patch(
        "apps.webauthn_auth.services.verify_authentication_response",
        return_value=fake,
    ):
        finish = client.post(
            "/webauthn/login/finish-usernameless/",
            data=json.dumps(
                {
                    "id": _b64u(b"e2e-cred"),
                    "response": {"userHandle": _b64u(str(user.id))},
                },
            ),
            content_type="application/json",
        )

    assert finish.status_code == 200
    assert finish.json()["ok"] is True
    assert client.session["_auth_user_id"] == str(user.id)
    # Challenge consumed (single-use): a replay must fail.
    assert "webauthn_auth_challenge" not in client.session
