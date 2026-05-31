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
        assert response.json() == {"error": "authentication_failed"}


@pytest.mark.django_db
def test_login_finish_does_not_echo_exception_message(client: Client) -> None:
    """A failed verification must not leak the specific WebAuthn cause.

    Before the fix the view returned `{"error": str(exc)}` so the client
    saw the underlying message ("signature mismatch", "expired challenge",
    "credential not found"). Now every failure collapses to the same
    generic code so DevTools / logs don't enumerate causes.
    """
    response = client.post(
        "/webauthn/login/finish/",
        data=json.dumps({"id": "x", "response": {}}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert response.json() == {"error": "authentication_failed"}


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
    """ZT-002: per-email throttle on login_start. The 4th call within the
    window (rate 3/m, keyed on the JSON-body email) is mapped to HTTP 429
    with a Retry-After header by RatelimitTo429Middleware.

    The email is read from the JSON body, not request.POST. This asserts
    the key function parses the body (otherwise every login would share one
    'no-email' bucket and this test would still pass for the wrong reason),
    so we also confirm a *different* email is not throttled.
    """
    cache.clear()  # Redis counters persist across runs; start clean.

    def hit(email: str):
        return client.post(
            "/webauthn/login/start/",
            data=json.dumps({"email": email}),
            content_type="application/json",
        )

    # 3 allowed (each 400, unknown email), 4th over the per-email cap.
    for _ in range(3):
        assert hit("flood@example.com").status_code == 400
    blocked = hit("flood@example.com")
    assert blocked.status_code == 429
    assert blocked["Retry-After"] == "60"

    # A different email is its own bucket, not collateral-damaged. Proves the
    # key is per-email (parsed from the body), not a single global bucket.
    assert hit("other@example.com").status_code == 400


# ---- usernameless sign-in views --------------------------------------------


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
def test_login_start_usernameless_clears_stale_email_keyed_session(client: Client) -> None:
    """An email-keyed ceremony in progress must not bleed into the
    usernameless start (otherwise finish_authentication_usernameless
    would refuse on `mode mismatch`, which we already test in services).
    """
    session = client.session
    session["webauthn_auth_user"] = "stale-id"
    session.save()

    response = client.post("/webauthn/login/start-usernameless/")
    assert response.status_code == 200
    assert "webauthn_auth_user" not in client.session
    assert client.session.get("webauthn_auth_challenge")


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


@pytest.mark.django_db
def test_cross_flow_email_session_cannot_finish_usernameless(client: Client) -> None:
    """An attacker who somehow got a victim's mid-flight email-keyed session
    cannot pivot to the usernameless finish endpoint: the mode-mismatch
    guard refuses before any crypto runs."""
    user = User.objects.create_user(email="xf@example.com", display_name="X")
    WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"xf-cred",
        public_key=b"pk",
        sign_count=0,
    )
    # Pre-seed an email-keyed session (as if login_start had run).
    session = client.session
    session["webauthn_auth_challenge"] = _b64u(b"victim-challenge")
    session["webauthn_auth_user"] = str(user.id)
    session.save()

    # Attacker submits a usernameless-shaped body with matching userHandle.
    # Mode mismatch must trip before verify_authentication_response.
    with patch(
        "apps.webauthn_auth.services.verify_authentication_response",
    ) as verify:
        response = client.post(
            "/webauthn/login/finish-usernameless/",
            data=json.dumps(
                {
                    "id": _b64u(b"xf-cred"),
                    "response": {"userHandle": _b64u(str(user.id))},
                },
            ),
            content_type="application/json",
        )

    assert response.status_code == 400
    assert response.json() == {"error": "authentication_failed"}
    verify.assert_not_called()
    # The session is NOT signed in.
    assert client.session.get("_auth_user_id") is None


@pytest.mark.django_db
def test_cross_flow_usernameless_session_cannot_finish_email_keyed(client: Client) -> None:
    """Reverse cross-flow: a usernameless start sets only the challenge
    (no user_id). The email-keyed finish requires user_id and must refuse,
    again before any crypto runs."""
    user = User.objects.create_user(email="rxf@example.com", display_name="RX")
    WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"rxf-cred",
        public_key=b"pk",
        sign_count=0,
    )
    # Usernameless start: only the challenge is set.
    session = client.session
    session["webauthn_auth_challenge"] = _b64u(b"chall")
    # explicitly no webauthn_auth_user
    session.save()

    with patch(
        "apps.webauthn_auth.services.verify_authentication_response",
    ) as verify:
        response = client.post(
            "/webauthn/login/finish/",
            data=json.dumps({"id": _b64u(b"rxf-cred")}),
            content_type="application/json",
        )

    assert response.status_code == 400
    assert response.json() == {"error": "authentication_failed"}
    verify.assert_not_called()
    assert client.session.get("_auth_user_id") is None
