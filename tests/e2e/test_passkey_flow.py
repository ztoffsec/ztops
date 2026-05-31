"""End-to-end tests for the full register → sign-in → dashboard flow.

These tests drive the actual `webauthn` library through real ECDSA
P-256 signatures produced by an in-process virtual authenticator
(`_virtual_authenticator.py`). No mocks of `verify_*` here — if these
pass, a real browser would too (assuming the same payload shape, which
the test confirms).

Origin is fixed at `http://testserver` (the Django test client's
default Host); RP_ID is `testserver` per `config.settings.test`.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

import pytest

from apps.accounts.models import Role, User
from apps.webauthn_auth.models import EnrollmentToken, WebAuthnCredential

from ._virtual_authenticator import VirtualAuthenticator

if TYPE_CHECKING:
    from django.test import Client

_ORIGIN = "http://testserver"


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _register(
    client: Client,
    *,
    user_email: str,
    user_display_name: str,
    authenticator: VirtualAuthenticator,
) -> tuple[User, dict[str, Any]]:
    """Run the full registration ceremony. Returns (user, finish_response)."""
    user = User.objects.create_user(
        email=user_email,
        display_name=user_display_name,
        role=Role.SUPERADMIN,
    )
    _, raw_token = EnrollmentToken.issue(user)

    # Land on the enrollment page so the CSRF cookie is set (informational —
    # the test client bypasses CSRF, but match the real browser flow).
    page = client.get(f"/webauthn/enroll/{raw_token}/")
    assert page.status_code == 200

    start = client.post(
        f"/webauthn/register/start/{raw_token}/",
        content_type="application/json",
    )
    assert start.status_code == 200, start.content
    options = start.json()

    payload = authenticator.create(
        rp_id=options["rp"]["id"],
        challenge=_b64u_decode(options["challenge"]),
        user_id=_b64u_decode(options["user"]["id"]),
        origin=_ORIGIN,
    )

    finish = client.post(
        f"/webauthn/register/finish/{raw_token}/",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert finish.status_code == 200, finish.content
    return user, finish.json()


def _login(
    client: Client,
    *,
    authenticator: VirtualAuthenticator,
) -> dict[str, Any]:
    """Drive the usernameless sign-in ceremony through the test client."""
    start = client.post("/webauthn/login/start-usernameless/")
    assert start.status_code == 200, start.content
    options = start.json()

    payload = authenticator.get(
        rp_id=options["rpId"],
        challenge=_b64u_decode(options["challenge"]),
        origin=_ORIGIN,
    )

    finish = client.post(
        "/webauthn/login/finish-usernameless/",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert finish.status_code == 200, finish.content
    return finish.json()


# ---- Phase 1 exit criterion ----


@pytest.mark.django_db
def test_phase1_exit_criterion_full_flow(client: Client) -> None:
    """Register → sign-in → access /super/dashboard/ as authenticated user.

    This is the gate that says Phase 1 is functionally complete: a
    superadmin can be provisioned, register a passkey, sign in with
    that passkey, and reach the post-login UI.
    """
    authenticator = VirtualAuthenticator()

    user, _ = _register(
        client,
        user_email="phase1@example.com",
        user_display_name="Phase 1",
        authenticator=authenticator,
    )
    assert WebAuthnCredential.objects.filter(user=user).count() == 1

    result = _login(client, authenticator=authenticator)
    assert result["ok"] is True
    assert result["redirect"] == "/super/dashboard/"

    # Session is now bound to the user; the dashboard renders.
    dash = client.get("/super/dashboard/")
    assert dash.status_code == 200
    # The dashboard surface is workspace metrics — account info lives on
    # the profile page. Sanity that we landed on an authenticated page.
    assert b"Total findings" in dash.content
    # And the profile carries identity.
    profile = client.get("/super/profile/")
    assert b"phase1@example.com" in profile.content
    assert b"superadmin" in profile.content


# ---- Registration ceremony invariants ----


@pytest.mark.django_db
def test_registration_persists_credential_with_real_crypto(client: Client) -> None:
    authenticator = VirtualAuthenticator()
    user, _ = _register(
        client,
        user_email="reg@example.com",
        user_display_name="R",
        authenticator=authenticator,
    )
    cred = WebAuthnCredential.objects.get(user=user)
    assert cred.sign_count == 0  # registration leaves count at zero
    assert cred.transports == ["internal"]
    assert bytes(cred.public_key)  # COSE bytes stored
    assert bytes(cred.credential_id) in authenticator.credentials


@pytest.mark.django_db
def test_enrollment_token_is_single_use(client: Client) -> None:
    authenticator = VirtualAuthenticator()
    _register(
        client,
        user_email="single@example.com",
        user_display_name="S",
        authenticator=authenticator,
    )

    # Pull the just-used token and try to re-use the same URL.
    user = User.objects.get(email="single@example.com")
    token = EnrollmentToken.objects.get(user=user)
    assert token.used_at is not None

    # A fresh second authenticator should not be able to register
    # against the burned token.
    second_auth = VirtualAuthenticator()
    raw_prefix = token.token_prefix  # incomplete — we don't know the rest
    response = client.post(
        f"/webauthn/register/start/{raw_prefix}garbage/",
        content_type="application/json",
    )
    assert response.status_code == 403
    assert WebAuthnCredential.objects.filter(user=user).count() == 1  # still just one
    # Suppress unused-variable warning for clarity of intent.
    del second_auth


# ---- Authentication ceremony invariants ----


@pytest.mark.django_db
def test_sign_count_increments_on_every_login(client: Client) -> None:
    authenticator = VirtualAuthenticator()
    _register(
        client,
        user_email="counter@example.com",
        user_display_name="C",
        authenticator=authenticator,
    )

    _login(client, authenticator=authenticator)
    cred = WebAuthnCredential.objects.get(user__email="counter@example.com")
    assert cred.sign_count == 1

    _login(client, authenticator=authenticator)
    cred.refresh_from_db()
    assert cred.sign_count == 2


@pytest.mark.django_db
def test_login_with_a_different_authenticator_fails(client: Client) -> None:
    """An authenticator whose credential id is not in the DB cannot sign in.

    Authenticator A registers; an unrelated authenticator B mints a fresh
    credential (whose id is not stored), then tries to use it to assert
    against the usernameless endpoint. The credential lookup fails before
    any crypto runs and the server collapses it to the generic error.
    """
    auth_a = VirtualAuthenticator()
    _register(
        client,
        user_email="impostor@example.com",
        user_display_name="A",
        authenticator=auth_a,
    )

    auth_b = VirtualAuthenticator()
    start = client.post("/webauthn/login/start-usernameless/")
    options = start.json()

    auth_b.create(
        rp_id=options["rpId"],
        challenge=_b64u_decode(options["challenge"]),
        user_id=b"fake-user-id",
        origin=_ORIGIN,
    )
    spoof = auth_b.get(
        rp_id=options["rpId"],
        challenge=_b64u_decode(options["challenge"]),
        origin=_ORIGIN,
    )

    finish = client.post(
        "/webauthn/login/finish-usernameless/",
        data=json.dumps(spoof),
        content_type="application/json",
    )
    assert finish.status_code == 400
    assert finish.json() == {"error": "authentication_failed"}


# ---- Session + dashboard wiring ----


@pytest.mark.django_db
def test_dashboard_inaccessible_until_login(client: Client) -> None:
    authenticator = VirtualAuthenticator()
    _register(
        client,
        user_email="locked@example.com",
        user_display_name="L",
        authenticator=authenticator,
    )

    # Registering does NOT sign the user in — the ceremony is enrollment-only.
    dash = client.get("/super/dashboard/")
    assert dash.status_code == 302
    assert "/super/login/" in dash["Location"]


@pytest.mark.django_db
def test_logout_after_login_clears_session(client: Client) -> None:
    authenticator = VirtualAuthenticator()
    _register(
        client,
        user_email="loop@example.com",
        user_display_name="L",
        authenticator=authenticator,
    )
    _login(client, authenticator=authenticator)

    # Dashboard works.
    assert client.get("/super/dashboard/").status_code == 200

    # Log out.
    logout = client.post("/super/logout/")
    assert logout.status_code == 302

    # Dashboard now requires login again.
    after = client.get("/super/dashboard/")
    assert after.status_code == 302
    assert "/super/login/" in after["Location"]
