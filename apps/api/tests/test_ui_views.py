"""Token management UI: ownership, IDOR, superadmin revoke, step-up gate."""

from __future__ import annotations

import base64
import json
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.test import Client, override_settings
from django.utils import timezone

from apps.accounts.models import User
from apps.api.models import ApiToken
from apps.audit.models import AuditAction, AuditLogEntry
from apps.webauthn_auth.models import WebAuthnCredential

from .conftest import MakeToken

LIST = "/super/profile/api-tokens/"
ADMIN_LIST = "/super/api-tokens/"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _step_up(client: Client, user: User, purpose: str = "api_token_create") -> None:
    """Run the step-up endpoints with the signature check mocked."""
    cred, _ = WebAuthnCredential.objects.get_or_create(
        user=user,
        credential_id=f"cred-{user.pk}".encode(),
        defaults={"public_key": b"pk", "sign_count": 0},
    )
    start = client.post(
        "/webauthn/step-up/start/",
        data=json.dumps({"purpose": purpose}),
        content_type="application/json",
    )
    assert start.status_code == 200, start.content
    fake = type("V", (), {"new_sign_count": cred.sign_count + 1})
    with patch("apps.webauthn_auth.services.verify_authentication_response", return_value=fake):
        finish = client.post(
            "/webauthn/step-up/finish/",
            data=json.dumps({"id": _b64u(bytes(cred.credential_id)), "response": {}}),
            content_type="application/json",
        )
    assert finish.status_code == 200, finish.content


def _create(client: Client, **overrides: object):  # noqa: ANN202
    data: dict[str, object] = {
        "name": "laptop agent",
        "scopes": ["findings:read", "findings:write"],
        "lifetime_days": "30",
    }
    data.update(overrides)
    return client.post(LIST, data)


# --- access control on pages ---------------------------------------------------------


@pytest.mark.django_db
def test_anonymous_is_redirected_to_login(client: Client) -> None:
    for url in (LIST, ADMIN_LIST):
        resp = client.get(url)
        assert resp.status_code == 302
        assert resp["Location"].startswith("/super/login/")


@pytest.mark.django_db
def test_list_shows_only_own_tokens(
    client: Client,
    alice: User,
    bob: User,
    make_token: MakeToken,
) -> None:
    mine, _ = make_token(alice, name="alice-agent")
    theirs, _ = make_token(bob, name="bob-agent")
    client.force_login(alice)
    resp = client.get(LIST)
    assert resp.status_code == 200
    body = resp.content.decode()
    assert mine.prefix in body
    assert "alice-agent" in body
    assert theirs.prefix not in body
    assert "bob-agent" not in body
    assert resp["Cache-Control"] == "no-store"


@pytest.mark.django_db
def test_admin_list_is_superadmin_only(
    client: Client,
    alice: User,
    bob: User,
    root: User,
    make_token: MakeToken,
) -> None:
    t, _ = make_token(bob)
    client.force_login(alice)
    assert client.get(ADMIN_LIST).status_code == 403
    client.force_login(root)
    resp = client.get(ADMIN_LIST)
    assert resp.status_code == 200
    assert t.prefix in resp.content.decode()
    assert t.token_hash not in resp.content.decode()


# --- creation + step-up ---------------------------------------------------------------


@pytest.mark.django_db
def test_create_without_step_up_is_refused(client: Client, alice: User) -> None:
    client.force_login(alice)
    resp = _create(client)
    assert resp.status_code == 403
    assert b"Confirm with your passkey" in resp.content
    assert not ApiToken.objects.exists()
    assert not AuditLogEntry.objects.filter(action=AuditAction.API_TOKEN_CREATED).exists()


@pytest.mark.django_db
def test_create_with_step_up_shows_token_once(client: Client, alice: User) -> None:
    client.force_login(alice)
    _step_up(client, alice)
    resp = _create(client)
    assert resp.status_code == 200
    token = ApiToken.objects.get(user=alice)
    body = resp.content.decode()
    assert f"ztops_{token.prefix}_" in body
    assert resp["Cache-Control"] == "no-store"
    raw = body.split(f"ztops_{token.prefix}_", 1)[1][:43]
    full = f"ztops_{token.prefix}_{raw}"

    # The token works against the API...
    api = Client()
    assert api.get("/api/v1/me/", HTTP_AUTHORIZATION=f"Bearer {full}").status_code == 200
    # ...and is never shown again.
    again = client.get(LIST).content.decode()
    assert raw not in again
    assert token.prefix in again
    # Nor stashed in the session for a later request.
    assert raw not in json.dumps(dict(client.session.items()), default=str)

    assert AuditLogEntry.objects.filter(
        action=AuditAction.STEP_UP_VERIFIED,
        actor_user=alice,
    ).exists()
    assert AuditLogEntry.objects.filter(
        action=AuditAction.API_TOKEN_CREATED,
        target_id=str(token.id),
    ).exists()


@pytest.mark.django_db
def test_step_up_grant_is_one_shot(client: Client, alice: User) -> None:
    client.force_login(alice)
    _step_up(client, alice)
    assert _create(client, name="first").status_code == 200
    assert _create(client, name="second").status_code == 403
    assert ApiToken.objects.filter(user=alice).count() == 1


@pytest.mark.django_db
@override_settings(STEP_UP_MAX_AGE_SECONDS=120)
def test_stale_step_up_is_refused(client: Client, alice: User) -> None:
    client.force_login(alice)
    _step_up(client, alice)
    later = timezone.now() + timedelta(seconds=121)
    with patch("apps.webauthn_auth.services.timezone.now", return_value=later):
        assert _create(client).status_code == 403
    assert not ApiToken.objects.exists()


@pytest.mark.django_db
def test_step_up_of_other_user_does_not_carry_over(
    client: Client,
    alice: User,
    bob: User,
) -> None:
    """A grant minted in alice's session cannot be used after the session
    switches to bob (grant is bound to the user id)."""
    client.force_login(alice)
    _step_up(client, alice)
    session = client.session
    grant = session["webauthn_stepup_grant"]
    client.force_login(bob)
    session = client.session
    session["webauthn_stepup_grant"] = grant
    session.save()
    assert _create(client).status_code == 403
    assert not ApiToken.objects.exists()


@pytest.mark.django_db
def test_invalid_form_does_not_burn_grant(client: Client, alice: User) -> None:
    client.force_login(alice)
    _step_up(client, alice)
    assert _create(client, scopes=["review:approve"]).status_code == 400
    assert _create(client, name="<script>").status_code == 400
    assert _create(client, lifetime_days="365").status_code == 400
    assert _create(client).status_code == 200


@pytest.mark.django_db
def test_create_csrf_enforced(alice: User) -> None:
    c = Client(enforce_csrf_checks=True)
    c.force_login(alice)
    assert _create(c).status_code == 403
    assert not ApiToken.objects.exists()


@pytest.mark.django_db
def test_token_name_is_escaped(client: Client, alice: User, make_token: MakeToken) -> None:
    make_token(alice, name="<img src=x onerror=alert(1)>")
    client.force_login(alice)
    body = client.get(LIST).content.decode()
    assert "<img src=x" not in body
    assert "&lt;img src=x" in body


# --- revoke ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_owner_can_revoke(client: Client, alice: User, make_token: MakeToken) -> None:
    token, raw = make_token(alice)
    client.force_login(alice)
    resp = client.post(f"{LIST}{token.id}/revoke/")
    assert resp.status_code == 302
    token.refresh_from_db()
    assert token.revoked_at is not None
    assert token.revoked_by_id == alice.id
    api = Client()
    assert api.get("/api/v1/me/", HTTP_AUTHORIZATION=f"Bearer {raw}").status_code == 401


@pytest.mark.django_db
def test_user_cannot_revoke_others_token_idor(
    client: Client,
    alice: User,
    bob: User,
    make_token: MakeToken,
) -> None:
    token, _ = make_token(bob)
    client.force_login(alice)
    resp = client.post(f"{LIST}{token.id}/revoke/")
    assert resp.status_code == 404
    token.refresh_from_db()
    assert token.revoked_at is None
    assert not AuditLogEntry.objects.filter(action=AuditAction.API_TOKEN_REVOKED).exists()


@pytest.mark.django_db
def test_unknown_token_id_is_404(client: Client, alice: User) -> None:
    client.force_login(alice)
    assert client.post(f"{LIST}00000000-0000-7000-8000-000000000000/revoke/").status_code == 404


@pytest.mark.django_db
def test_superadmin_can_revoke_any_token(
    client: Client,
    bob: User,
    root: User,
    make_token: MakeToken,
) -> None:
    token, _ = make_token(bob)
    client.force_login(root)
    resp = client.post(f"{LIST}{token.id}/revoke/")
    assert resp.status_code == 302
    assert resp["Location"] == ADMIN_LIST
    token.refresh_from_db()
    assert token.revoked_by_id == root.id
    entry = AuditLogEntry.objects.get(action=AuditAction.API_TOKEN_REVOKED)
    assert entry.actor_user_id == root.id
    assert entry.metadata["owner_id"] == str(bob.id)


@pytest.mark.django_db
def test_revoke_requires_post_and_csrf(alice: User, make_token: MakeToken) -> None:
    token, _ = make_token(alice)
    c = Client(enforce_csrf_checks=True)
    c.force_login(alice)
    assert c.get(f"{LIST}{token.id}/revoke/").status_code == 405
    assert c.post(f"{LIST}{token.id}/revoke/").status_code == 403
    token.refresh_from_db()
    assert token.revoked_at is None


@pytest.mark.django_db
def test_ui_pages_keep_security_headers(client: Client, alice: User) -> None:
    client.force_login(alice)
    resp = client.get(LIST)
    csp = resp["Content-Security-Policy"]
    assert "nonce-" in csp
    assert "unsafe-inline" not in csp
    assert resp["X-Frame-Options"] == "DENY"
    nonce = csp.split("'nonce-", 1)[1].split("'", 1)[0]
    body = resp.content.decode()
    # Every <script>/<style> tag on the page carries the request nonce.
    assert body.count("<script") + body.count("<style") == body.count(f'nonce="{nonce}"')
