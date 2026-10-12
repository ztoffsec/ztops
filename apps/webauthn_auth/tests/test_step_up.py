"""Step-up (fresh passkey assertion for a signed-in user) endpoints + grant."""

from __future__ import annotations

import base64
import json
from unittest.mock import patch

import pytest
from django.contrib.sessions.backends.cache import SessionStore
from django.core.cache import cache
from django.test import Client, RequestFactory, override_settings
from django.utils import timezone

from apps.accounts.models import User
from apps.audit.models import AuditAction, AuditLogEntry
from apps.webauthn_auth.models import WebAuthnCredential
from apps.webauthn_auth.services import consume_step_up

START = "/webauthn/step-up/start/"
FINISH = "/webauthn/step-up/finish/"
PURPOSE = "api_token_create"


def _b64u(data: bytes | str) -> str:
    raw = data.encode() if isinstance(data, str) else data
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture
def alice(db: None) -> User:
    u = User.objects.create_user(email="su-alice@example.com", display_name="A")
    WebAuthnCredential.objects.create(user=u, credential_id=b"alice-cred", public_key=b"pk")
    return u


@pytest.fixture
def bob(db: None) -> User:
    u = User.objects.create_user(email="su-bob@example.com", display_name="B")
    WebAuthnCredential.objects.create(user=u, credential_id=b"bob-cred", public_key=b"pk")
    return u


def _start(client: Client, purpose: str = PURPOSE):  # noqa: ANN202
    return client.post(
        START, data=json.dumps({"purpose": purpose}), content_type="application/json"
    )


def _finish(client: Client, cred_id: bytes, user_handle: str | None = None, ok: bool = True):  # noqa: ANN202, FBT001, FBT002
    fake = type("V", (), {"new_sign_count": 1})
    resp_body: dict[str, object] = {}
    if user_handle is not None:
        resp_body["userHandle"] = _b64u(user_handle)
    kwargs = {"return_value": fake} if ok else {"side_effect": ValueError("bad sig")}
    with patch("apps.webauthn_auth.services.verify_authentication_response", **kwargs):
        return client.post(
            FINISH,
            data=json.dumps({"id": _b64u(cred_id), "response": resp_body}),
            content_type="application/json",
        )


@pytest.mark.django_db
def test_requires_session(client: Client) -> None:
    assert _start(client).status_code == 401
    assert client.post(FINISH, data="{}", content_type="application/json").status_code == 401


@pytest.mark.django_db
def test_get_not_allowed(client: Client, alice: User) -> None:
    client.force_login(alice)
    assert client.get(START).status_code == 405
    assert client.get(FINISH).status_code == 405


@pytest.mark.django_db
def test_csrf_enforced(alice: User) -> None:
    c = Client(enforce_csrf_checks=True)
    c.force_login(alice)
    assert _start(c).status_code == 403


@pytest.mark.django_db
def test_unknown_purpose_rejected(client: Client, alice: User) -> None:
    client.force_login(alice)
    resp = _start(client, purpose="superadmin_anything")
    assert resp.status_code == 400
    assert resp.json() == {"error": "step_up_failed"}


@pytest.mark.django_db
def test_start_offers_only_own_credentials_and_requires_uv(
    client: Client,
    alice: User,
    bob: User,
) -> None:
    client.force_login(alice)
    opts = _start(client).json()
    assert [c["id"] for c in opts["allowCredentials"]] == [_b64u(b"alice-cred")]
    assert opts["userVerification"] == "required"


@pytest.mark.django_db
def test_finish_success_records_grant_and_audits(client: Client, alice: User) -> None:
    client.force_login(alice)
    _start(client)
    resp = _finish(client, b"alice-cred", user_handle=str(alice.id))
    assert resp.status_code == 200
    grant = client.session["webauthn_stepup_grant"]
    assert grant["user"] == str(alice.id)
    assert grant["purpose"] == PURPOSE
    entry = AuditLogEntry.objects.get(action=AuditAction.STEP_UP_VERIFIED)
    assert entry.actor_user_id == alice.id
    assert entry.metadata == {"purpose": PURPOSE}


@pytest.mark.django_db
def test_other_users_credential_rejected(client: Client, alice: User, bob: User) -> None:
    client.force_login(alice)
    _start(client)
    resp = _finish(client, b"bob-cred")
    assert resp.status_code == 400
    assert resp.json() == {"error": "step_up_failed"}
    assert "webauthn_stepup_grant" not in client.session


@pytest.mark.django_db
def test_user_handle_mismatch_rejected(client: Client, alice: User, bob: User) -> None:
    client.force_login(alice)
    _start(client)
    assert _finish(client, b"alice-cred", user_handle=str(bob.id)).status_code == 400


@pytest.mark.django_db
def test_bad_signature_rejected(client: Client, alice: User) -> None:
    client.force_login(alice)
    _start(client)
    assert _finish(client, b"alice-cred", ok=False).status_code == 400
    assert "webauthn_stepup_grant" not in client.session


@pytest.mark.django_db
def test_finish_without_start_rejected_and_challenge_single_use(
    client: Client,
    alice: User,
) -> None:
    client.force_login(alice)
    assert _finish(client, b"alice-cred").status_code == 400
    _start(client)
    assert _finish(client, b"alice-cred").status_code == 200
    # Replaying the finish (challenge already consumed) fails.
    assert _finish(client, b"alice-cred").status_code == 400


@pytest.mark.django_db
def test_ceremony_started_by_one_user_cannot_finish_as_another(
    client: Client,
    alice: User,
    bob: User,
) -> None:
    client.force_login(alice)
    _start(client)
    state = client.session["webauthn_stepup_challenge"]
    client.force_login(bob)
    s = client.session
    s["webauthn_stepup_challenge"] = state
    s.save()
    assert _finish(client, b"bob-cred").status_code == 400


@pytest.mark.django_db
def test_consume_checks_purpose_and_is_one_shot(alice: User) -> None:
    req = RequestFactory().post("/")
    req.session = SessionStore()
    now = int(timezone.now().timestamp())
    req.session["webauthn_stepup_grant"] = {"user": str(alice.id), "purpose": "other", "at": now}
    assert consume_step_up(alice, req, PURPOSE) is False
    assert "webauthn_stepup_grant" not in req.session  # popped even on mismatch
    req.session["webauthn_stepup_grant"] = {"user": str(alice.id), "purpose": PURPOSE, "at": now}
    assert consume_step_up(alice, req, PURPOSE) is True
    assert consume_step_up(alice, req, PURPOSE) is False


@pytest.mark.django_db
@override_settings(RATELIMIT_ENABLE=True)
def test_step_up_is_rate_limited(client: Client, alice: User) -> None:
    cache.clear()
    client.force_login(alice)
    codes = [_start(client).status_code for _ in range(11)]
    assert codes[:10] == [200] * 10
    assert codes[10] == 429
    cache.clear()
