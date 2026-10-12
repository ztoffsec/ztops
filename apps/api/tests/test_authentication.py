"""Bearer authentication chain against GET /api/v1/me/."""

from __future__ import annotations

import logging
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.db import connection
from django.test import Client, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.accounts.models import User
from apps.api.authentication import GENERIC_FAILURE
from apps.api.models import ApiToken
from apps.audit.models import AuditAction, AuditLogEntry

from .conftest import MakeToken

ME = "/api/v1/me/"


def _get(client: Client, auth: str | None, **extra: str):  # noqa: ANN202
    if auth is not None:
        extra["HTTP_AUTHORIZATION"] = auth
    return client.get(ME, **extra)


# --- happy path ---------------------------------------------------------------


@pytest.mark.django_db
def test_valid_token_authenticates(client: Client, alice: User, make_token: MakeToken) -> None:
    token, raw = make_token(alice, scopes=["findings:read", "notes:write"])
    resp = _get(client, f"Bearer {raw}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"] == {
        "id": str(alice.id),
        "email": alice.email,
        "display_name": alice.display_name,
    }
    assert body["token"]["id"] == str(token.id)
    assert body["token"]["prefix"] == token.prefix
    assert body["token"]["scopes"] == ["findings:read", "notes:write"]
    assert body["token"]["expires_at"] == token.expires_at.isoformat()
    # The response never echoes the secret or the hash.
    assert raw not in resp.content.decode()
    assert "token_hash" not in resp.content.decode()


@pytest.mark.django_db
def test_scheme_is_case_insensitive(client: Client, alice: User, make_token: MakeToken) -> None:
    _, raw = make_token(alice)
    assert _get(client, f"bearer {raw}").status_code == 200


# --- rejection matrix (all must be the identical generic 401) ----------------


def _assert_generic_401(resp) -> None:  # noqa: ANN001
    assert resp.status_code == 401
    assert resp.json() == {"detail": GENERIC_FAILURE}
    assert resp["WWW-Authenticate"] == 'Bearer realm="ztops-api"'


@pytest.mark.django_db
def test_revoked_token_rejected(client: Client, alice: User, make_token: MakeToken) -> None:
    token, raw = make_token(alice)
    ApiToken.objects.filter(pk=token.pk).update(revoked_at=timezone.now())
    _assert_generic_401(_get(client, f"Bearer {raw}"))


@pytest.mark.django_db
def test_revocation_is_instant(client: Client, alice: User, make_token: MakeToken) -> None:
    token, raw = make_token(alice)
    assert _get(client, f"Bearer {raw}").status_code == 200
    ApiToken.objects.filter(pk=token.pk).update(revoked_at=timezone.now())
    _assert_generic_401(_get(client, f"Bearer {raw}"))


@pytest.mark.django_db
def test_expired_token_rejected(client: Client, alice: User, make_token: MakeToken) -> None:
    token, raw = make_token(alice, lifetime=timedelta(days=1))
    with patch("apps.api.authentication.timezone.now", return_value=token.expires_at):
        _assert_generic_401(_get(client, f"Bearer {raw}"))


@pytest.mark.django_db
@override_settings(API_TOKEN_IDLE_TIMEOUT_DAYS=14)
def test_idle_token_rejected(client: Client, alice: User, make_token: MakeToken) -> None:
    token, raw = make_token(alice, lifetime=timedelta(days=60))
    later = token.created_at + timedelta(days=15)
    with patch("apps.api.authentication.timezone.now", return_value=later):
        _assert_generic_401(_get(client, f"Bearer {raw}"))


@pytest.mark.django_db
@override_settings(API_TOKEN_IDLE_TIMEOUT_DAYS=14)
def test_recent_use_keeps_token_alive(client: Client, alice: User, make_token: MakeToken) -> None:
    token, raw = make_token(alice, lifetime=timedelta(days=60))
    ApiToken.objects.filter(pk=token.pk).update(last_used_at=token.created_at + timedelta(days=10))
    later = token.created_at + timedelta(days=15)
    with patch("apps.api.authentication.timezone.now", return_value=later):
        assert _get(client, f"Bearer {raw}").status_code == 200


@pytest.mark.django_db
def test_inactive_user_rejected(client: Client, alice: User, make_token: MakeToken) -> None:
    _, raw = make_token(alice)
    alice.is_active = False
    alice.save()
    _assert_generic_401(_get(client, f"Bearer {raw}"))


@pytest.mark.django_db
def test_wrong_secret_with_valid_prefix_rejected(
    client: Client,
    alice: User,
    make_token: MakeToken,
) -> None:
    token, raw = make_token(alice)
    tampered = f"ztops_{token.prefix}_{'A' * 43}"
    assert tampered != raw
    _assert_generic_401(_get(client, f"Bearer {tampered}"))


@pytest.mark.django_db
def test_unknown_prefix_rejected_with_dummy_verify(client: Client) -> None:
    with patch("apps.api.authentication.api_tokens.burn_verify") as burn:
        _assert_generic_401(_get(client, f"Bearer ztops_0123456789ab_{'A' * 43}"))
    burn.assert_called_once()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "header",
    [
        "Bearer",
        "Bearer ",
        "Bearer a b",
        "Bearer not-a-token",
        "Bearer ztops_0123456789ab_short",
        "Token ztops_0123456789ab_" + "A" * 43,
        "Bearer " + "A" * 600,
        "Bearer\tztops_0123456789ab_" + "A" * 43 + " extra",
    ],
)
def test_malformed_headers_rejected_without_argon2(client: Client, header: str) -> None:
    with (
        patch("apps.api.authentication.api_tokens.verify") as verify,
        patch("apps.api.authentication.api_tokens.burn_verify") as burn,
    ):
        _assert_generic_401(_get(client, header))
    verify.assert_not_called()
    burn.assert_not_called()


@pytest.mark.django_db
def test_missing_header_is_401_not_403(client: Client) -> None:
    resp = _get(client, None)
    assert resp.status_code == 401
    assert resp["WWW-Authenticate"] == 'Bearer realm="ztops-api"'


@pytest.mark.django_db
def test_session_cookie_never_authenticates_api(client: Client, alice: User) -> None:
    client.force_login(alice)
    resp = _get(client, None)
    assert resp.status_code == 401


@pytest.mark.django_db
def test_failure_bodies_are_indistinguishable(
    client: Client,
    alice: User,
    make_token: MakeToken,
) -> None:
    revoked, raw_revoked = make_token(alice, name="r")
    ApiToken.objects.filter(pk=revoked.pk).update(revoked_at=timezone.now())
    good, _ = make_token(alice, name="g")
    bodies = {
        _get(client, f"Bearer ztops_0123456789ab_{'A' * 43}").content,  # unknown prefix
        _get(client, f"Bearer ztops_{good.prefix}_{'A' * 43}").content,  # bad secret
        _get(client, f"Bearer {raw_revoked}").content,  # revoked
        _get(client, "Bearer garbage").content,  # malformed
    }
    assert len(bodies) == 1


# --- side effects -------------------------------------------------------------


@pytest.mark.django_db
def test_last_used_at_is_throttled(client: Client, alice: User, make_token: MakeToken) -> None:
    token, raw = make_token(alice)
    assert token.last_used_at is None
    assert _get(client, f"Bearer {raw}").status_code == 200
    token.refresh_from_db()
    first = token.last_used_at
    assert first is not None

    # A second request inside the resolution window issues no UPDATE.
    with CaptureQueriesContext(connection) as ctx:
        assert _get(client, f"Bearer {raw}").status_code == 200
    assert not [q for q in ctx.captured_queries if q["sql"].startswith('UPDATE "api_apitoken"')]
    token.refresh_from_db()
    assert token.last_used_at == first

    # After the window, it is bumped.
    later = first + timedelta(minutes=6)
    with patch("apps.api.authentication.timezone.now", return_value=later):
        assert _get(client, f"Bearer {raw}").status_code == 200
    token.refresh_from_db()
    assert token.last_used_at == later


@pytest.mark.django_db
def test_known_token_failures_are_audited_without_secret(
    client: Client,
    alice: User,
    make_token: MakeToken,
) -> None:
    token, raw = make_token(alice)
    ApiToken.objects.filter(pk=token.pk).update(revoked_at=timezone.now())
    _get(client, f"Bearer {raw}")
    _get(client, f"Bearer ztops_{token.prefix}_{'B' * 43}")
    _get(client, f"Bearer ztops_0123456789ab_{'A' * 43}")  # unknown -> log only

    entries = list(
        AuditLogEntry.objects.filter(action=AuditAction.API_AUTH_FAILED).order_by("timestamp"),
    )
    assert [e.metadata["reason"] for e in entries] == ["revoked", "hash_mismatch"]
    secret = raw.split("_", 2)[2]
    for e in entries:
        assert e.metadata["via"] == "api"
        assert e.metadata["token_id"] == str(token.id)
        assert e.target_id == str(token.id)
        assert e.actor_user_id is None
        assert secret not in str(e.metadata)
        assert "B" * 43 not in str(e.metadata)


@pytest.mark.django_db
def test_successful_auth_writes_no_audit_rows(
    client: Client,
    alice: User,
    make_token: MakeToken,
) -> None:
    _, raw = make_token(alice)
    _get(client, f"Bearer {raw}")
    assert not AuditLogEntry.objects.filter(action=AuditAction.API_AUTH_FAILED).exists()


@pytest.mark.django_db
def test_secret_never_logged(
    client: Client,
    alice: User,
    make_token: MakeToken,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    token, raw = make_token(alice)
    _get(client, f"Bearer {raw}")
    _get(client, f"Bearer ztops_{token.prefix}_{'C' * 43}")
    ApiToken.objects.filter(pk=token.pk).update(revoked_at=timezone.now())
    _get(client, f"Bearer {raw}")
    assert "api auth failed" in caplog.text
    assert raw.split("_", 2)[2] not in caplog.text
    assert "C" * 43 not in caplog.text


# --- failed-auth rate limit (per IP) ------------------------------------------


@pytest.mark.django_db
@override_settings(RATELIMIT_ENABLE=True, API_AUTH_FAILURE_RATE="3/m")
def test_failed_auth_is_rate_limited_per_ip(
    client: Client,
    alice: User,
    make_token: MakeToken,
) -> None:
    _, raw = make_token(alice)
    bad = f"Bearer ztops_0123456789ab_{'A' * 43}"
    statuses = [_get(client, bad).status_code for _ in range(4)]
    assert statuses == [401, 401, 401, 401]  # 4th failure crosses the limit
    blocked = _get(client, bad)
    assert blocked.status_code == 429
    # Once over the limit, the IP is blocked before any verification,
    # including for a valid token (attacker cannot keep guessing).
    with patch("apps.api.authentication.api_tokens.verify") as verify:
        assert _get(client, f"Bearer {raw}").status_code == 429
    verify.assert_not_called()

    # A different client IP is unaffected.
    other = _get(client, f"Bearer {raw}", REMOTE_ADDR="10.9.8.7")
    assert other.status_code == 200


@pytest.mark.django_db
@override_settings(RATELIMIT_ENABLE=True, API_AUTH_FAILURE_RATE="3/m")
def test_successful_auth_does_not_count_toward_failure_limit(
    client: Client,
    alice: User,
    make_token: MakeToken,
) -> None:
    _, raw = make_token(alice)
    for _ in range(10):
        assert _get(client, f"Bearer {raw}").status_code == 200
