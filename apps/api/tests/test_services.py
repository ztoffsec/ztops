"""Token lifecycle services: creation rules, revocation, audit trail."""

from __future__ import annotations

import json
import logging

import pytest
from django.test import override_settings

from apps.accounts.models import User
from apps.api.models import ApiToken
from apps.api.services import TokenError, create_token, revoke_token
from apps.audit.models import AuditAction, AuditLogEntry

from .conftest import MakeToken


@pytest.mark.django_db
def test_create_token_returns_raw_once_and_audits(alice: User) -> None:
    token, raw = create_token(
        user=alice,
        name="  laptop agent ",
        scopes=["findings:write", "findings:read"],
        lifetime_days=30,
    )
    assert raw.startswith(f"ztops_{token.prefix}_")
    assert token.name == "laptop agent"
    assert token.scopes == ["findings:read", "findings:write"]
    assert (token.expires_at - token.created_at).days in (29, 30)

    entry = AuditLogEntry.objects.get(action=AuditAction.API_TOKEN_CREATED)
    assert entry.actor_user_id == alice.id
    assert entry.target_id == str(token.id)
    assert entry.metadata["token_id"] == str(token.id)
    assert entry.metadata["via"] == "ui"
    # Neither the raw token nor its secret part ever reaches the audit row.
    secret = raw.split("_", 2)[2]
    dumped = json.dumps(entry.metadata) + entry.target_label
    assert secret not in dumped
    assert token.token_hash not in dumped


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("kwargs", "msg"),
    [
        ({"name": "  "}, "name"),
        ({"scopes": []}, "scope"),
        ({"scopes": ["review:approve"]}, "Unknown scope"),
        ({"lifetime_days": 91}, "lifetime"),
        ({"lifetime_days": 0}, "lifetime"),
        ({"lifetime_days": -5}, "lifetime"),
    ],
)
def test_create_token_validation(alice: User, kwargs: dict[str, object], msg: str) -> None:
    params: dict[str, object] = {
        "user": alice,
        "name": "ok",
        "scopes": ["findings:read"],
        "lifetime_days": 30,
    }
    params.update(kwargs)
    with pytest.raises(TokenError, match=msg):
        create_token(**params)  # type: ignore[arg-type]
    assert not ApiToken.objects.exists()


@pytest.mark.django_db
def test_create_token_refused_for_inactive_user(alice: User) -> None:
    alice.is_active = False
    alice.save()
    with pytest.raises(TokenError):
        create_token(user=alice, name="x", scopes=["findings:read"], lifetime_days=7)


@pytest.mark.django_db
@override_settings(API_TOKEN_MAX_ACTIVE_PER_USER=2)
def test_active_token_cap(alice: User, root: User) -> None:
    t1, _ = create_token(user=alice, name="a", scopes=["findings:read"], lifetime_days=7)
    create_token(user=alice, name="b", scopes=["findings:read"], lifetime_days=7)
    with pytest.raises(TokenError, match="active tokens"):
        create_token(user=alice, name="c", scopes=["findings:read"], lifetime_days=7)
    revoke_token(token=t1, actor=alice)
    create_token(user=alice, name="c", scopes=["findings:read"], lifetime_days=7)


@pytest.mark.django_db
def test_revoke_is_atomic_idempotent_and_audited(
    alice: User,
    root: User,
    make_token: MakeToken,
) -> None:
    token, _ = make_token(alice)
    assert revoke_token(token=token, actor=root) is True
    assert revoke_token(token=token, actor=root) is False

    token.refresh_from_db()
    assert token.revoked_at is not None
    assert token.revoked_by_id == root.id

    entries = AuditLogEntry.objects.filter(action=AuditAction.API_TOKEN_REVOKED)
    assert entries.count() == 1
    entry = entries.get()
    assert entry.actor_user_id == root.id
    assert entry.metadata["token_id"] == str(token.id)
    assert entry.metadata["by_superadmin_for_other_user"] is True


@pytest.mark.django_db
def test_no_secret_in_logs(alice: User, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    _, raw = create_token(user=alice, name="x", scopes=["findings:read"], lifetime_days=7)
    assert raw.split("_", 2)[2] not in caplog.text
