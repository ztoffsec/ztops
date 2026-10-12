"""ApiToken model: storage, DB-level constraints, state evaluation."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.db import IntegrityError, transaction
from django.test import override_settings
from django.utils import timezone

from apps.accounts.models import User
from apps.api.models import ApiToken, RejectionReason
from apps.api.scopes import ALL_SCOPES, Scope, normalize_scopes

from .conftest import MakeToken


def test_scope_registry_is_exactly_the_agreed_set() -> None:
    assert {
        "findings:read",
        "findings:write",
        "findings:status",
        "notes:write",
        "attachments:write",
    } == ALL_SCOPES
    # Review approval / superadmin actions are never exposed via API scopes.
    assert not any("review" in s or "admin" in s for s in ALL_SCOPES)


def test_normalize_scopes_rejects_unknown_and_dedupes() -> None:
    assert normalize_scopes(["notes:write", "findings:read", "notes:write"]) == [
        "findings:read",
        "notes:write",
    ]
    with pytest.raises(ValueError, match="unknown scope"):
        normalize_scopes(["findings:read", "review:approve"])


@pytest.mark.django_db
def test_raw_token_is_never_stored(alice: User, make_token: MakeToken) -> None:
    token, raw = make_token(alice)
    secret = raw.split("_", 2)[2]
    row = ApiToken.objects.filter(pk=token.pk).values().get()
    for value in row.values():
        assert secret not in str(value)
        assert raw != str(value)
    assert row["token_hash"].startswith("$argon2id$")


def _insert(user: User, **overrides: object) -> None:
    fields: dict[str, object] = {
        "user": user,
        "name": "x",
        "prefix": "0123456789ab",
        "token_hash": "$argon2id$dummy",
        "scopes": [Scope.FINDINGS_READ.value],
        "expires_at": timezone.now() + timedelta(days=30),
    }
    fields.update(overrides)
    with transaction.atomic():
        ApiToken.objects.create(**fields)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "overrides",
    [
        {"scopes": []},
        {"scopes": ["review:approve"]},
        {"scopes": ["findings:read", "superadmin"]},
        {"expires_at": timezone.now() + timedelta(days=91)},
        {"expires_at": timezone.now() - timedelta(seconds=1)},
    ],
)
def test_db_rejects_invalid_scopes_and_lifetimes(alice: User, overrides: dict[str, object]) -> None:
    with pytest.raises(IntegrityError):
        _insert(alice, **overrides)


@pytest.mark.django_db
def test_db_requires_revoked_at_when_revoked_by_set(alice: User, root: User) -> None:
    with pytest.raises(IntegrityError):
        _insert(alice, revoked_by=root)


@pytest.mark.django_db
def test_prefix_is_unique(alice: User) -> None:
    _insert(alice)
    with pytest.raises(IntegrityError):
        _insert(alice)


@pytest.mark.django_db
def test_max_lifetime_90_days_is_accepted(alice: User) -> None:
    _insert(alice, expires_at=timezone.now() + timedelta(days=89, hours=23))


@pytest.mark.django_db
@override_settings(API_TOKEN_IDLE_TIMEOUT_DAYS=14)
def test_rejection_reasons(alice: User, make_token: MakeToken) -> None:
    token, _ = make_token(alice)
    now = timezone.now()
    assert token.rejection_reason(now) is None
    assert token.status_label(now) == "active"

    assert token.rejection_reason(token.expires_at) == RejectionReason.EXPIRED

    # Idle: never used, created > 14 days ago.
    assert token.rejection_reason(token.created_at + timedelta(days=14)) == RejectionReason.IDLE
    token.last_used_at = token.created_at + timedelta(days=10)
    assert token.rejection_reason(token.created_at + timedelta(days=15)) is None
    assert token.rejection_reason(token.created_at + timedelta(days=24)) == RejectionReason.IDLE

    alice.is_active = False
    assert token.rejection_reason(now) == RejectionReason.INACTIVE_USER

    token.revoked_at = now
    assert token.rejection_reason(now) == RejectionReason.REVOKED
    assert token.status_label(now) == "revoked"


@pytest.mark.django_db
def test_has_scopes(alice: User, make_token: MakeToken) -> None:
    token, _ = make_token(alice, scopes=["findings:read", "notes:write"])
    assert token.has_scopes(frozenset())
    assert token.has_scopes({"findings:read"})
    assert token.has_scopes({"findings:read", "notes:write"})
    assert not token.has_scopes({"findings:write"})
