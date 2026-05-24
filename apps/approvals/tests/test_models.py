"""Tests for SuperAdminApproval model: DB constraints + helpers."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.accounts.models import Role, User
from apps.approvals.models import (
    ApprovableAction,
    ApprovalState,
    SuperAdminApproval,
    hash_payload,
)


def _make_superadmin(email: str) -> User:
    return User.objects.create_user(email=email, display_name="X", role=Role.SUPERADMIN)


@pytest.mark.django_db
def test_issue_creates_pending_approval_with_payload_hash() -> None:
    user = _make_superadmin("issuer@example.com")
    approval = SuperAdminApproval.issue(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={"slug": "acme", "name": "Acme"},
        requested_by=user,
    )
    assert approval.state == ApprovalState.PENDING.value
    assert approval.payload_hash == hash_payload({"slug": "acme", "name": "Acme"})
    assert approval.expires_at > timezone.now()


@pytest.mark.django_db
def test_hash_payload_is_stable_across_key_order() -> None:
    a = hash_payload({"x": 1, "y": 2})
    b = hash_payload({"y": 2, "x": 1})
    assert a == b


@pytest.mark.django_db
def test_self_approval_blocked_at_db_layer() -> None:
    user = _make_superadmin("self@example.com")
    approval = SuperAdminApproval.issue(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=user,
    )
    with transaction.atomic(), pytest.raises(IntegrityError):
        approval.approved_by = user
        approval.approved_at = timezone.now()
        approval.save(update_fields=["approved_by", "approved_at"])


@pytest.mark.django_db
def test_self_denial_blocked_at_db_layer() -> None:
    user = _make_superadmin("selfden@example.com")
    approval = SuperAdminApproval.issue(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=user,
    )
    with transaction.atomic(), pytest.raises(IntegrityError):
        approval.denied_by = user
        approval.denied_at = timezone.now()
        approval.save(update_fields=["denied_by", "denied_at"])


@pytest.mark.django_db
def test_distinct_approver_is_allowed_by_db_layer() -> None:
    requester = _make_superadmin("req@example.com")
    approver = _make_superadmin("app@example.com")
    approval = SuperAdminApproval.issue(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=requester,
    )
    approval.approved_by = approver
    approval.approved_at = timezone.now()
    approval.save(update_fields=["approved_by", "approved_at"])  # must not raise


@pytest.mark.django_db
def test_is_pending_and_is_terminal_helpers() -> None:
    user = _make_superadmin("h@example.com")
    approval = SuperAdminApproval.issue(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=user,
    )
    assert approval.is_pending is True
    assert approval.is_terminal is False

    approval.state = ApprovalState.EXECUTED.value
    approval.save(update_fields=["state"])
    assert approval.is_pending is False
    assert approval.is_terminal is True


@pytest.mark.django_db
def test_has_expired_helper() -> None:
    user = _make_superadmin("exp@example.com")
    approval = SuperAdminApproval.issue(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=user,
        ttl_seconds=1,
    )
    approval.expires_at = timezone.now() - timedelta(seconds=1)
    approval.save(update_fields=["expires_at"])
    assert approval.has_expired is True
