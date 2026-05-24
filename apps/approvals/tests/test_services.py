"""Tests for the approval state-machine service functions."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.accounts.models import Role, User
from apps.approvals.models import (
    ApprovableAction,
    ApprovalState,
)
from apps.approvals.services import (
    _HANDLERS,
    ApprovalError,
    approve,
    deny,
    register_handler,
    request_approval,
    sweep_expired,
)
from apps.audit.models import AuditAction, AuditLogEntry


def _make_superadmin(email: str) -> User:
    return User.objects.create_user(email=email, display_name="X", role=Role.SUPERADMIN)


def _make_regular(email: str) -> User:
    return User.objects.create_user(email=email, display_name="R", role=Role.REGULAR)


# ---- request_approval ----------------------------------------------------


@pytest.mark.django_db
def test_request_approval_requires_superadmin() -> None:
    user = _make_regular("nope@example.com")
    with pytest.raises(ApprovalError, match="superadmins"):
        request_approval(
            action=ApprovableAction.REGISTER_SUPERADMIN,
            payload={},
            requested_by=user,
        )


@pytest.mark.django_db
def test_request_approval_emits_audit_entry() -> None:
    user = _make_superadmin("emit@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={"slug": "a"},
        requested_by=user,
    )
    assert AuditLogEntry.objects.filter(
        action=AuditAction.APPROVAL_REQUESTED.value,
        target_id=str(approval.id),
    ).exists()


# ---- approve -------------------------------------------------------------


@pytest.mark.django_db
def test_approve_rejects_non_superadmin() -> None:
    requester = _make_superadmin("r@example.com")
    approver = _make_regular("notadmin@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=requester,
    )
    with pytest.raises(ApprovalError, match="superadmins"):
        approve(approval, by=approver)


@pytest.mark.django_db
def test_approve_rejects_self_at_app_layer() -> None:
    user = _make_superadmin("self@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=user,
    )
    with pytest.raises(ApprovalError, match="own"):
        approve(approval, by=user)


@pytest.mark.django_db
def test_approve_marks_executed_when_handler_registered() -> None:
    requester = _make_superadmin("rr@example.com")
    approver = _make_superadmin("aa@example.com")

    received: list[dict] = []

    @register_handler("test_action_executed")
    def _handler(payload: dict) -> None:
        received.append(payload)

    try:
        approval = request_approval(
            action="test_action_executed",
            payload={"k": "v"},
            requested_by=requester,
        )
        result = approve(approval, by=approver)
        assert result.state == ApprovalState.EXECUTED.value
        assert received == [{"k": "v"}]
    finally:
        _HANDLERS.pop("test_action_executed", None)


@pytest.mark.django_db
def test_approve_marks_failed_when_no_handler() -> None:
    requester = _make_superadmin("rh@example.com")
    approver = _make_superadmin("ah@example.com")
    approval = request_approval(
        action="test_action_no_handler",
        payload={},
        requested_by=requester,
    )
    # No handler registered for "test_action_no_handler" — approve still
    # transitions through APPROVED → FAILED with a clear execution_error.
    result = approve(approval, by=approver)
    assert result.state == ApprovalState.FAILED.value
    assert "no handler" in result.execution_error.lower()


@pytest.mark.django_db
def test_approve_marks_failed_when_handler_raises() -> None:
    requester = _make_superadmin("rf@example.com")
    approver = _make_superadmin("af@example.com")

    @register_handler("test_action_boom")
    def _boom(_payload: dict) -> None:
        msg = "handler exploded"
        raise RuntimeError(msg)

    try:
        approval = request_approval(
            action="test_action_boom",
            payload={},
            requested_by=requester,
        )
        result = approve(approval, by=approver)
        assert result.state == ApprovalState.FAILED.value
        assert "exploded" in result.execution_error
    finally:
        _HANDLERS.pop("test_action_boom", None)


@pytest.mark.django_db
def test_approve_rejects_already_terminal_approval() -> None:
    requester = _make_superadmin("ar@example.com")
    approver = _make_superadmin("av@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=requester,
    )
    approval.state = ApprovalState.DENIED.value
    approval.save(update_fields=["state"])

    with pytest.raises(ApprovalError, match="already"):
        approve(approval, by=approver)


@pytest.mark.django_db
def test_approve_expires_an_already_expired_pending_approval() -> None:
    requester = _make_superadmin("er@example.com")
    approver = _make_superadmin("ev@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=requester,
    )
    approval.expires_at = timezone.now() - timedelta(seconds=1)
    approval.save(update_fields=["expires_at"])

    with pytest.raises(ApprovalError, match="expired"):
        approve(approval, by=approver)
    approval.refresh_from_db()
    assert approval.state == ApprovalState.EXPIRED.value


# ---- deny ----------------------------------------------------------------


@pytest.mark.django_db
def test_deny_transitions_to_denied_with_reason() -> None:
    requester = _make_superadmin("dr@example.com")
    denier = _make_superadmin("dn@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=requester,
    )
    result = deny(approval, by=denier, reason="payload looks fishy")
    assert result.state == ApprovalState.DENIED.value
    assert result.denied_reason == "payload looks fishy"
    assert result.denied_by_id == denier.id


@pytest.mark.django_db
def test_deny_rejects_empty_reason() -> None:
    requester = _make_superadmin("der@example.com")
    denier = _make_superadmin("ded@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=requester,
    )
    with pytest.raises(ApprovalError, match="reason"):
        deny(approval, by=denier, reason="   ")


@pytest.mark.django_db
def test_deny_rejects_self() -> None:
    user = _make_superadmin("ds@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=user,
    )
    with pytest.raises(ApprovalError, match="own"):
        deny(approval, by=user, reason="why not")


# ---- sweep_expired -------------------------------------------------------


@pytest.mark.django_db
def test_sweep_expired_transitions_only_pending_past_due() -> None:
    requester = _make_superadmin("sr@example.com")
    p_fresh = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=requester,
    )
    p_stale = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=requester,
    )
    p_stale.expires_at = timezone.now() - timedelta(seconds=1)
    p_stale.save(update_fields=["expires_at"])

    # Already-terminal rows must not be touched even if their expires_at is past.
    p_done = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=requester,
    )
    p_done.state = ApprovalState.DENIED.value
    p_done.expires_at = timezone.now() - timedelta(seconds=1)
    p_done.save(update_fields=["state", "expires_at"])

    n = sweep_expired()
    assert n == 1

    p_fresh.refresh_from_db()
    p_stale.refresh_from_db()
    p_done.refresh_from_db()
    assert p_fresh.state == ApprovalState.PENDING.value
    assert p_stale.state == ApprovalState.EXPIRED.value
    assert p_done.state == ApprovalState.DENIED.value  # unchanged
