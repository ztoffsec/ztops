"""Service functions for the two-person-rule state machine.

These are the only sanctioned ways to mutate a SuperAdminApproval row.
Each function validates the transition AND emits the corresponding
audit log entry — callers never have to remember to do both.

Action handlers are registered in `_HANDLERS`. The state machine is
fully exercisable with an empty handler registry — approve() transitions
pending → approved, and execute() either runs a registered handler or
marks the row as failed with "no handler".
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from django.db import transaction
from django.utils import timezone

from apps.audit.models import AuditAction
from apps.audit.services import audit

from .models import ApprovableAction, ApprovalState, SuperAdminApproval

if TYPE_CHECKING:
    from django.http import HttpRequest

    from apps.accounts.models import User


class ApprovalError(Exception):
    """Raised when a state-machine transition is rejected."""


# Action handlers are functions: (payload: dict) -> None. Land in Paso 4.
_HANDLERS: dict[str, Callable[[dict[str, Any]], None]] = {}


def register_handler(
    action: str | ApprovableAction,
) -> Callable[
    [Callable[[dict[str, Any]], None]],
    Callable[[dict[str, Any]], None],
]:
    """Decorator: bind a function as the executor for an action code."""

    def _wrap(fn: Callable[[dict[str, Any]], None]) -> Callable[[dict[str, Any]], None]:
        _HANDLERS[str(action)] = fn
        return fn

    return _wrap


# ---- request -------------------------------------------------------------


def request_approval(
    *,
    action: str | ApprovableAction,
    payload: dict[str, Any],
    requested_by: User,
    request: HttpRequest | None = None,
) -> SuperAdminApproval:
    """Issue a pending approval. Only superadmins may request."""
    if not requested_by.is_superadmin:
        msg = "only superadmins can request approvals"
        raise ApprovalError(msg)

    approval = SuperAdminApproval.issue(
        action=action,
        payload=payload,
        requested_by=requested_by,
    )
    audit(
        action=AuditAction.APPROVAL_REQUESTED,
        actor=requested_by,
        request=request,
        target_kind="approval",
        target_id=str(approval.id),
        target_label=str(action),
        metadata={"action": str(action), "payload_hash": approval.payload_hash},
    )
    return approval


# ---- approve / deny ------------------------------------------------------


def approve(
    approval: SuperAdminApproval,
    *,
    by: User,
    request: HttpRequest | None = None,
) -> SuperAdminApproval:
    """Mark an approval as approved and auto-execute its handler.

    Rejects if:
    - `by` is not a superadmin
    - `by` is the same user who requested
    - `approval` is not in PENDING state
    - `approval` has expired
    """
    _require_superadmin(by)
    _ensure_not_self(approval, by)
    _ensure_pending(approval)

    if approval.has_expired:
        _expire(approval, request=None)
        msg = "approval expired before it could be approved"
        raise ApprovalError(msg)

    with transaction.atomic():
        approval.state = ApprovalState.APPROVED.value
        approval.approved_by = by
        approval.approved_at = timezone.now()
        approval.save(update_fields=["state", "approved_by", "approved_at"])

    audit(
        action=AuditAction.APPROVAL_APPROVED,
        actor=by,
        request=request,
        target_kind="approval",
        target_id=str(approval.id),
        target_label=approval.action,
        metadata={"requested_by": str(approval.requested_by_id)},
    )

    _execute(approval, request=request)
    approval.refresh_from_db()
    return approval


def deny(
    approval: SuperAdminApproval,
    *,
    by: User,
    reason: str,
    request: HttpRequest | None = None,
) -> SuperAdminApproval:
    """Mark an approval as denied. `reason` is required and audited."""
    _require_superadmin(by)
    _ensure_not_self(approval, by)
    _ensure_pending(approval)

    if not reason.strip():
        msg = "deny() requires a non-empty reason"
        raise ApprovalError(msg)

    with transaction.atomic():
        approval.state = ApprovalState.DENIED.value
        approval.denied_by = by
        approval.denied_at = timezone.now()
        approval.denied_reason = reason.strip()[:500]
        approval.save(
            update_fields=["state", "denied_by", "denied_at", "denied_reason"],
        )

    audit(
        action=AuditAction.APPROVAL_DENIED,
        actor=by,
        request=request,
        target_kind="approval",
        target_id=str(approval.id),
        target_label=approval.action,
        metadata={"reason": approval.denied_reason},
    )
    return approval


# ---- execute / expire ----------------------------------------------------


def _execute(approval: SuperAdminApproval, *, request: HttpRequest | None) -> None:
    """Run the registered handler for this approval's action.

    If no handler is registered (Paso 2 state) or the handler raises,
    transition to FAILED and record the error string. Otherwise mark
    as EXECUTED.
    """
    handler = _HANDLERS.get(approval.action)
    if handler is None:
        approval.state = ApprovalState.FAILED.value
        approval.execution_error = "no handler registered for this action"
        approval.save(update_fields=["state", "execution_error"])
        audit(
            action=AuditAction.APPROVAL_EXECUTED,
            request=request,
            target_kind="approval",
            target_id=str(approval.id),
            target_label=approval.action,
            metadata={"outcome": "failed", "reason": "no_handler"},
        )
        return

    try:
        handler(approval.payload)
    except Exception as exc:  # noqa: BLE001 — we deliberately catch broadly
        approval.state = ApprovalState.FAILED.value
        approval.execution_error = repr(exc)[:500]
        approval.save(update_fields=["state", "execution_error"])
        audit(
            action=AuditAction.APPROVAL_EXECUTED,
            request=request,
            target_kind="approval",
            target_id=str(approval.id),
            target_label=approval.action,
            metadata={"outcome": "failed", "error": repr(exc)[:200]},
        )
        return

    approval.state = ApprovalState.EXECUTED.value
    approval.executed_at = timezone.now()
    approval.save(update_fields=["state", "executed_at"])
    audit(
        action=AuditAction.APPROVAL_EXECUTED,
        request=request,
        target_kind="approval",
        target_id=str(approval.id),
        target_label=approval.action,
        metadata={"outcome": "ok"},
    )


def _expire(approval: SuperAdminApproval, *, request: HttpRequest | None) -> None:
    """Mark a single pending approval as expired and audit."""
    approval.state = ApprovalState.EXPIRED.value
    approval.save(update_fields=["state"])
    audit(
        action=AuditAction.APPROVAL_EXPIRED,
        request=request,
        target_kind="approval",
        target_id=str(approval.id),
        target_label=approval.action,
        metadata={},
    )


def sweep_expired() -> int:
    """Transition every pending+expired approval to EXPIRED. Returns count."""
    candidates = list(
        SuperAdminApproval.objects.filter(
            state=ApprovalState.PENDING.value,
            expires_at__lte=timezone.now(),
        ),
    )
    for approval in candidates:
        _expire(approval, request=None)
    return len(candidates)


# ---- guards --------------------------------------------------------------


def _require_superadmin(user: User) -> None:
    if not user.is_superadmin:
        msg = "only superadmins can act on approvals"
        raise ApprovalError(msg)


def _ensure_not_self(approval: SuperAdminApproval, user: User) -> None:
    if approval.requested_by_id == user.id:
        msg = "you cannot approve or deny your own request"
        raise ApprovalError(msg)


def _ensure_pending(approval: SuperAdminApproval) -> None:
    if approval.state != ApprovalState.PENDING.value:
        msg = f"approval is already {approval.state}"
        raise ApprovalError(msg)
