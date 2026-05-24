"""Approval handlers for actions that mutate the accounts surface.

Currently:
- REGISTER_SUPERADMIN: create a new superadmin User. Triggered by a
  superadmin via /super/users/new/ with role=superadmin; executes once
  a second superadmin approves.
"""

from __future__ import annotations

from typing import Any

from apps.approvals.models import ApprovableAction
from apps.approvals.services import register_handler
from apps.audit.models import AuditAction
from apps.audit.services import audit

from .models import Role, User


@register_handler(ApprovableAction.REGISTER_SUPERADMIN)
def create_superadmin_user(payload: dict[str, Any]) -> None:
    """Create a superadmin user from approval payload.

    Idempotent: if the email already exists, refuses (raises so the
    approval transitions to FAILED with a clear error rather than
    silently no-op).
    """
    email = payload["email"].strip().lower()
    display_name = payload["display_name"]

    if User.objects.filter(email__iexact=email).exists():
        msg = f"User {email!r} already exists; cannot create."
        raise RuntimeError(msg)

    user = User.objects.create_user(
        email=email,
        display_name=display_name,
        role=Role.SUPERADMIN,
    )

    audit(
        action=AuditAction.USER_CREATED,
        target_kind="user",
        target_id=str(user.id),
        target_label=user.email,
        metadata={"role": Role.SUPERADMIN.value, "via": "approval"},
    )
