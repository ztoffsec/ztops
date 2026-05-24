"""SuperAdminApproval — the two-person-rule state machine.

A pending approval is a request from one superadmin (`requested_by`)
to perform a privileged action that another superadmin (`approved_by`)
must endorse before it runs. Self-endorsement is structurally
impossible: the model carries a CHECK constraint at the DB layer.

Payload semantics: `payload` is action-specific JSON. `payload_hash`
is a stable SHA-256 over the canonical encoding so any tampering
between request-time and execution-time is detectable in audit
correlation.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any, ClassVar

from django.db import models
from django.utils import timezone

from core.security.uuids import uuid7

DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24h window per project spec


class ApprovableAction(models.TextChoices):
    """Closed set of action codes that the two-person rule gates.

    Adding an entry here without a matching handler in
    apps/approvals/services.py:_HANDLERS is allowed at Paso 2 (handlers
    land in Paso 4); but a request for an unknown action will be
    refused at execution time once handlers exist.
    """

    REGISTER_SUPERADMIN = "register_superadmin", "Register Superadmin"
    REVOKE_USER = "revoke_user", "Revoke User"


class ApprovalState(models.TextChoices):
    """States a SuperAdminApproval row can occupy.

    Transitions are validated in apps/approvals/services.py — the
    model does not enforce them with constraints, only the immutable
    facts (self-approval impossible, request timestamps monotonic).
    """

    PENDING = "pending", "Pending"
    APPROVED = "approved", "Approved"
    DENIED = "denied", "Denied"
    EXECUTED = "executed", "Executed"
    EXPIRED = "expired", "Expired"
    FAILED = "failed", "Failed"


TERMINAL_STATES: frozenset[str] = frozenset(
    {
        ApprovalState.DENIED.value,
        ApprovalState.EXECUTED.value,
        ApprovalState.EXPIRED.value,
        ApprovalState.FAILED.value,
    },
)


def hash_payload(payload: dict[str, Any]) -> str:
    """Stable SHA-256 over the canonical JSON encoding of `payload`."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SuperAdminApproval(models.Model):
    """One row per two-person-rule request."""

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    requested_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.PROTECT,
        related_name="approvals_requested",
    )
    action = models.CharField(max_length=50, choices=ApprovableAction.choices)
    payload = models.JSONField()
    payload_hash = models.CharField(max_length=64)

    state = models.CharField(
        max_length=20,
        choices=ApprovalState.choices,
        default=ApprovalState.PENDING,
        db_index=True,
    )

    approved_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="approvals_approved",
    )
    approved_at = models.DateTimeField(null=True, blank=True)

    denied_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="approvals_denied",
    )
    denied_at = models.DateTimeField(null=True, blank=True)
    denied_reason = models.CharField(max_length=500, blank=True)

    executed_at = models.DateTimeField(null=True, blank=True)
    execution_error = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        constraints: ClassVar[list[models.BaseConstraint]] = [
            # DB-enforced: cannot approve your own request.
            models.CheckConstraint(
                condition=models.Q(approved_by__isnull=True)
                | ~models.Q(approved_by=models.F("requested_by")),
                name="approvals_no_self_approval",
            ),
            # DB-enforced: cannot deny your own request either.
            models.CheckConstraint(
                condition=models.Q(denied_by__isnull=True)
                | ~models.Q(denied_by=models.F("requested_by")),
                name="approvals_no_self_denial",
            ),
        ]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["state", "-created_at"], name="approvals_state_ts_idx"),
            models.Index(fields=["requested_by", "-created_at"], name="approvals_req_ts_idx"),
        ]

    def __str__(self) -> str:
        return f"Approval({self.action}, {self.state}, by={self.requested_by_id})"

    # ---- query helpers --------------------------------------------------

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def is_pending(self) -> bool:
        return self.state == ApprovalState.PENDING.value

    @property
    def has_expired(self) -> bool:
        return self.expires_at <= timezone.now()

    # ---- factory --------------------------------------------------------

    @classmethod
    def issue(
        cls,
        *,
        action: str | ApprovableAction,
        payload: dict[str, Any],
        requested_by: Any,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> SuperAdminApproval:
        """Create a pending approval. Does NOT validate that `requested_by`
        is a superadmin — services.request_approval() owns that policy
        check; this is the dumb persistence layer.
        """
        return cls.objects.create(
            action=str(action),
            payload=payload,
            payload_hash=hash_payload(payload),
            requested_by=requested_by,
            expires_at=timezone.now() + timedelta(seconds=ttl_seconds),
        )
