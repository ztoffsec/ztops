"""AuditLogEntry — the append-only forensic record.

Per hardening requirement #11, this table is immutable at the
database layer. The migration that follows the model creation installs
Postgres triggers on UPDATE / DELETE / TRUNCATE that RAISE EXCEPTION
unconditionally — UPDATE/DELETE attempted from any user, including
postgres / a future buggy view, will fail loud.

Allowlist discipline for the `metadata` JSON: callers MUST NOT put
secrets, finding bodies, raw tokens, raw passkey bytes, or attachment
contents in there. Safe entries: user IDs, action params that are
already public (e.g. slugs), counts.
"""

from __future__ import annotations

from typing import ClassVar

from django.db import models

from core.security.uuids import uuid7


class AuditAction(models.TextChoices):
    """Closed set of action codes. New entries land here when a new event
    fires. Codes are stable strings — they live in DB rows and external
    SIEM ingest forever."""

    # Account lifecycle
    USER_CREATED = "user_created", "User Created"
    SUPERADMIN_TOKEN_ISSUED = "superadmin_token_issued", "Superadmin Token Issued"
    SUPERADMIN_ROLE_GRANTED = "superadmin_role_granted", "Superadmin Role Granted"

    # Credential lifecycle
    CREDENTIAL_REGISTERED = "credential_registered", "Credential Registered"

    # Auth events
    USER_SIGNED_IN = "user_signed_in", "User Signed In"
    USER_SIGNED_OUT = "user_signed_out", "User Signed Out"

    # Finding lifecycle (destructive ops only — creation/edit aren't
    # privileged enough to warrant audit churn).
    FINDING_DELETED = "finding_deleted", "Finding Deleted"

    # Review workflow — each transition emits exactly one row so the
    # state-machine history is fully reconstructable from the audit log.
    REVIEW_STARTED = "review_started", "Review Started"
    REVIEW_APPROVED = "review_approved", "Review Approved"
    REVIEW_REJECTED = "review_rejected", "Review Rejected"
    REVIEW_RESUBMITTED = "review_resubmitted", "Review Resubmitted"

    # Approval lifecycle (state-machine events, populated in Paso 2)
    APPROVAL_REQUESTED = "approval_requested", "Approval Requested"
    APPROVAL_APPROVED = "approval_approved", "Approval Approved"
    APPROVAL_DENIED = "approval_denied", "Approval Denied"
    APPROVAL_EXECUTED = "approval_executed", "Approval Executed"
    APPROVAL_EXPIRED = "approval_expired", "Approval Expired"


class AuditLogEntry(models.Model):
    """One row per privileged or security-relevant action.

    `actor_*` snapshot fields preserve identity even if the User row is
    later deleted — useful when forensic search outlives account
    cleanup.
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    action = models.CharField(
        max_length=50,
        choices=AuditAction.choices,
        db_index=True,
    )

    # Actor — who initiated the action. The FK has `db_constraint=False`
    # and `on_delete=DO_NOTHING` because the immutability trigger would
    # reject the UPDATE that SET_NULL would issue on user deletion. The
    # `actor_email` snapshot is the canonical record; this column is
    # an ergonomic accessor that may become dangling.
    actor_user = models.ForeignKey(
        "accounts.User",
        on_delete=models.DO_NOTHING,
        db_constraint=False,
        null=True,
        blank=True,
        related_name="audit_entries",
    )
    actor_email = models.CharField(max_length=255, blank=True)
    actor_ip = models.GenericIPAddressField(null=True, blank=True)
    actor_user_agent = models.CharField(max_length=500, blank=True)

    # Target — what was acted upon. Generic FK by string id so any model can fit.
    target_kind = models.CharField(max_length=50, blank=True)
    target_id = models.CharField(max_length=100, blank=True)
    target_label = models.CharField(max_length=255, blank=True)

    # Allowlisted structured detail. Schemaless on purpose; per-action
    # shape is documented in the emit-site comments, not enforced here.
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("-timestamp",)
        verbose_name_plural = "Audit log entries"
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["-timestamp", "action"], name="audit_ts_action_idx"),
            models.Index(fields=["actor_user", "-timestamp"], name="audit_actor_ts_idx"),
            models.Index(fields=["target_kind", "target_id"], name="audit_target_idx"),
        ]

    def __str__(self) -> str:
        actor = self.actor_email or "system"
        return f"{self.timestamp:%Y-%m-%dT%H:%M:%S} {self.action} actor={actor}"
