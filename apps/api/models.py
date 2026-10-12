"""ApiToken — a scoped, short-lived bearer credential for agent access.

Storage rules (SECURITY.md "API tokens"):

- The raw token (``ztops_<prefix>_<secret>``) is shown once at creation and
  never stored. Only ``prefix`` (public lookup key) and ``token_hash``
  (argon2id PHC string of the full raw token) are persisted.
- Lifetime: default ``settings.API_TOKEN_DEFAULT_LIFETIME_DAYS`` (30), hard
  max ``MAX_LIFETIME`` (90 days), enforced in code AND by a DB check.
- Idle expiry: a token unused for ``settings.API_TOKEN_IDLE_TIMEOUT_DAYS`` is
  rejected even before ``expires_at``.
- Revocation is instant: authentication re-reads the row on every request.
- Scopes are an allow-listed subset of ``apps.api.scopes.Scope``, enforced in
  code and by a DB check (no empty / unknown scopes).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import ClassVar

from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models import F, Q

from core.security.uuids import uuid7

from .scopes import ALL_SCOPES

MAX_LIFETIME = timedelta(days=90)
NAME_MAX_LEN = 100


class RejectionReason(models.TextChoices):
    """Internal-only reasons a known token was refused. Never sent to clients."""

    HASH_MISMATCH = "hash_mismatch"
    REVOKED = "revoked"
    EXPIRED = "expired"
    IDLE = "idle_expired"
    INACTIVE_USER = "inactive_user"


def idle_timeout() -> timedelta:
    return timedelta(days=int(settings.API_TOKEN_IDLE_TIMEOUT_DAYS))


class ApiToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="api_tokens",
    )
    name = models.CharField(max_length=NAME_MAX_LEN)
    prefix = models.CharField(max_length=16, unique=True, editable=False)
    token_hash = models.CharField(max_length=255, editable=False)
    scopes = ArrayField(models.CharField(max_length=32), default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["user", "-created_at"], name="api_token_user_created_idx"),
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(scopes__contained_by=sorted(ALL_SCOPES)) & Q(scopes__len__gt=0),
                name="api_token_scopes_allowlisted",
            ),
            models.CheckConstraint(
                condition=Q(expires_at__gt=F("created_at"))
                & Q(expires_at__lte=F("created_at") + MAX_LIFETIME),
                name="api_token_lifetime_bounded",
            ),
            models.CheckConstraint(
                condition=Q(revoked_by__isnull=True) | Q(revoked_at__isnull=False),
                name="api_token_revoked_by_needs_revoked_at",
            ),
        ]

    def __str__(self) -> str:
        return f"ApiToken({self.name}, prefix={self.prefix})"

    # --- state -------------------------------------------------------------

    def rejection_reason(self, now: datetime) -> RejectionReason | None:
        """Return why this token must not authenticate at ``now`` (or None)."""
        if self.revoked_at is not None:
            return RejectionReason.REVOKED
        if self.expires_at <= now:
            return RejectionReason.EXPIRED
        last_activity = self.last_used_at or self.created_at
        if last_activity <= now - idle_timeout():
            return RejectionReason.IDLE
        if not self.user.is_active:
            return RejectionReason.INACTIVE_USER
        return None

    def status_label(self, now: datetime) -> str:
        reason = self.rejection_reason(now)
        if reason is None:
            return "active"
        return {
            RejectionReason.REVOKED: "revoked",
            RejectionReason.EXPIRED: "expired",
            RejectionReason.IDLE: "idle-expired",
            RejectionReason.INACTIVE_USER: "owner inactive",
        }.get(reason, "inactive")

    def has_scopes(self, required: frozenset[str] | set[str]) -> bool:
        return set(required).issubset(self.scopes)
