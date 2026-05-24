"""WebAuthnCredential and EnrollmentToken models.

`WebAuthnCredential` stores one row per (user, authenticator) pair. A
single user can have many — a phone, a YubiKey, a Touch ID device — and
any of them can authenticate. The model holds only what the ceremony
needs to verify a future assertion: credential_id, public_key,
sign_count, plus optional metadata (transports, AAGUID, user nickname).

`EnrollmentToken` is a one-shot, time-limited grant that lets the holder
register a WebAuthn credential against a specific user. It is issued by
the `register_superadmin_passkey` management command (and later by an
in-app invite flow). The raw token is shown once at creation and
hashed at rest with argon2id. The first 16 chars of the raw token form
a non-secret prefix used as the DB lookup key — so we don't have to
scan every hash on every enrollment request.
"""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import ClassVar

from django.db import models
from django.utils import timezone

from core.security.crypto import hash_token, verify_token
from core.security.uuids import uuid7

# Bandit/ruff treat `*TOKEN* = "..."` as a hardcoded-credential smell, but
# this is a documented public prefix (not a secret) used to namespace the
# random body that follows.
_ENROLLMENT_TOKEN_PREFIX = "zto_enr_"  # noqa: S105  # nosec B105
_ENROLLMENT_TOKEN_TTL_SECONDS = 24 * 60 * 60  # 24 hours
_ENROLLMENT_PREFIX_LEN = 16  # chars of the raw token used as DB lookup key


class WebAuthnCredential(models.Model):
    """A registered WebAuthn credential bound to a user.

    `credential_id` is the raw bytes returned by the authenticator;
    `public_key` is the COSE-encoded public key the verifier checks
    each assertion against. `sign_count` is the authenticator's
    monotonic counter — used to detect cloned credentials (a presented
    response with `sign_count <= stored` is suspect).
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="credentials",
    )
    credential_id = models.BinaryField(unique=True)
    public_key = models.BinaryField()
    sign_count = models.PositiveBigIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    aaguid = models.UUIDField(null=True, blank=True)
    nickname = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["user"], name="webauthn_cred_user_idx"),
        ]

    def __str__(self) -> str:
        label = self.nickname or str(self.id)[:8]
        return f"Credential({label})"


def _generate_raw_token() -> str:
    """Return a fresh URL-safe enrollment token (single source of truth)."""
    return f"{_ENROLLMENT_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


class EnrollmentToken(models.Model):
    """A one-shot grant to register a WebAuthn credential against a user.

    The raw token value is returned by `issue()` and shown to the
    operator once; it is never stored, only the argon2id hash. The
    first 16 characters of the raw token are stored separately as
    `token_prefix` so lookups during enrollment don't have to scan
    every row.
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    user = models.ForeignKey(
        "accounts.User",
        on_delete=models.CASCADE,
        related_name="enrollment_tokens",
    )
    token_prefix = models.CharField(max_length=24, db_index=True)
    token_hash = models.CharField(max_length=255)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)

    def __str__(self) -> str:
        return f"EnrollmentToken({self.user.email}, prefix={self.token_prefix})"

    def is_valid(self) -> bool:
        return self.used_at is None and self.expires_at > timezone.now()

    def mark_used(self) -> None:
        self.used_at = timezone.now()
        self.save(update_fields=["used_at"])

    @classmethod
    def issue(
        cls,
        user: object,
        ttl_seconds: int = _ENROLLMENT_TOKEN_TTL_SECONDS,
    ) -> tuple[EnrollmentToken, str]:
        """Create a fresh token for `user`. Returns (row, raw_token_string).

        The raw token must be communicated out-of-band to the operator;
        it is not retrievable from the DB after this call returns.
        """
        raw = _generate_raw_token()
        instance: EnrollmentToken = cls.objects.create(
            user=user,
            token_prefix=raw[:_ENROLLMENT_PREFIX_LEN],
            token_hash=hash_token(raw),
            expires_at=timezone.now() + timedelta(seconds=ttl_seconds),
        )
        return instance, raw

    @classmethod
    def consume(cls, raw_token: str) -> EnrollmentToken | None:
        """Resolve `raw_token` to a usable row, marking it used on success.

        Returns the matching row (and sets `used_at`) only when the
        token is unexpired, unused, and the argon2id hash verifies.
        Returns None for every failure mode so callers cannot
        distinguish "wrong token" from "expired" from "already used"
        based on response shape.
        """
        if not raw_token.startswith(_ENROLLMENT_TOKEN_PREFIX):
            return None

        prefix = raw_token[:_ENROLLMENT_PREFIX_LEN]
        candidates = cls.objects.filter(
            token_prefix=prefix,
            used_at__isnull=True,
            expires_at__gt=timezone.now(),
        )
        for candidate in candidates:
            if verify_token(raw_token, candidate.token_hash):
                candidate.mark_used()
                return candidate
        return None
