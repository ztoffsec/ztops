"""Token lifecycle services: the only sanctioned way to mint or revoke tokens.

Each function performs the state change AND emits the audit entry, so callers
cannot forget one of the two. The raw token is returned to the caller exactly
once and is never passed to ``audit()`` or a logger.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.audit.models import AuditAction
from apps.audit.services import audit
from core.security import api_tokens

from .models import MAX_LIFETIME, ApiToken
from .scopes import normalize_scopes

if TYPE_CHECKING:
    from django.http import HttpRequest

    from apps.accounts.models import User

_PREFIX_ATTEMPTS = 5


class TokenError(Exception):
    """Raised when a token cannot be created. Message is safe to show the owner."""


def lifetime_choices() -> list[int]:
    """Lifetimes (days) offered in the UI. All are within MAX_LIFETIME."""
    return [d for d in (7, 30, 60, 90) if timedelta(days=d) <= MAX_LIFETIME]


def active_tokens_for(user: User) -> list[ApiToken]:
    now = timezone.now()
    return [
        t
        for t in ApiToken.objects.select_related("user").filter(
            user=user,
            revoked_at__isnull=True,
            expires_at__gt=now,
        )
        if t.rejection_reason(now) is None
    ]


def create_token(
    *,
    user: User,
    name: str,
    scopes: list[str],
    lifetime_days: int,
    request: HttpRequest | None = None,
) -> tuple[ApiToken, str]:
    """Mint a token for ``user``. Returns ``(row, raw_token)``.

    The caller is responsible for having verified a fresh step-up for
    ``user`` before calling this.
    """
    if not user.is_active:
        raise TokenError("Inactive users cannot create API tokens.")
    clean_name = name.strip()
    if not clean_name:
        raise TokenError("A token name is required.")
    try:
        clean_scopes = normalize_scopes(scopes)
    except ValueError as exc:
        raise TokenError("Unknown scope requested.") from exc
    if not clean_scopes:
        raise TokenError("Select at least one scope.")
    lifetime = timedelta(days=int(lifetime_days))
    if lifetime <= timedelta(0) or lifetime > MAX_LIFETIME:
        raise TokenError("Token lifetime is out of range.")

    max_active = int(settings.API_TOKEN_MAX_ACTIVE_PER_USER)
    if len(active_tokens_for(user)) >= max_active:
        raise TokenError(
            f"You already have {max_active} active tokens. Revoke one before creating another.",
        )

    expires_at = timezone.now() + lifetime
    for _ in range(_PREFIX_ATTEMPTS):
        generated = api_tokens.generate()
        try:
            with transaction.atomic():
                token = ApiToken.objects.create(
                    user=user,
                    name=clean_name,
                    prefix=generated.prefix,
                    token_hash=generated.hashed,
                    scopes=clean_scopes,
                    expires_at=expires_at,
                )
        except IntegrityError:
            # Prefix collision (48 bits; astronomically rare). Retry.
            continue
        break
    else:  # pragma: no cover - would need 5 consecutive 48-bit collisions
        raise TokenError("Could not allocate a token. Try again.")

    audit(
        action=AuditAction.API_TOKEN_CREATED,
        actor=user,
        request=request,
        target_kind="api_token",
        target_id=str(token.id),
        target_label=f"{token.name} ({token.prefix})",
        metadata={
            "via": "ui",
            "token_id": str(token.id),
            "prefix": token.prefix,
            "scopes": clean_scopes,
            "expires_at": token.expires_at.isoformat(),
            "owner_id": str(user.id),
        },
    )
    return token, generated.raw


def revoke_token(
    *,
    token: ApiToken,
    actor: User,
    request: HttpRequest | None = None,
) -> bool:
    """Revoke ``token``. Returns False if it was already revoked (no-op).

    Authorization (owner or superadmin) is the caller's job; this function
    only performs the atomic state change and the audit write.
    """
    now = timezone.now()
    updated = ApiToken.objects.filter(pk=token.pk, revoked_at__isnull=True).update(
        revoked_at=now,
        revoked_by=actor,
    )
    if not updated:
        return False
    token.revoked_at = now
    token.revoked_by = actor
    audit(
        action=AuditAction.API_TOKEN_REVOKED,
        actor=actor,
        request=request,
        target_kind="api_token",
        target_id=str(token.id),
        target_label=f"{token.name} ({token.prefix})",
        metadata={
            "via": "ui",
            "token_id": str(token.id),
            "prefix": token.prefix,
            "owner_id": str(token.user_id),
            "by_superadmin_for_other_user": actor.pk != token.user_id,
        },
    )
    return True


def audit_api(
    *,
    action: AuditAction,
    token: ApiToken | None,
    actor: User | None,
    request: HttpRequest | None,
    target_kind: str = "",
    target_id: str = "",
    target_label: str = "",
    metadata: dict[str, Any] | None = None,
) -> None:
    """Audit an event that happened through the API (``via=api`` + token id).

    Phase B/C endpoints reuse this so every API-originated change carries the
    token that performed it.
    """
    meta: dict[str, Any] = {"via": "api"}
    if token is not None:
        meta["token_id"] = str(token.id)
        meta["prefix"] = token.prefix
    meta.update(metadata or {})
    audit(
        action=action,
        actor=actor,
        request=request,
        target_kind=target_kind,
        target_id=target_id,
        target_label=target_label,
        metadata=meta,
    )
