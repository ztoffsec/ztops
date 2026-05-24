"""`audit()` — the single emission entry point for the audit log.

Every privileged action should call this once it succeeds (and ideally
also when it fails, with a distinct action code). Calls are
INSERT-only by construction; UPDATE/DELETE on the resulting row will
be rejected at the database layer.

Hardening requirement #12 allowlist: callers are responsible for not
slipping secrets / finding bodies / tokens into `metadata`. The helper
does not try to be clever about redaction — it's a thin persistence layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from core.security.trusted_proxies import get_real_client_ip

from .models import AuditAction, AuditLogEntry

if TYPE_CHECKING:
    from django.http import HttpRequest

    from apps.accounts.models import User


_USER_AGENT_MAX_LEN = 500


def audit(
    *,
    action: str | AuditAction,
    actor: User | None = None,
    request: HttpRequest | None = None,
    target_kind: str = "",
    target_id: str = "",
    target_label: str = "",
    metadata: dict[str, Any] | None = None,
) -> AuditLogEntry:
    """Insert a new audit log entry.

    `actor` is the User who initiated this action. If absent (system
    event, management-command run), the row is anonymized but still
    recorded. If `request` is provided, IP + truncated User-Agent are
    captured for forensic correlation.
    """
    actor_email = actor.email if actor is not None else ""

    ip: str | None = None
    user_agent = ""
    if request is not None:
        ip = get_real_client_ip(request)
        raw_ua = request.META.get("HTTP_USER_AGENT", "")
        if isinstance(raw_ua, str):
            user_agent = raw_ua[:_USER_AGENT_MAX_LEN]

    return AuditLogEntry.objects.create(
        action=str(action),
        actor_user=actor,
        actor_email=actor_email,
        actor_ip=ip,
        actor_user_agent=user_agent,
        target_kind=target_kind,
        target_id=str(target_id) if target_id else "",
        target_label=target_label,
        metadata=metadata or {},
    )
