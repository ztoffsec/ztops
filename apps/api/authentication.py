"""``Authorization: Bearer ztops_<prefix>_<secret>`` authentication for DRF.

This is the ONLY authentication class on the API (no SessionAuthentication),
so a browser session cookie never authenticates an API call and there is no
CSRF surface.

Verification order (every failure ends in the same generic 401):

1. Per-IP failed-auth limiter is consulted first; an IP over the limit gets
   429 before any parsing, DB or argon2 work.
2. Strict format parse (no DB / argon2 for malformed input).
3. Lookup by public prefix. Unknown prefix -> a dummy argon2 verify, so the
   timing matches the "known prefix, wrong secret" path.
4. argon2id verify of the full raw token (constant-time).
5. State checks AFTER the hash check: revoked, expired, idle-expired,
   inactive owner. Ordering means only a holder of the real secret can learn
   anything about state, and even they only get the generic 401.

Never log or audit the raw header or token: only the prefix, token id and an
internal reason code.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, NoReturn

from django.conf import settings
from django.utils import timezone
from django_ratelimit.core import is_ratelimited
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication

from apps.audit.models import AuditAction
from core.security import api_tokens
from core.security.ratelimit_keys import client_ip
from core.security.trusted_proxies import get_real_client_ip

from .models import ApiToken, RejectionReason
from .services import audit_api

if TYPE_CHECKING:
    from django.http import HttpRequest
    from rest_framework.request import Request

    from apps.accounts.models import User

logger = logging.getLogger("apps.api.auth")

AUTH_FAILURE_GROUP = "api:auth_failure"
GENERIC_FAILURE = "Invalid or expired token."
_KEYWORD = "bearer"
_MAX_HEADER_LEN = 512


def _over_failure_limit(request: HttpRequest, *, increment: bool) -> bool:
    return bool(
        is_ratelimited(
            request,
            group=AUTH_FAILURE_GROUP,
            key=client_ip,
            rate=settings.API_AUTH_FAILURE_RATE,
            increment=increment,
        ),
    )


class BearerTokenAuthentication(BaseAuthentication):
    def authenticate_header(self, request: Request) -> str:
        # Presence of this header makes DRF answer 401 (not 403).
        return 'Bearer realm="ztops-api"'

    def authenticate(self, request: Request) -> tuple[User, ApiToken] | None:
        header = request.META.get("HTTP_AUTHORIZATION", "")
        if not isinstance(header, str) or not header:
            return None  # -> NotAuthenticated (401) from the permission layer

        django_request: HttpRequest = request._request  # noqa: SLF001
        if _over_failure_limit(django_request, increment=False):
            raise exceptions.Throttled(wait=60)

        if len(header) > _MAX_HEADER_LEN:
            self._fail(django_request, reason="malformed")
        parts = header.split()
        if len(parts) != 2 or parts[0].lower() != _KEYWORD:  # noqa: PLR2004
            self._fail(django_request, reason="malformed")
        raw = parts[1]

        prefix = api_tokens.parse_prefix(raw)
        if prefix is None:
            self._fail(django_request, reason="malformed")

        token = ApiToken.objects.select_related("user").filter(prefix=prefix).first()
        if token is None:
            api_tokens.burn_verify(raw)
            self._fail(django_request, reason="unknown_prefix")

        if not api_tokens.verify(raw, token.token_hash):
            self._fail(django_request, reason=RejectionReason.HASH_MISMATCH, token=token)

        now = timezone.now()
        rejection = token.rejection_reason(now)
        if rejection is not None:
            self._fail(django_request, reason=rejection, token=token)

        self._touch(token, now)
        return token.user, token

    # --- helpers -----------------------------------------------------------

    @staticmethod
    def _touch(token: ApiToken, now: datetime) -> None:
        """Bump last_used_at at most once per resolution window (no write per request)."""
        resolution = timedelta(seconds=int(settings.API_TOKEN_LAST_USED_RESOLUTION_SECONDS))
        if token.last_used_at is None or token.last_used_at <= now - resolution:
            ApiToken.objects.filter(pk=token.pk).update(last_used_at=now)
            token.last_used_at = now

    @staticmethod
    def _fail(
        request: HttpRequest,
        *,
        reason: str,
        token: ApiToken | None = None,
    ) -> NoReturn:
        _over_failure_limit(request, increment=True)
        # Logs only the public prefix, row id, reason code and IP — never the
        # header or secret (asserted by test_secret_never_logged).
        logger.warning(  # nosemgrep: python-logger-credential-disclosure
            "api auth failed reason=%s prefix=%s token_id=%s ip=%s",
            str(reason),
            token.prefix if token is not None else "-",
            str(token.id) if token is not None else "-",
            get_real_client_ip(request) or "-",
        )
        if token is not None:
            # A real token was presented with a bad secret, or a revoked /
            # expired / idle / orphaned token is still in use: both are signals
            # of a leak worth keeping in the forensic record. Unknown prefixes
            # are only logged (bounded by the per-IP limiter either way).
            audit_api(
                action=AuditAction.API_AUTH_FAILED,
                token=token,
                actor=None,
                request=request,
                target_kind="api_token",
                target_id=str(token.id),
                target_label=token.prefix,
                metadata={"reason": str(reason), "owner_id": str(token.user_id)},
            )
        raise exceptions.AuthenticationFailed(GENERIC_FAILURE)
