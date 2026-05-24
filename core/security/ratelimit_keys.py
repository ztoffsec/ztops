"""Rate-limit key functions for django-ratelimit.

These feed `@ratelimit(key=...)`. The per-IP key uses the trusted-proxy-aware
`get_real_client_ip` rather than django-ratelimit's built-in ``key="ip"``: the
app runs behind Caddy over a UNIX socket, so ``REMOTE_ADDR`` is the proxy and
the built-in key would bucket all traffic under a single value. The real client
IP cannot be spoofed by a direct connection (see core.security.trusted_proxies).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from core.security.trusted_proxies import get_real_client_ip

if TYPE_CHECKING:
    from django.http import HttpRequest


def client_ip(group: str, request: HttpRequest) -> str:
    """Per real-client-IP bucket (trusted-proxy aware, spoof-safe)."""
    return get_real_client_ip(request) or "unknown"


def login_email(group: str, request: HttpRequest) -> str:
    """Per-account bucket for the login-start ceremony (slows targeted probing).

    `login_start` sends the email in a JSON body, not a form field, so we
    parse `request.body` here — `request.POST` would always be empty and
    collapse every login into one global bucket. Reading the body caches it,
    so the view's own `json.loads(request.body)` still works afterwards.
    """
    try:
        body = json.loads(request.body or b"{}")
    except (ValueError, TypeError):
        return "no-email"
    if not isinstance(body, dict):
        return "no-email"
    raw = body.get("email")
    email = raw.strip().lower() if isinstance(raw, str) else ""
    return email or "no-email"


def enroll_token(group: str, request: HttpRequest) -> str:
    """Per-enrollment-token bucket for the enroll/register endpoints."""
    if request.resolver_match is None:
        return ""
    return str(request.resolver_match.kwargs.get("token", ""))
