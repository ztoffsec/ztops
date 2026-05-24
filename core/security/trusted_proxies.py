"""Trusted-proxy aware client-IP extraction.

Project anti-pattern: *"Do not trust
`request.META['HTTP_X_FORWARDED_FOR']` directly."* This module is the only
place that reads that header, and it refuses to honor it unless the
immediate hop (``REMOTE_ADDR``) is in the configured trusted-proxies set.

Implementation choice: walk the ``X-Forwarded-For`` chain right-to-left
(closest-to-us first), skipping known proxies, and return the first
untrusted hop. This is robust against both "Caddy appends" and "Caddy
rewrites" configurations — only the contiguous trusted tail matters.
"""

from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest


def get_real_client_ip(request: HttpRequest) -> str | None:
    """Return the actual client IP, or ``None`` if it cannot be determined.

    The result is safe to log and to feed into rate-limit keys; it cannot be
    spoofed by a client that connects directly (their packets do not come
    from a trusted-proxy address).
    """
    # django-stubs types HttpRequest.META values as `Any`. Narrow with
    # isinstance before returning so this module stays mypy --strict-clean.
    remote_value = request.META.get("REMOTE_ADDR")
    if not isinstance(remote_value, str) or not remote_value:
        return None
    remote_addr: str = remote_value

    trusted = _trusted_proxy_set()
    if remote_addr not in trusted:
        # Direct connection; REMOTE_ADDR is authoritative — XFF is ignored.
        return remote_addr

    xff_value = request.META.get("HTTP_X_FORWARDED_FOR", "")
    xff_raw: str = xff_value if isinstance(xff_value, str) else ""

    chain: list[str] = [hop.strip() for hop in xff_raw.split(",") if hop.strip()]
    for hop in reversed(chain):
        if hop not in trusted:
            return hop

    # Either XFF was absent or every entry was a trusted proxy. Fall back to
    # the immediate proxy — better than silently returning None.
    return remote_addr


def _trusted_proxy_set() -> frozenset[str]:
    raw: tuple[str, ...] = getattr(settings, "TRUSTED_PROXY_IPS", ())
    return frozenset(raw)
