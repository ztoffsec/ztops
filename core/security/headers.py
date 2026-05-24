"""HTTP security-header middleware.

Emits the headers that Django's built-in ``SecurityMiddleware`` does not
cover: Content-Security-Policy (with a per-request nonce),
Cross-Origin-Embedder-Policy, and Permissions-Policy. The Django builtins
handle HSTS, COOP, Referrer-Policy, and nosniff via settings.

CSP design notes:

- ``default-src 'self'`` plus per-directive overrides; no ``unsafe-inline``,
  no ``unsafe-eval`` anywhere.
- A 128-bit nonce is generated per request and attached to ``request`` so
  templates can render ``<script nonce="{{ request.csp_nonce }}">`` when
  inline blocks are unavoidable. The nonce is included in ``script-src``
  and ``style-src``.
- ``frame-ancestors 'none'`` is the modern equivalent of
  ``X-Frame-Options: DENY`` (which Django still emits via
  XFrameOptionsMiddleware for older clients).
- ``form-action 'self'`` prevents form-submission redirection attacks.
- ``base-uri 'none'`` blocks base-tag injection.
- ``object-src 'none'`` disables Flash / Java / PDF embed vectors.
- ``upgrade-insecure-requests`` opts browsers into rewriting mixed-content
  ``http:`` URLs on the same origin.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Final

from django.http import HttpRequest, HttpResponse

_NONCE_BYTES: Final[int] = 16  # 128 bits — `token_urlsafe(16)` ≈ 22 chars.

_PERMISSIONS_POLICY: Final[str] = ", ".join(
    [
        "camera=()",
        "microphone=()",
        "geolocation=()",
        "payment=()",
        "usb=()",
        "interest-cohort=()",
        "browsing-topics=()",
    ],
)

_COEP_VALUE: Final[str] = "require-corp"


def _build_csp(nonce: str) -> str:
    return "; ".join(
        [
            "default-src 'self'",
            f"script-src 'self' 'nonce-{nonce}'",
            f"style-src 'self' 'nonce-{nonce}'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "object-src 'none'",
            "upgrade-insecure-requests",
        ],
    )


class SecurityHeadersMiddleware:
    """Set CSP/COEP/Permissions-Policy on every response.

    Runs early on the request path (to attach ``request.csp_nonce`` before
    views render) and late on the response path (to overwrite anything a
    view inadvertently set).
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        nonce = secrets.token_urlsafe(_NONCE_BYTES)
        # mypy: HttpRequest is dynamically attribute-extensible by Django convention.
        request.csp_nonce = nonce  # type: ignore[attr-defined]

        response = self.get_response(request)

        response.headers["Content-Security-Policy"] = _build_csp(nonce)
        response.headers["Cross-Origin-Embedder-Policy"] = _COEP_VALUE
        response.headers["Permissions-Policy"] = _PERMISSIONS_POLICY
        return response
