"""Tests for SecurityHeadersMiddleware: CSP/COEP/Permissions-Policy."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory

from core.security.headers import SecurityHeadersMiddleware


def _ok(_request: HttpRequest) -> HttpResponse:
    return HttpResponse("hi")


@pytest.fixture
def middleware() -> SecurityHeadersMiddleware:
    return SecurityHeadersMiddleware(_ok)


def test_csp_header_is_set(rf: RequestFactory, middleware: SecurityHeadersMiddleware) -> None:
    response = middleware(rf.get("/"))
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'none'" in csp
    assert "form-action 'self'" in csp
    assert "upgrade-insecure-requests" in csp


def test_csp_disallows_unsafe_inline_and_eval(
    rf: RequestFactory,
    middleware: SecurityHeadersMiddleware,
) -> None:
    csp = middleware(rf.get("/")).headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_per_request_nonce_is_attached_and_referenced_in_csp(
    rf: RequestFactory,
) -> None:
    captured: dict[str, str] = {}

    def capture(request: HttpRequest) -> HttpResponse:
        captured["nonce"] = request.csp_nonce  # type: ignore[attr-defined]
        return HttpResponse("hi")

    middleware = SecurityHeadersMiddleware(capture)
    response = middleware(rf.get("/"))

    nonce = captured["nonce"]
    assert len(nonce) >= 20  # token_urlsafe(16) yields ~22 url-safe chars
    csp = response.headers["Content-Security-Policy"]
    assert f"'nonce-{nonce}'" in csp


def test_nonces_differ_between_requests(rf: RequestFactory) -> None:
    captured: list[str] = []

    def capture(request: HttpRequest) -> HttpResponse:
        captured.append(request.csp_nonce)  # type: ignore[attr-defined]
        return HttpResponse("hi")

    middleware = SecurityHeadersMiddleware(capture)
    middleware(rf.get("/"))
    middleware(rf.get("/"))

    assert captured[0] != captured[1]


def test_coep_and_permissions_policy_are_set(
    rf: RequestFactory,
    middleware: SecurityHeadersMiddleware,
) -> None:
    response = middleware(rf.get("/"))
    assert response.headers["Cross-Origin-Embedder-Policy"] == "require-corp"
    pp = response.headers["Permissions-Policy"]
    for sensor in ("camera=()", "microphone=()", "geolocation=()", "payment=()"):
        assert sensor in pp


def test_middleware_forwards_response_unchanged_apart_from_headers(
    rf: RequestFactory,
) -> None:
    def body(_request: HttpRequest) -> HttpResponse:
        return HttpResponse("payload-123", status=201)

    response: HttpResponse = SecurityHeadersMiddleware(body)(rf.get("/"))
    assert response.status_code == 201
    assert response.content == b"payload-123"


def test_get_response_callable_type() -> None:
    # Compile-time check that the constructor accepts the documented signature.
    get_response: Callable[[HttpRequest], HttpResponse] = _ok
    SecurityHeadersMiddleware(get_response)
