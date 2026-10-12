"""Scope enforcement (deny by default), throttling, and transport hardening."""

from __future__ import annotations

import pytest
from django.test import Client, RequestFactory, override_settings
from django.urls import path
from rest_framework.response import Response
from rest_framework.settings import api_settings

from apps.accounts.models import User
from apps.api.authentication import BearerTokenAuthentication
from apps.api.permissions import HasTokenScopes
from apps.api.throttling import TokenRateThrottle
from apps.api.views import ApiView

from .conftest import MakeToken

# --- test-only views exercising the permission contract ------------------------


class _Undeclared(ApiView):
    def get(self, request):  # noqa: ANN001, ANN201
        return Response({"ok": True})


class _ReadOnly(ApiView):
    required_scopes = {"GET": frozenset({"findings:read"})}

    def get(self, request):  # noqa: ANN001, ANN201
        return Response({"ok": True})

    def post(self, request):  # noqa: ANN001, ANN201  # method not declared -> denied
        return Response({"ok": True})


class _WriteStatus(ApiView):
    required_scopes = frozenset({"findings:write", "findings:status"})

    def post(self, request):  # noqa: ANN001, ANN201
        return Response({"ok": True})


urlpatterns = [
    path("t/undeclared/", _Undeclared.as_view()),
    path("t/read/", _ReadOnly.as_view()),
    path("t/write-status/", _WriteStatus.as_view()),
]

_URLS = "apps.api.tests.test_permissions"


def _auth(raw: str) -> dict[str, str]:
    return {"HTTP_AUTHORIZATION": f"Bearer {raw}"}


@pytest.mark.django_db
@pytest.mark.urls(_URLS)
def test_view_without_declared_scopes_is_denied(
    client: Client,
    alice: User,
    make_token: MakeToken,
) -> None:
    all_scopes = [
        "findings:read",
        "findings:write",
        "findings:status",
        "notes:write",
        "attachments:write",
    ]
    _, raw = make_token(alice, scopes=all_scopes)
    assert client.get("/t/undeclared/", **_auth(raw)).status_code == 403


@pytest.mark.django_db
@pytest.mark.urls(_URLS)
def test_scope_required_per_method(client: Client, alice: User, make_token: MakeToken) -> None:
    _, reader = make_token(alice, scopes=["findings:read"], name="r")
    _, notes = make_token(alice, scopes=["notes:write"], name="n")
    assert client.get("/t/read/", **_auth(reader)).status_code == 200
    assert client.head("/t/read/", **_auth(reader)).status_code == 200
    assert client.get("/t/read/", **_auth(notes)).status_code == 403
    # POST is implemented but not declared in required_scopes -> denied.
    assert (
        client.post("/t/read/", {}, content_type="application/json", **_auth(reader)).status_code
        == 403
    )


@pytest.mark.django_db
@pytest.mark.urls(_URLS)
def test_all_declared_scopes_required(client: Client, alice: User, make_token: MakeToken) -> None:
    _, partial = make_token(alice, scopes=["findings:write"], name="p")
    _, full = make_token(alice, scopes=["findings:write", "findings:status"], name="f")
    url = "/t/write-status/"
    assert (
        client.post(url, {}, content_type="application/json", **_auth(partial)).status_code == 403
    )
    assert client.post(url, {}, content_type="application/json", **_auth(full)).status_code == 200


@pytest.mark.django_db
@pytest.mark.urls(_URLS)
def test_api_post_needs_no_csrf_but_never_accepts_cookies(
    alice: User,
    make_token: MakeToken,
) -> None:
    """Bearer-only means CSRF is moot: cookies alone get 401, bearer works."""
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.force_login(alice)
    url = "/t/write-status/"
    assert csrf_client.post(url, {}, content_type="application/json").status_code == 401
    _, full = make_token(alice, scopes=["findings:write", "findings:status"])
    assert (
        csrf_client.post(url, {}, content_type="application/json", **_auth(full)).status_code == 200
    )


# --- per-token throttle ------------------------------------------------------------


@pytest.mark.django_db
@override_settings(API_TOKEN_THROTTLE_RATE="3/m")
def test_per_token_throttle(client: Client, alice: User, make_token: MakeToken) -> None:
    _, a = make_token(alice, name="a")
    _, b = make_token(alice, name="b")
    codes = [client.get("/api/v1/me/", **_auth(a)).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    throttled = client.get("/api/v1/me/", **_auth(a))
    assert throttled.status_code == 429
    assert "Retry-After" in throttled
    # Another token of the same user has its own bucket.
    assert client.get("/api/v1/me/", **_auth(b)).status_code == 200


# --- transport / response hardening on /api/v1/ --------------------------------------


@pytest.mark.django_db
def test_security_headers_on_api_responses(
    client: Client,
    alice: User,
    make_token: MakeToken,
) -> None:
    _, raw = make_token(alice)
    for resp in (client.get("/api/v1/me/", **_auth(raw)), client.get("/api/v1/me/")):
        assert "nonce-" in resp["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in resp["Content-Security-Policy"]
        assert resp["Cross-Origin-Embedder-Policy"] == "require-corp"
        assert resp["Cross-Origin-Opener-Policy"] == "same-origin"
        assert resp["X-Frame-Options"] == "DENY"
        assert resp["X-Content-Type-Options"] == "nosniff"
        assert resp["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert resp["Cache-Control"] == "no-store"
        assert resp["Content-Type"] == "application/json"
        assert "Set-Cookie" not in resp


@pytest.mark.django_db
def test_no_browsable_api_and_no_metadata(
    client: Client,
    alice: User,
    make_token: MakeToken,
) -> None:
    _, raw = make_token(alice)
    html = client.get("/api/v1/me/", HTTP_ACCEPT="text/html", **_auth(raw))
    assert html.status_code in (200, 406)
    assert html["Content-Type"] == "application/json"
    assert b"<html" not in html.content.lower()
    assert client.get("/api/v1/me/?format=api", **_auth(raw))["Content-Type"] != "text/html"
    # OPTIONS is not a declared method -> denied by the scope layer before
    # DRF's (disabled) metadata handler could describe the endpoint.
    opts = client.options("/api/v1/me/", **_auth(raw))
    assert opts.status_code in (403, 405)
    assert b"actions" not in opts.content
    assert b"renders" not in opts.content
    assert (
        client.post("/api/v1/me/", {}, content_type="application/json", **_auth(raw)).status_code
        == 403
    )


def test_drf_hardened_defaults() -> None:

    assert [BearerTokenAuthentication] == api_settings.DEFAULT_AUTHENTICATION_CLASSES
    assert HasTokenScopes in api_settings.DEFAULT_PERMISSION_CLASSES
    assert [r.__name__ for r in api_settings.DEFAULT_RENDERER_CLASSES] == ["JSONRenderer"]
    assert [p.__name__ for p in api_settings.DEFAULT_PARSER_CLASSES] == ["JSONParser"]
    assert [TokenRateThrottle] == api_settings.DEFAULT_THROTTLE_CLASSES
    assert api_settings.DEFAULT_METADATA_CLASS is None


@pytest.mark.django_db
@pytest.mark.urls(_URLS)
def test_form_encoded_body_is_unsupported(
    client: Client, alice: User, make_token: MakeToken
) -> None:
    class _Echo(ApiView):
        required_scopes = frozenset()

        def post(self, request):  # noqa: ANN001, ANN201
            return Response({"data": request.data})

    _, raw = make_token(alice)
    req = RequestFactory().post(
        "/x/",
        "a=b",
        content_type="application/x-www-form-urlencoded",
        HTTP_AUTHORIZATION=f"Bearer {raw}",
    )
    resp = _Echo.as_view()(req)
    assert resp.status_code == 415
