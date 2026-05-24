"""Tests for the superadmin shell views: login, dashboard, logout."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from apps.accounts.models import Role, User
from apps.webauthn_auth.models import WebAuthnCredential

if TYPE_CHECKING:
    from django.test import Client


@pytest.mark.django_db
def test_login_page_renders_when_unauthenticated(client: Client) -> None:
    response = client.get("/super/login/")
    assert response.status_code == 200
    assert b"Sign in" in response.content
    assert b"passkey" in response.content


@pytest.mark.django_db
def test_login_page_redirects_to_dashboard_when_already_authenticated(client: Client) -> None:
    user = User.objects.create_user(
        email="signedin@example.com",
        display_name="Already",
        role=Role.SUPERADMIN,
    )
    client.force_login(user)
    response = client.get("/super/login/")
    assert response.status_code == 302
    assert response["Location"] == "/super/dashboard/"


@pytest.mark.django_db
def test_dashboard_requires_authentication(client: Client) -> None:
    response = client.get("/super/dashboard/")
    assert response.status_code == 302
    assert "/super/login/" in response["Location"]


@pytest.mark.django_db
def test_dashboard_renders_metric_cards_when_authenticated(client: Client) -> None:
    user = User.objects.create_user(
        email="dash@example.com",
        display_name="Dashboard User",
        role=Role.SUPERADMIN,
    )
    client.force_login(user)
    response = client.get("/super/dashboard/")
    assert response.status_code == 200
    # Stat cards rendered (no data yet, so counts are zero).
    assert b"Total findings" in response.content
    assert b"Critical + High" in response.content
    assert b"My open" in response.content
    assert b"Vendors" in response.content


@pytest.mark.django_db
def test_profile_renders_account_details(client: Client) -> None:
    user = User.objects.create_user(
        email="prof@example.com",
        display_name="Profile User",
        role=Role.SUPERADMIN,
    )
    client.force_login(user)
    response = client.get("/super/profile/")
    assert response.status_code == 200
    assert b"prof@example.com" in response.content
    assert b"Profile User" in response.content
    assert b"superadmin" in response.content


@pytest.mark.django_db
def test_profile_lists_user_credentials(client: Client) -> None:
    user = User.objects.create_user(
        email="cred@example.com",
        display_name="Cred",
        role=Role.SUPERADMIN,
    )
    WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"sample-cred-1",
        public_key=b"pk",
        transports=["internal"],
    )
    client.force_login(user)
    response = client.get("/super/profile/")
    assert response.status_code == 200
    assert b"1 authenticator" in response.content
    assert b"internal" in response.content


@pytest.mark.django_db
def test_profile_shows_zero_passkey_warning(client: Client) -> None:
    user = User.objects.create_user(
        email="nokey@example.com",
        display_name="No",
        role=Role.SUPERADMIN,
    )
    client.force_login(user)
    response = client.get("/super/profile/")
    assert response.status_code == 200
    assert b"No passkeys registered" in response.content


@pytest.mark.django_db
def test_profile_requires_authentication(client: Client) -> None:
    response = client.get("/super/profile/")
    assert response.status_code == 302
    assert "/super/login/" in response["Location"]


@pytest.mark.django_db
def test_dashboard_emits_security_headers(client: Client) -> None:
    # Sanity: SecurityHeadersMiddleware still wraps the response on
    # authenticated views too.
    user = User.objects.create_user(
        email="hdr@example.com",
        display_name="H",
        role=Role.SUPERADMIN,
    )
    client.force_login(user)
    response = client.get("/super/dashboard/")
    csp = response.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    # Per-request nonce is injected into the inline <style> tag.
    assert b'nonce="' in response.content


@pytest.mark.django_db
def test_logout_requires_post(client: Client) -> None:
    user = User.objects.create_user(
        email="logout@example.com",
        display_name="Lo",
        role=Role.SUPERADMIN,
    )
    client.force_login(user)
    response = client.get("/super/logout/")
    assert response.status_code == 405


@pytest.mark.django_db
def test_logout_clears_session_and_redirects(client: Client) -> None:
    user = User.objects.create_user(
        email="clear@example.com",
        display_name="C",
        role=Role.SUPERADMIN,
    )
    client.force_login(user)
    assert client.session.get("_auth_user_id") == str(user.id)

    response = client.post("/super/logout/")

    assert response.status_code == 302
    assert "/super/login/" in response["Location"]
    assert "_auth_user_id" not in client.session


@pytest.mark.django_db
def test_login_url_setting_points_at_super_login(client: Client) -> None:
    # Hitting an authenticated view as an anon user must redirect to
    # /super/login/, not Django's default /accounts/login/.
    response = client.get("/super/dashboard/")
    assert response.status_code == 302
    assert response["Location"].startswith("/super/login/")
