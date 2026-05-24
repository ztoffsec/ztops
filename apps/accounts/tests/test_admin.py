"""Tests for the SuperadminAdminSite gate + model registrations."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from apps.accounts.models import Role, User

if TYPE_CHECKING:
    from django.test import Client


@pytest.mark.django_db
def test_admin_index_redirects_anon_to_login(client: Client) -> None:
    # Django admin first redirects to admin/login/; our SuperadminAdminSite
    # then bounces from there to /super/login/. Follow the chain.
    response = client.get("/super/admin/", follow=True)
    chain = [url for url, _ in response.redirect_chain]
    assert any("/super/login/" in url for url in chain)


@pytest.mark.django_db
def test_admin_index_redirects_regular_user_to_login(client: Client) -> None:
    user = User.objects.create_user(
        email="reg@example.com",
        display_name="R",
        role=Role.REGULAR,
    )
    client.force_login(user)
    response = client.get("/super/admin/", follow=True)
    chain = [url for url, _ in response.redirect_chain]
    assert any("/super/login/" in url for url in chain)


@pytest.mark.django_db
def test_admin_index_renders_for_superadmin(client: Client) -> None:
    user = User.objects.create_user(
        email="su@example.com",
        display_name="S",
        role=Role.SUPERADMIN,
    )
    client.force_login(user)
    response = client.get("/super/admin/")
    assert response.status_code == 200
    assert b"ZTOps Superadmin" in response.content


@pytest.mark.django_db
def test_admin_user_list_visible(client: Client) -> None:
    superadmin = User.objects.create_user(
        email="lu@example.com",
        display_name="LU",
        role=Role.SUPERADMIN,
    )
    User.objects.create_user(email="other@example.com", display_name="O")
    client.force_login(superadmin)
    response = client.get("/super/admin/accounts/user/")
    assert response.status_code == 200
    assert b"other@example.com" in response.content


@pytest.mark.django_db
def test_admin_user_change_excludes_add_button(client: Client) -> None:
    superadmin = User.objects.create_user(
        email="ad@example.com",
        display_name="AD",
        role=Role.SUPERADMIN,
    )
    client.force_login(superadmin)
    response = client.get("/super/admin/accounts/user/")
    assert response.status_code == 200
    # has_add_permission returns False on UserAdmin — no "Add user" link.
    assert b"Add user" not in response.content
