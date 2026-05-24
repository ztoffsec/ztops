"""Tests for the Vendor CRUD views."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from apps.accounts.models import Role, User
from apps.findings.models import Channel, Finding
from apps.vendors.models import Vendor

if TYPE_CHECKING:
    from django.test import Client


def _user(email: str, role: str = Role.REGULAR.value) -> User:
    return User.objects.create_user(email=email, display_name=email[:6], role=role)


@pytest.mark.django_db
def test_anonymous_redirected(client: Client) -> None:
    response = client.get("/vendors/")
    assert response.status_code == 302
    assert "/super/login/" in response["Location"]


@pytest.mark.django_db
def test_list_renders_existing(client: Client) -> None:
    Vendor.objects.create(slug="acme", name="Acme")
    user = _user("v@example.com")
    client.force_login(user)
    body = client.get("/vendors/").content.decode()
    assert "Acme" in body


@pytest.mark.django_db
def test_any_authenticated_user_can_create(client: Client) -> None:
    user = _user("creator@example.com")
    client.force_login(user)
    response = client.post(
        "/vendors/new/",
        data={"slug": "newv", "name": "NewV", "description": "", "website": ""},
    )
    assert response.status_code == 302
    v = Vendor.objects.get(slug="newv")
    assert v.created_by_id == user.id
    assert v.created_by_email == "creator@example.com"


@pytest.mark.django_db
def test_create_with_invalid_slug_re_renders(client: Client) -> None:
    user = _user("bad@example.com")
    client.force_login(user)
    response = client.post(
        "/vendors/new/",
        data={"slug": "bad slug with spaces", "name": "B"},
    )
    assert response.status_code == 200
    # Did not create.
    assert not Vendor.objects.filter(name="B").exists()


@pytest.mark.django_db
def test_detail_lists_findings_for_vendor(client: Client) -> None:
    reporter = _user("rep@example.com")
    vendor = Vendor.objects.create(slug="vd", name="VD", created_by=reporter)
    Finding.objects.create(
        internal_id="VD-001",
        title="x",
        vendor=vendor,
        channel=Channel.OTHER,
        reported_by=reporter,
    )
    client.force_login(reporter)
    body = client.get(f"/vendors/{vendor.slug}/").content.decode()
    assert "VD-001" in body


@pytest.mark.django_db
def test_non_creator_cannot_edit(client: Client) -> None:
    owner = _user("ow@example.com")
    intruder = _user("in@example.com")
    vendor = Vendor.objects.create(slug="ed", name="ED", created_by=owner)
    client.force_login(intruder)
    response = client.get(f"/vendors/{vendor.slug}/edit/")
    assert response.status_code == 404


@pytest.mark.django_db
def test_creator_can_edit(client: Client) -> None:
    owner = _user("ow2@example.com")
    vendor = Vendor.objects.create(slug="ed2", name="ED2", created_by=owner)
    client.force_login(owner)
    response = client.post(
        f"/vendors/{vendor.slug}/edit/",
        data={
            "slug": "ed2",
            "name": "ED2 renamed",
            "description": "",
            "website": "",
        },
    )
    assert response.status_code == 302
    vendor.refresh_from_db()
    assert vendor.name == "ED2 renamed"


@pytest.mark.django_db
def test_superadmin_can_edit_any(client: Client) -> None:
    owner = _user("anom@example.com")
    superadmin = _user("sup@example.com", role=Role.SUPERADMIN.value)
    vendor = Vendor.objects.create(slug="sa", name="SA", created_by=owner)
    client.force_login(superadmin)
    response = client.get(f"/vendors/{vendor.slug}/edit/")
    assert response.status_code == 200


@pytest.mark.django_db
def test_delete_blocked_when_findings_exist(client: Client) -> None:
    reporter = _user("dr@example.com")
    vendor = Vendor.objects.create(slug="dv", name="DV", created_by=reporter)
    Finding.objects.create(
        internal_id="DV-001",
        title="x",
        vendor=vendor,
        channel=Channel.OTHER,
        reported_by=reporter,
    )
    client.force_login(reporter)
    response = client.post(f"/vendors/{vendor.slug}/delete/")
    # Redirect back to detail with a flash error; vendor still exists.
    assert response.status_code == 302
    assert Vendor.objects.filter(slug="dv").exists()


@pytest.mark.django_db
def test_delete_succeeds_when_no_findings(client: Client) -> None:
    owner = _user("del@example.com")
    vendor = Vendor.objects.create(slug="del", name="DEL", created_by=owner)
    client.force_login(owner)
    response = client.post(f"/vendors/{vendor.slug}/delete/")
    assert response.status_code == 302
    assert not Vendor.objects.filter(slug="del").exists()
