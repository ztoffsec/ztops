"""Tests for the report builder metadata step (Phase 4a)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from apps.accounts.models import Role, User
from apps.reports.models import PointOfContact, Report, ScopeCategory
from apps.vendors.models import Vendor

if TYPE_CHECKING:
    from django.test import Client


def _user(email: str, role: str = Role.REGULAR.value) -> User:
    return User.objects.create_user(email=email, display_name=email[:5], role=role)


def _vendor() -> Vendor:
    return Vendor.objects.create(name="Acme", slug="acme")


@pytest.mark.django_db
def test_scope_categories_seeded() -> None:
    assert ScopeCategory.objects.filter(slug="web-application").exists()
    assert ScopeCategory.objects.count() >= 12


@pytest.mark.django_db
def test_create_report_with_contact(client: Client) -> None:
    user = _user("r@example.com")
    vendor = _vendor()
    scope = ScopeCategory.objects.get(slug="web-application")
    client.force_login(user)
    resp = client.post(
        "/reports/new/",
        data={
            "name": "Acme Q2 Pentest",
            "client": str(vendor.id),
            "researchers": [str(user.id)],
            "scope_categories": [str(scope.id)],
            "classification": "CONFIDENTIAL",
            # PoC inline formset (one row).
            "contacts-TOTAL_FORMS": "1",
            "contacts-INITIAL_FORMS": "0",
            "contacts-MIN_NUM_FORMS": "0",
            "contacts-MAX_NUM_FORMS": "1000",
            "contacts-0-name": "Jane Doe",
            "contacts-0-role": "security",
            "contacts-0-email": "jane@acme.example",
            "contacts-0-phone": "",
        },
    )
    assert resp.status_code == 302
    report = Report.objects.get(name="Acme Q2 Pentest")
    assert report.created_by_id == user.id
    assert report.client_id == vendor.id
    assert list(report.scope_categories.values_list("slug", flat=True)) == ["web-application"]
    assert PointOfContact.objects.filter(report=report, name="Jane Doe").count() == 1


@pytest.mark.django_db
def test_list_and_detail_render(client: Client) -> None:
    user = _user("v@example.com")
    report = Report.objects.create(name="Visible Report", client=_vendor(), created_by=user)
    client.force_login(user)
    assert "Visible Report" in client.get("/reports/").content.decode()
    assert "Visible Report" in client.get(f"/reports/{report.id}/").content.decode()


@pytest.mark.django_db
def test_only_authorized_can_edit() -> None:
    creator = _user("c@example.com")
    outsider = _user("o@example.com")
    superadmin = _user("s@example.com", role=Role.SUPERADMIN.value)
    report = Report.objects.create(name="R", client=_vendor(), created_by=creator)

    assert report.can_user_edit(creator) is True
    assert report.can_user_edit(superadmin) is True
    assert report.can_user_edit(outsider) is False


@pytest.mark.django_db
def test_outsider_edit_404(client: Client) -> None:
    creator = _user("cc@example.com")
    outsider = _user("oo@example.com")
    report = Report.objects.create(name="R", client=_vendor(), created_by=creator)
    client.force_login(outsider)
    assert client.get(f"/reports/{report.id}/edit/").status_code == 404
