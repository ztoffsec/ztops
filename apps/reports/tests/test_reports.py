"""Tests for the report builder metadata step (Phase 4a)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from apps.accounts.models import Role, User
from apps.findings.models import Channel, Finding
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


# ---- Phase 4b: findings in a report -------------------------------------


def _finding(vendor: Vendor, reporter: User, title: str = "f") -> Finding:
    return Finding.objects.create(
        internal_id="",
        title=title,
        vendor=vendor,
        channel=Channel.OTHER.value,
        reported_by=reporter,
    )


@pytest.mark.django_db
def test_add_finding_from_same_client(client: Client) -> None:
    user = _user("a@example.com")
    vendor = _vendor()
    report = Report.objects.create(name="R", client=vendor, created_by=user)
    finding = _finding(vendor, user)
    client.force_login(user)
    resp = client.post(f"/reports/{report.id}/findings/add/", data={"finding_id": str(finding.id)})
    assert resp.status_code == 302
    assert report.findings.filter(pk=finding.pk).exists()


@pytest.mark.django_db
def test_cannot_add_finding_from_a_different_client(client: Client) -> None:
    """Cross-vendor guard: a finding of another client is rejected server-side
    even if its id is posted directly."""
    user = _user("x@example.com")
    client_a = Vendor.objects.create(name="Acme", slug="acme")
    client_b = Vendor.objects.create(name="Globex", slug="globex")
    report = Report.objects.create(name="R", client=client_a, created_by=user)
    foreign = _finding(client_b, user)  # belongs to Globex, not the report's Acme
    client.force_login(user)
    resp = client.post(f"/reports/{report.id}/findings/add/", data={"finding_id": str(foreign.id)})
    assert resp.status_code == 302  # redirect with error flash
    assert not report.findings.filter(pk=foreign.pk).exists()


@pytest.mark.django_db
def test_create_finding_form_renders(client: Client) -> None:
    """GET the in-report finding form — catches template/include errors."""
    user = _user("g3@example.com")
    report = Report.objects.create(name="R", client=_vendor(), created_by=user)
    client.force_login(user)
    body = client.get(f"/reports/{report.id}/findings/new/").content.decode()
    assert "CVSS 3.1 calculator" in body  # the shared CVSS partial rendered
    assert "data-cvss40-metric" in body


@pytest.mark.django_db
def test_create_finding_in_report_is_mapped_to_client(client: Client) -> None:

    user = _user("c2@example.com", role=Role.SUPERADMIN.value)
    vendor = _vendor()
    report = Report.objects.create(name="R", client=vendor, created_by=user)
    client.force_login(user)
    resp = client.post(
        f"/reports/{report.id}/findings/new/",
        data={
            "title": "In-report finding",
            "channel": Channel.OTHER.value,
            "channel_program": "",
            "cve_id": "",
            "cvss_31_score": "7.0",
            "cvss_31_vector": "",
            "cvss_4_score": "",
            "cvss_4_vector": "",
            "status": "drafted",
            "narrative": "n",
            "poc": "",
            "remediation": "",
            "affected_hosts_text": "host.example.com",
            "cwe_ids": "[]",
            "references": "[]",
            "disclosed_at": "",
            "acknowledged_at": "",
            "patched_at": "",
            "published_at": "",
        },
    )
    assert resp.status_code == 302
    finding = Finding.objects.get(title="In-report finding")
    assert finding.vendor_id == vendor.id  # fixed to the report's client
    assert report.findings.filter(pk=finding.pk).exists()
    assert finding.affected_hosts.filter(value="host.example.com").exists()


@pytest.mark.django_db
def test_edit_finding_in_report(client: Client) -> None:
    user = _user("e@example.com", role=Role.SUPERADMIN.value)
    vendor = _vendor()
    report = Report.objects.create(name="R", client=vendor, created_by=user)
    finding = _finding(vendor, user, title="old title")
    report.findings.add(finding)
    client.force_login(user)
    # GET renders the edit form pre-filled.
    assert client.get(f"/reports/{report.id}/findings/{finding.id}/edit/").status_code == 200
    resp = client.post(
        f"/reports/{report.id}/findings/{finding.id}/edit/",
        data={
            "title": "new title",
            "channel": Channel.OTHER.value,
            "channel_program": "",
            "cve_id": "",
            "cvss_31_score": "",
            "cvss_31_vector": "",
            "cvss_4_score": "",
            "cvss_4_vector": "",
            "status": "drafted",
            "narrative": "n",
            "poc": "",
            "remediation": "",
            "affected_hosts_text": "",
            "cwe_ids": "[]",
            "references": "[]",
            "disclosed_at": "",
            "acknowledged_at": "",
            "patched_at": "",
            "published_at": "",
        },
    )
    assert resp.status_code == 302
    finding.refresh_from_db()
    assert finding.title == "new title"
    assert finding.vendor_id == vendor.id  # vendor unchanged


@pytest.mark.django_db
def test_cannot_edit_finding_not_in_report(client: Client) -> None:
    user = _user("ne@example.com", role=Role.SUPERADMIN.value)
    vendor = _vendor()
    report = Report.objects.create(name="R", client=vendor, created_by=user)
    other = _finding(vendor, user)  # same client, but NOT added to the report
    client.force_login(user)
    assert client.get(f"/reports/{report.id}/findings/{other.id}/edit/").status_code == 404


@pytest.mark.django_db
def test_remove_finding_unlinks_but_keeps_it(client: Client) -> None:

    user = _user("rm@example.com")
    vendor = _vendor()
    report = Report.objects.create(name="R", client=vendor, created_by=user)
    finding = _finding(vendor, user)
    report.findings.add(finding)
    client.force_login(user)
    resp = client.post(f"/reports/{report.id}/findings/{finding.id}/remove/")
    assert resp.status_code == 302
    assert not report.findings.filter(pk=finding.pk).exists()
    assert Finding.objects.filter(pk=finding.pk).exists()  # not deleted
