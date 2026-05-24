"""End-to-end tests for the findings + engagements UI.

Drives the same code paths a real researcher would: signs in, browses
the findings list with filters, opens a finding's detail page, posts a
note, confirms the note round-trips after a fresh navigation.
Authentication uses `client.force_login` (the WebAuthn ceremony has its
own e2e suite in test_passkey_flow.py).
"""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING

import pytest

from apps.accounts.models import Role, User
from apps.findings.models import Channel, Finding
from apps.vendors.models import Vendor

if TYPE_CHECKING:
    from django.test import Client


def _vendor(name: str, slug: str) -> Vendor:
    return Vendor.objects.create(name=name, slug=slug)


@pytest.mark.django_db
def test_findings_browse_filter_and_note_roundtrip(client: Client) -> None:
    """seed findings → list shows rows → filter → open detail → add note → it persists."""
    reporter = User.objects.create_user(
        email="reporter@example.com",
        display_name="Reporter",
        role=Role.SUPERADMIN,
    )

    Finding.objects.create(
        internal_id="ACME-001",
        title="2FA bypass via token reuse",
        vendor=_vendor("Acme", "acme"),
        channel=Channel.HACKERONE.value,
        channel_program="acme",
        cvss_31_score=Decimal("7.3"),
        reported_by=reporter,
    )
    Finding.objects.create(
        internal_id="GLBX-001",
        title="Unauth signing oracle",
        vendor=_vendor("Globex", "globex"),
        channel=Channel.HACKERONE.value,
        channel_program="globex",
        cvss_4_score=Decimal("9.3"),
        reported_by=reporter,
    )
    Finding.objects.create(
        internal_id="INIT-001",
        title="Mass assignment via permit",
        vendor=_vendor("Initech", "initech"),
        channel=Channel.MITRE.value,
        cvss_31_score=Decimal("2.7"),
        reported_by=reporter,
    )
    assert Finding.objects.count() == 3

    # The signed-in user (reporter) is the one who filed them — and is
    # automatically in assigned_researchers, so they can add notes.
    client.force_login(reporter)
    list_response = client.get("/findings/")
    assert list_response.status_code == 200
    body = list_response.content.decode()
    assert "ACME-001" in body
    assert "GLBX-001" in body
    assert "INIT-001" in body
    assert "3 findings" in body

    filtered = client.get("/findings/?severity=critical")
    assert filtered.status_code == 200
    fbody = filtered.content.decode()
    assert "GLBX-001" in fbody
    assert "ACME-001" not in fbody

    glbx = Finding.objects.get(internal_id="GLBX-001")
    detail = client.get(f"/findings/{glbx.id}/")
    assert detail.status_code == 200
    dbody = detail.content.decode()
    assert "GLBX-001" in dbody
    assert "Globex" in dbody
    assert "Critical" in dbody

    note_response = client.post(
        f"/findings/{glbx.id}/notes/add/",
        data={"body": "Vendor acknowledged; PoC reproducing on testnet."},
    )
    assert note_response.status_code == 302

    after = client.get(f"/findings/{glbx.id}/?tab=notes")
    abody = after.content.decode()
    assert "Vendor acknowledged" in abody
    assert "reporter@example.com" in abody
    # Notes tab pill shows the count of 1.
    assert 'data-tab-link="notes"' in abody
    assert '<span class="count">1</span>' in abody
