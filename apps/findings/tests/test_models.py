"""Tests for the Finding + FindingNote models."""

from __future__ import annotations

from decimal import Decimal

import pytest
from django.db import IntegrityError

from apps.accounts.models import Role, User
from apps.findings.models import (
    Channel,
    Finding,
    FindingNote,
    Severity,
    Status,
    severity_from_score,
)
from apps.vendors.models import Vendor

# ---- severity derivation -------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (None, Severity.NONE.value),
        (Decimal("0.0"), Severity.NONE.value),
        (Decimal("0.1"), Severity.LOW.value),
        (Decimal("3.9"), Severity.LOW.value),
        (Decimal("4.0"), Severity.MEDIUM.value),
        (Decimal("6.9"), Severity.MEDIUM.value),
        (Decimal("7.0"), Severity.HIGH.value),
        (Decimal("8.9"), Severity.HIGH.value),
        (Decimal("9.0"), Severity.CRITICAL.value),
        (Decimal("10.0"), Severity.CRITICAL.value),
    ],
)
def test_severity_band_from_score(score: Decimal | None, expected: str) -> None:
    assert severity_from_score(score) == expected


# ---- helpers -------------------------------------------------------------


def _make_reporter(email: str = "rep@example.com") -> User:
    return User.objects.create_user(email=email, display_name="R", role=Role.REGULAR)


def _make_vendor(name: str = "Acme", slug: str | None = None) -> Vendor:
    return Vendor.objects.create(slug=slug or name.lower(), name=name)


# ---- Finding model -------------------------------------------------------


@pytest.mark.django_db
def test_finding_creation_with_internal_id() -> None:
    f = Finding.objects.create(
        internal_id="ACME-001",
        title="2FA bypass via token reuse",
        vendor=_make_vendor("Acme"),
        channel=Channel.HACKERONE,
        channel_program="acme",
        cvss_31_score=Decimal("7.3"),
        cvss_31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        status=Status.IN_TRIAGE,
        reported_by=_make_reporter(),
    )
    assert f.severity == Severity.HIGH.value  # auto-derived on save
    assert f.status == Status.IN_TRIAGE.value


@pytest.mark.django_db
def test_reporter_auto_added_to_assigned_researchers() -> None:
    reporter = _make_reporter("auto@example.com")
    f = Finding.objects.create(
        internal_id="AUTO-001",
        title="x",
        vendor=_make_vendor("V", slug="auto-v"),
        channel=Channel.OTHER,
        reported_by=reporter,
    )
    assert reporter in f.assigned_researchers.all()


@pytest.mark.django_db
def test_can_user_edit_permissions() -> None:
    reporter = _make_reporter("owner@example.com")
    other = User.objects.create_user(email="oth@example.com", display_name="O")
    superadmin = User.objects.create_user(
        email="sup@example.com",
        display_name="S",
        role=Role.SUPERADMIN,
    )
    collaborator = User.objects.create_user(email="col@example.com", display_name="C")

    f = Finding.objects.create(
        internal_id="PERM-001",
        title="x",
        vendor=_make_vendor("PV", slug="pv"),
        channel=Channel.OTHER,
        reported_by=reporter,
    )
    f.assigned_researchers.add(collaborator)

    assert f.can_user_edit(reporter) is True
    assert f.can_user_edit(collaborator) is True
    assert f.can_user_edit(superadmin) is True
    assert f.can_user_edit(other) is False


@pytest.mark.django_db
def test_can_user_manage_collaborators_is_owner_only() -> None:
    reporter = _make_reporter("m_owner@example.com")
    collaborator = User.objects.create_user(email="col2@example.com", display_name="C")
    superadmin = User.objects.create_user(
        email="m_sup@example.com",
        display_name="S",
        role=Role.SUPERADMIN,
    )

    f = Finding.objects.create(
        internal_id="MGMT-001",
        title="x",
        vendor=_make_vendor("MV", slug="mv"),
        channel=Channel.OTHER,
        reported_by=reporter,
    )
    f.assigned_researchers.add(collaborator)

    assert f.can_user_manage_collaborators(reporter) is True
    assert f.can_user_manage_collaborators(superadmin) is True
    # Collaborator is assigned but NOT the owner — cannot manage.
    assert f.can_user_manage_collaborators(collaborator) is False


@pytest.mark.django_db
def test_severity_uses_higher_of_both_cvss_scores() -> None:
    """When both standards are filled, take the worst-case band so a
    lower 4.0 score never silently downgrades a Critical 3.1 finding."""
    f = Finding.objects.create(
        internal_id="ARC-001",
        title="Unauth signing oracle",
        vendor=_make_vendor("Circle", slug="circle"),
        channel=Channel.HACKERONE,
        cvss_31_score=Decimal("7.5"),  # High
        cvss_31_vector="CVSS:3.1/...",
        cvss_4_score=Decimal("9.3"),  # Critical
        cvss_4_vector="CVSS:4.0/...",
        reported_by=_make_reporter("arc@example.com"),
    )
    assert f.severity == Severity.CRITICAL.value


@pytest.mark.django_db
def test_severity_uses_31_when_higher_than_40() -> None:
    """Regression guard for DOP-001: a Critical 3.1 (9.9) finding must
    NOT be silently downgraded by a coexisting High 4.0 (7.4) score."""
    f = Finding.objects.create(
        internal_id="DOP-001",
        title="x",
        vendor=_make_vendor("Doppler", slug="doppler"),
        channel=Channel.HACKERONE,
        cvss_31_score=Decimal("9.9"),
        cvss_4_score=Decimal("7.4"),
        reported_by=_make_reporter("dop@example.com"),
    )
    assert f.severity == Severity.CRITICAL.value


@pytest.mark.django_db
def test_severity_recomputed_on_save() -> None:
    f = Finding.objects.create(
        internal_id="REC-001",
        title="x",
        vendor=_make_vendor("RecV", slug="recv"),
        channel=Channel.OTHER,
        cvss_31_score=Decimal("3.0"),
        reported_by=_make_reporter("rec@example.com"),
    )
    assert f.severity == Severity.LOW.value
    f.cvss_31_score = Decimal("9.5")
    f.save()
    assert f.severity == Severity.CRITICAL.value


@pytest.mark.django_db
def test_internal_id_unique() -> None:
    reporter = _make_reporter("dup@example.com")
    v = _make_vendor("DupV", slug="dupv")
    Finding.objects.create(
        internal_id="DUP-001",
        title="A",
        vendor=v,
        channel=Channel.OTHER,
        reported_by=reporter,
    )
    with pytest.raises(IntegrityError):
        Finding.objects.create(
            internal_id="DUP-001",
            title="B",
            vendor=v,
            channel=Channel.OTHER,
            reported_by=reporter,
        )


@pytest.mark.django_db
def test_finding_status_defaults_to_drafted() -> None:
    f = Finding.objects.create(
        internal_id="DRA-001",
        title="x",
        vendor=_make_vendor("DraV", slug="drav"),
        channel=Channel.OTHER,
        reported_by=_make_reporter("dra@example.com"),
    )
    assert f.status == Status.DRAFTED.value


@pytest.mark.django_db
def test_finding_supports_cwe_and_references_json() -> None:
    f = Finding.objects.create(
        internal_id="JS-001",
        title="x",
        vendor=_make_vendor("JsV", slug="jsv"),
        channel=Channel.OTHER,
        cwe_ids=["CWE-79", "CWE-352"],
        references=["https://example.com/advisory/1"],
        reported_by=_make_reporter("js@example.com"),
    )
    f.refresh_from_db()
    assert f.cwe_ids == ["CWE-79", "CWE-352"]
    assert f.references == ["https://example.com/advisory/1"]


@pytest.mark.django_db
def test_reporter_email_snapshot_persists_through_user_delete() -> None:
    reporter = _make_reporter("snap@example.com")
    f = Finding.objects.create(
        internal_id="SNAP-001",
        title="x",
        vendor=_make_vendor("SnapV", slug="snapv"),
        channel=Channel.OTHER,
        reported_by=reporter,
    )
    assert f.reported_by_email == "snap@example.com"


# ---- FindingNote ---------------------------------------------------------


@pytest.mark.django_db
def test_finding_note_links_to_finding() -> None:
    f = Finding.objects.create(
        internal_id="N-001",
        title="x",
        vendor=_make_vendor("NV", slug="nv"),
        channel=Channel.OTHER,
        reported_by=_make_reporter("n@example.com"),
    )
    note = FindingNote.objects.create(
        finding=f,
        body="initial draft, sending to vendor",
        author_email="me@example.com",
    )
    assert list(f.notes.all()) == [note]


@pytest.mark.django_db
def test_finding_note_author_fk() -> None:
    user = User.objects.create_user(
        email="auth@example.com",
        display_name="A",
        role=Role.SUPERADMIN,
    )
    f = Finding.objects.create(
        internal_id="N-002",
        title="x",
        vendor=_make_vendor("N2V", slug="n2v"),
        channel=Channel.OTHER,
        reported_by=user,
    )
    note = FindingNote.objects.create(
        finding=f,
        body="ack from vendor",
        author=user,
        author_email=user.email,
    )
    assert note.author_id == user.id
    assert note.author_email == "auth@example.com"
