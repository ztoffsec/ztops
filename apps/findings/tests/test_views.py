"""Tests for the Finding CRUD views.

Single-instance app: any authenticated active user can view/edit
findings; only superadmins reach /super/.
"""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING

import pytest

from apps.accounts.models import Role, User
from apps.findings.models import Channel, Finding, Severity, Status
from apps.vendors.models import Vendor

if TYPE_CHECKING:
    from django.test import Client


def _make_user(email: str, role: str = Role.REGULAR.value) -> User:
    return User.objects.create_user(email=email, display_name=email[:6], role=role)


def _vendor(name: str = "V") -> Vendor:
    return Vendor.objects.get_or_create(slug=name.lower(), defaults={"name": name})[0]


def _make_finding(
    internal_id: str,
    reporter: User | None = None,
    **overrides: object,
) -> Finding:
    if reporter is None:
        reporter = _make_user(f"rep-{internal_id}@example.com")
    defaults: dict[str, object] = {
        "title": "test",
        "vendor": _vendor(),
        "channel": Channel.OTHER.value,
        "cvss_31_score": Decimal("5.0"),
        "reported_by": reporter,
    }
    defaults.update(overrides)
    return Finding.objects.create(internal_id=internal_id, **defaults)


# ---- access control ------------------------------------------------------


@pytest.mark.django_db
def test_anonymous_redirected_to_login(client: Client) -> None:
    response = client.get("/findings/")
    assert response.status_code == 302
    assert "/super/login/" in response["Location"]


@pytest.mark.django_db
def test_regular_user_can_view_list(client: Client) -> None:
    user = _make_user("reg@example.com")
    client.force_login(user)
    response = client.get("/findings/")
    assert response.status_code == 200
    assert b"Findings" in response.content


@pytest.mark.django_db
def test_superadmin_can_view_list(client: Client) -> None:
    superadmin = _make_user("super@example.com", role=Role.SUPERADMIN.value)
    client.force_login(superadmin)
    response = client.get("/findings/")
    assert response.status_code == 200


# ---- list rendering + filters -------------------------------------------


@pytest.mark.django_db
def test_list_renders_findings(client: Client) -> None:
    user = _make_user("lister@example.com")
    _make_finding(
        "ACME-001",
        title="2FA bypass",
        vendor=_vendor("Acme"),
        channel=Channel.HACKERONE,
    )
    _make_finding("GLBX-002", title="TLS bypass", vendor=_vendor("globex-client"))

    client.force_login(user)
    # `?scope=all` because the test user isn't a researcher on these rows.
    response = client.get("/findings/?scope=all")
    body = response.content.decode()
    assert "ACME-001" in body
    assert "GLBX-002" in body
    assert "2 findings" in body


@pytest.mark.django_db
def test_default_scope_is_mine(client: Client) -> None:
    """Scope=mine is the default and hides findings the viewer isn't assigned to."""
    viewer = _make_user("viewer@example.com")
    # Made by someone else; viewer isn't assigned.
    _make_finding("OTHER-001", title="not mine")

    client.force_login(viewer)
    body = client.get("/findings/").content.decode()
    assert "OTHER-001" not in body
    assert "0 findings" in body


@pytest.mark.django_db
def test_list_filters_by_status(client: Client) -> None:
    user = _make_user("fs@example.com")
    _make_finding("PATCHED-001", status=Status.PATCHED.value)
    _make_finding("TRIAGE-001", status=Status.IN_TRIAGE.value)
    client.force_login(user)
    response = client.get(f"/findings/?scope=all&status={Status.PATCHED.value}")
    body = response.content.decode()
    assert "PATCHED-001" in body
    assert "TRIAGE-001" not in body


@pytest.mark.django_db
def test_list_filters_by_severity(client: Client) -> None:
    user = _make_user("sev@example.com")
    _make_finding("LOW-001", cvss_31_score=Decimal("3.0"))  # Low
    _make_finding("HIGH-001", cvss_31_score=Decimal("8.5"))  # High
    client.force_login(user)
    response = client.get(f"/findings/?scope=all&severity={Severity.HIGH.value}")
    body = response.content.decode()
    assert "HIGH-001" in body
    assert "LOW-001" not in body


@pytest.mark.django_db
def test_list_searches_by_internal_id_and_title(client: Client) -> None:
    user = _make_user("se@example.com")
    _make_finding("SEARCH-A", title="something interesting")
    _make_finding("SEARCH-B", title="completely unrelated")
    client.force_login(user)

    by_id = client.get("/findings/?scope=all&q=SEARCH-A").content.decode()
    assert "SEARCH-A" in by_id
    assert "SEARCH-B" not in by_id

    by_title = client.get("/findings/?scope=all&q=unrelated").content.decode()
    assert "SEARCH-B" in by_title
    assert "SEARCH-A" not in by_title


@pytest.mark.django_db
def test_list_sort_by_id_ascending(client: Client) -> None:
    user = _make_user("s@example.com")
    _make_finding("AAA-1")
    _make_finding("ZZZ-9")
    _make_finding("MMM-5")
    client.force_login(user)
    body = client.get("/findings/?scope=all&sort=id").content.decode()
    # AAA-1 should appear before ZZZ-9 in the rendered table (ascending).
    assert body.index("AAA-1") < body.index("MMM-5") < body.index("ZZZ-9")


@pytest.mark.django_db
def test_list_sort_by_id_descending(client: Client) -> None:
    user = _make_user("sd@example.com")
    _make_finding("AAA-1")
    _make_finding("ZZZ-9")
    client.force_login(user)
    body = client.get("/findings/?scope=all&sort=-id").content.decode()
    assert body.index("ZZZ-9") < body.index("AAA-1")


@pytest.mark.django_db
def test_list_filter_by_reporter(client: Client) -> None:
    viewer = _make_user("rv@example.com")
    rep_a = _make_user("ra@example.com")
    rep_b = _make_user("rb@example.com")
    _make_finding("RA-001", reporter=rep_a)
    _make_finding("RB-001", reporter=rep_b)
    client.force_login(viewer)
    body = client.get(f"/findings/?scope=all&reporter={rep_a.id}").content.decode()
    assert "RA-001" in body
    assert "RB-001" not in body


@pytest.mark.django_db
def test_list_pagination_splits_results(client: Client) -> None:
    user = _make_user("pg@example.com")
    for i in range(60):
        _make_finding(f"PG-{i:03d}")
    client.force_login(user)
    body = client.get("/findings/?scope=all&per_page=25").content.decode()
    assert "Page 1 / 3" in body
    # First page: 25 rows. Per-page links present.
    assert "Showing 1–25 of 60" in body
    # Page 2 link exists.
    assert "page=2" in body


@pytest.mark.django_db
def test_list_pagination_per_page_choice_applied(client: Client) -> None:
    user = _make_user("pp@example.com")
    for i in range(30):
        _make_finding(f"PP-{i:03d}")
    client.force_login(user)
    body = client.get("/findings/?scope=all&per_page=100").content.decode()
    # Only one page since 30 < 100.
    assert "Page 1 / 1" in body
    assert "Showing 1–30 of 30" in body


@pytest.mark.django_db
def test_non_assigned_user_sees_view_only_in_list(client: Client) -> None:
    viewer = _make_user("vo@example.com")
    _make_finding("VO-001", title="not mine")

    client.force_login(viewer)
    body = client.get("/findings/?scope=all").content.decode()
    assert "VO-001" in body
    assert "View only" in body


# ---- detail view --------------------------------------------------------


@pytest.mark.django_db
def test_detail_renders(client: Client) -> None:
    user = _make_user("d@example.com")
    f = _make_finding("DET-001", title="detail demo")
    client.force_login(user)
    response = client.get(f"/findings/{f.id}/")
    assert response.status_code == 200
    assert b"DET-001" in response.content
    assert b"detail demo" in response.content


@pytest.mark.django_db
def test_detail_404_for_unknown_id(client: Client) -> None:
    user = _make_user("nf@example.com")
    client.force_login(user)
    response = client.get("/findings/00000000-0000-0000-0000-000000000000/")
    assert response.status_code == 404


# ---- create / edit -----------------------------------------------------


@pytest.mark.django_db
def test_new_post_creates_finding(client: Client) -> None:
    user = _make_user("nw@example.com")
    v = _vendor()
    client.force_login(user)
    response = client.post(
        "/findings/new/",
        data={
            "title": "fresh finding",
            "vendor": str(v.id),
            "channel": Channel.OTHER.value,
            "channel_program": "",
            "cve_id": "",
            "cvss_31_score": "5.0",
            "cvss_31_vector": "",
            "cvss_4_score": "",
            "cvss_4_vector": "",
            "status": Status.DRAFTED.value,
            "narrative": "body",
            "cwe_ids": "[]",
            "references": "[]",
            "disclosed_at": "",
            "acknowledged_at": "",
            "patched_at": "",
            "published_at": "",
        },
    )
    assert response.status_code == 302, response.content
    f = Finding.objects.get(title="fresh finding")
    assert f.reported_by_id == user.id
    assert user in f.assigned_researchers.all()
    # internal_id is auto-assigned: ZT-{year}-{7 digits}.
    assert f.internal_id.startswith("ZT-")
    assert len(f.internal_id.split("-")[-1]) == 7


@pytest.mark.django_db
def test_new_post_invalid_form_re_renders(client: Client) -> None:
    user = _make_user("inv@example.com")
    client.force_login(user)
    response = client.post(
        "/findings/new/",
        data={"internal_id": "", "title": "", "vendor": ""},
    )
    assert response.status_code == 200
    assert b"Form has errors" in response.content


@pytest.mark.django_db
def test_edit_post_updates_finding(client: Client) -> None:
    user = _make_user("ed@example.com")
    f = _make_finding("ED-001", title="before", reporter=user)
    client.force_login(user)
    response = client.post(
        f"/findings/{f.id}/edit/",
        data={
            "internal_id": "ED-001",
            "title": "after",
            "vendor": str(f.vendor_id),
            "channel": Channel.OTHER.value,
            "channel_program": "",
            "cve_id": "",
            "cvss_31_score": "5.0",
            "cvss_31_vector": "",
            "cvss_4_score": "",
            "cvss_4_vector": "",
            "status": Status.IN_TRIAGE.value,
            "narrative": "",
            "cwe_ids": "[]",
            "references": "[]",
            "disclosed_at": "",
            "acknowledged_at": "",
            "patched_at": "",
            "published_at": "",
        },
    )
    assert response.status_code == 302
    f.refresh_from_db()
    assert f.title == "after"
    assert f.status == Status.IN_TRIAGE.value


# ---- add note ----------------------------------------------------------


@pytest.mark.django_db
def test_add_note_appends(client: Client) -> None:
    user = _make_user("nt@example.com")
    f = _make_finding("NT-001", reporter=user)  # reporter == note author
    client.force_login(user)
    response = client.post(
        f"/findings/{f.id}/notes/add/",
        data={"body": "first note from member"},
    )
    assert response.status_code == 302
    f.refresh_from_db()
    notes = list(f.notes.all())
    assert len(notes) == 1
    assert notes[0].body == "first note from member"
    assert notes[0].author_email == "nt@example.com"


@pytest.mark.django_db
def test_add_note_with_empty_body_is_rejected(client: Client) -> None:
    user = _make_user("eb@example.com")
    f = _make_finding("EB-001", reporter=user)
    client.force_login(user)
    response = client.post(
        f"/findings/{f.id}/notes/add/",
        data={"body": ""},
    )
    assert response.status_code == 302  # redirects regardless; flash carries error
    f.refresh_from_db()
    assert f.notes.count() == 0


@pytest.mark.django_db
def test_non_assigned_user_cannot_add_note(client: Client) -> None:
    intruder = _make_user("intr@example.com")
    f = _make_finding("INTR-001")  # reporter is some other auto-created user
    client.force_login(intruder)
    response = client.post(
        f"/findings/{f.id}/notes/add/",
        data={"body": "sneaking in"},
    )
    assert response.status_code == 404
    f.refresh_from_db()
    assert f.notes.count() == 0


@pytest.mark.django_db
def test_non_assigned_user_cannot_edit_finding(client: Client) -> None:
    intruder = _make_user("ed_intr@example.com")
    f = _make_finding("EDI-001", title="orig")
    client.force_login(intruder)
    response = client.get(f"/findings/{f.id}/edit/")
    assert response.status_code == 404


@pytest.mark.django_db
def test_assigned_collaborator_can_add_note(client: Client) -> None:
    reporter = _make_user("orep@example.com")
    collaborator = _make_user("cola@example.com")
    f = _make_finding("COL-001", reporter=reporter)
    f.assigned_researchers.add(collaborator)

    client.force_login(collaborator)
    response = client.post(
        f"/findings/{f.id}/notes/add/",
        data={"body": "collab note"},
    )
    assert response.status_code == 302
    f.refresh_from_db()
    assert f.notes.count() == 1


# ---- collaborator management -------------------------------------------


@pytest.mark.django_db
def test_owner_can_add_collaborator(client: Client) -> None:
    owner = _make_user("ow@example.com")
    target = _make_user("tgt@example.com")
    f = _make_finding("CA-001", reporter=owner)

    client.force_login(owner)
    response = client.post(
        f"/findings/{f.id}/collaborators/add/",
        data={"user_id": str(target.id)},
    )
    assert response.status_code == 302
    f.refresh_from_db()
    assert target in f.assigned_researchers.all()


@pytest.mark.django_db
def test_assigned_non_owner_cannot_add_collaborator(client: Client) -> None:
    owner = _make_user("ow2@example.com")
    collaborator = _make_user("col2@example.com")
    f = _make_finding("CA-002", reporter=owner)
    f.assigned_researchers.add(collaborator)

    other = _make_user("other-target@example.com")
    client.force_login(collaborator)
    response = client.post(
        f"/findings/{f.id}/collaborators/add/",
        data={"user_id": str(other.id)},
    )
    assert response.status_code == 404


@pytest.mark.django_db
def test_owner_cannot_remove_themselves(client: Client) -> None:
    owner = _make_user("ow3@example.com")
    f = _make_finding("CR-001", reporter=owner)

    client.force_login(owner)
    response = client.post(
        f"/findings/{f.id}/collaborators/{owner.id}/remove/",
    )
    assert response.status_code == 302
    f.refresh_from_db()
    assert owner in f.assigned_researchers.all()  # still assigned


# ---- delete -------------------------------------------------------------


@pytest.mark.django_db
def test_owner_can_delete_finding(client: Client) -> None:
    from apps.audit.models import AuditAction, AuditLogEntry  # noqa: PLC0415

    owner = _make_user("del_ow@example.com")
    f = _make_finding("DEL-001", reporter=owner)
    fid = f.id
    client.force_login(owner)

    confirm = client.get(f"/findings/{fid}/delete/")
    assert confirm.status_code == 200
    assert b"Delete this finding?" in confirm.content

    response = client.post(f"/findings/{fid}/delete/")
    assert response.status_code == 302
    assert response["Location"].endswith("/findings/")
    assert not Finding.objects.filter(pk=fid).exists()
    assert AuditLogEntry.objects.filter(
        action=AuditAction.FINDING_DELETED.value,
        target_id=str(fid),
    ).exists()


@pytest.mark.django_db
def test_superadmin_can_delete_any_finding(client: Client) -> None:
    owner = _make_user("del_o@example.com")
    superadmin = _make_user("del_sa@example.com", role=Role.SUPERADMIN.value)
    f = _make_finding("DEL-002", reporter=owner)
    client.force_login(superadmin)
    response = client.post(f"/findings/{f.id}/delete/")
    assert response.status_code == 302
    assert not Finding.objects.filter(pk=f.id).exists()


@pytest.mark.django_db
def test_assigned_non_owner_cannot_delete(client: Client) -> None:
    owner = _make_user("del_real_o@example.com")
    collaborator = _make_user("del_col@example.com")
    f = _make_finding("DEL-003", reporter=owner)
    f.assigned_researchers.add(collaborator)

    client.force_login(collaborator)
    # GET confirm page is also gated.
    get_resp = client.get(f"/findings/{f.id}/delete/")
    assert get_resp.status_code == 404
    post_resp = client.post(f"/findings/{f.id}/delete/")
    assert post_resp.status_code == 404
    assert Finding.objects.filter(pk=f.id).exists()


@pytest.mark.django_db
def test_random_user_cannot_delete(client: Client) -> None:
    intruder = _make_user("del_intr@example.com")
    f = _make_finding("DEL-004")  # reporter is a different auto-created user
    client.force_login(intruder)
    response = client.post(f"/findings/{f.id}/delete/")
    assert response.status_code == 404
    assert Finding.objects.filter(pk=f.id).exists()
