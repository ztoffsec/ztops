"""Tests for the finding review workflow.

Covers:
- New findings get review_state seeded by reporter role.
- Visibility filtering on findings_list (mine vs all).
- finding_detail 404s pending findings for non-review-authority users.
- State transitions emit audit + write reviewed_by/reviewed_at.
- Private review notes ACL.
- Global queue at /super/reviews/.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from apps.accounts.models import Role, User
from apps.audit.models import AuditAction, AuditLogEntry
from apps.findings.models import (
    Channel,
    Finding,
    FindingReviewNote,
    ReviewState,
)
from apps.vendors.models import Vendor

if TYPE_CHECKING:
    from django.test import Client


def _user(email: str, role: str = Role.REGULAR.value, reviewer: bool = False) -> User:
    u = User.objects.create_user(email=email, display_name=email[:6], role=role)
    if reviewer:
        u.is_reviewer = True
        u.save(update_fields=["is_reviewer"])
    return u


def _vendor(name: str = "RV") -> Vendor:
    return Vendor.objects.get_or_create(slug=name.lower(), defaults={"name": name})[0]


def _make_finding(internal_id: str, reporter: User, state: str | None = None) -> Finding:
    f = Finding.objects.create(
        internal_id=internal_id,
        title="t",
        vendor=_vendor(),
        channel=Channel.OTHER,
        reported_by=reporter,
    )
    if state is not None and state != f.review_state:
        f.review_state = state
        f.save(update_fields=["review_state"])
    return f


# ---- review_state seeded by reporter role -------------------------------


@pytest.mark.django_db
def test_new_finding_by_regular_starts_pending(client: Client) -> None:
    reg = _user("r@example.com")
    v = _vendor("MAT")
    client.force_login(reg)
    response = client.post(
        "/findings/new/",
        data={
            "title": "x",
            "vendor": str(v.id),
            "channel": Channel.OTHER.value,
            "channel_program": "",
            "cve_id": "",
            "cvss_31_score": "5.0",
            "cvss_31_vector": "",
            "cvss_4_score": "",
            "cvss_4_vector": "",
            "status": "drafted",
            "engagement": "",
            "description": "",
            "cwe_ids": "[]",
            "references": "[]",
            "disclosed_at": "",
            "acknowledged_at": "",
            "patched_at": "",
            "published_at": "",
        },
    )
    assert response.status_code == 302, response.content
    f = Finding.objects.get(title="x")
    assert f.review_state == ReviewState.PENDING.value


@pytest.mark.django_db
def test_new_finding_by_superadmin_starts_approved(client: Client) -> None:
    sa = _user("sa@example.com", role=Role.SUPERADMIN.value)
    v = _vendor("V2")
    client.force_login(sa)
    response = client.post(
        "/findings/new/",
        data={
            "title": "x",
            "vendor": str(v.id),
            "channel": Channel.OTHER.value,
            "channel_program": "",
            "cve_id": "",
            "cvss_31_score": "5.0",
            "cvss_31_vector": "",
            "cvss_4_score": "",
            "cvss_4_vector": "",
            "status": "drafted",
            "engagement": "",
            "description": "",
            "cwe_ids": "[]",
            "references": "[]",
            "disclosed_at": "",
            "acknowledged_at": "",
            "patched_at": "",
            "published_at": "",
        },
    )
    assert response.status_code == 302
    f = Finding.objects.get(title="x")
    assert f.review_state == ReviewState.APPROVED.value


@pytest.mark.django_db
def test_new_finding_by_explicit_reviewer_starts_approved(client: Client) -> None:
    rev = _user("rev@example.com", reviewer=True)
    v = _vendor("V3")
    client.force_login(rev)
    client.post(
        "/findings/new/",
        data={
            "title": "x",
            "vendor": str(v.id),
            "channel": Channel.OTHER.value,
            "status": "drafted",
            "cwe_ids": "[]",
            "references": "[]",
        },
    )
    f = Finding.objects.get(title="x")
    assert f.review_state == ReviewState.APPROVED.value


# ---- visibility on the list --------------------------------------------


@pytest.mark.django_db
def test_pending_finding_hidden_from_all_for_regular(client: Client) -> None:
    reg = _user("hr@example.com")
    other_reporter = _user("oth@example.com")
    _make_finding("PEND-001", other_reporter, ReviewState.PENDING.value)
    _make_finding("APP-001", other_reporter, ReviewState.APPROVED.value)
    client.force_login(reg)
    body = client.get("/findings/?scope=all").content.decode()
    assert "APP-001" in body
    assert "PEND-001" not in body


@pytest.mark.django_db
def test_pending_finding_visible_to_reviewer_on_all(client: Client) -> None:
    rev = _user("vis_r@example.com", reviewer=True)
    reporter = _user("vis_p@example.com")
    _make_finding("VR-001", reporter, ReviewState.PENDING.value)
    client.force_login(rev)
    body = client.get("/findings/?scope=all").content.decode()
    assert "VR-001" in body


@pytest.mark.django_db
def test_pending_finding_shows_in_my_findings_for_reporter(client: Client) -> None:
    reporter = _user("my@example.com")
    _make_finding("MY-001", reporter, ReviewState.PENDING.value)
    client.force_login(reporter)
    body = client.get("/findings/?scope=mine").content.decode()
    assert "MY-001" in body
    assert "Pending" in body


# ---- detail view 404s pending findings for outsiders -------------------


@pytest.mark.django_db
def test_detail_404s_pending_finding_for_random_user(client: Client) -> None:
    reporter = _user("dr@example.com")
    outsider = _user("d_oth@example.com")
    f = _make_finding("PD-001", reporter, ReviewState.PENDING.value)
    client.force_login(outsider)
    response = client.get(f"/findings/{f.id}/")
    assert response.status_code == 404


@pytest.mark.django_db
def test_detail_visible_to_reporter_for_their_own_pending(client: Client) -> None:
    reporter = _user("own@example.com")
    f = _make_finding("OWN-001", reporter, ReviewState.PENDING.value)
    client.force_login(reporter)
    response = client.get(f"/findings/{f.id}/")
    assert response.status_code == 200


@pytest.mark.django_db
def test_detail_visible_to_reviewer_for_any_pending(client: Client) -> None:
    reporter = _user("d_rep@example.com")
    rev = _user("d_rev@example.com", reviewer=True)
    f = _make_finding("DR-001", reporter, ReviewState.PENDING.value)
    client.force_login(rev)
    response = client.get(f"/findings/{f.id}/")
    assert response.status_code == 200


# ---- state transitions -------------------------------------------------


@pytest.mark.django_db
def test_reviewer_can_start_review(client: Client) -> None:
    reporter = _user("ts_p@example.com")
    rev = _user("ts_r@example.com", reviewer=True)
    f = _make_finding("TS-001", reporter, ReviewState.PENDING.value)
    client.force_login(rev)
    response = client.post(f"/findings/{f.id}/review/start/")
    assert response.status_code == 302
    f.refresh_from_db()
    assert f.review_state == ReviewState.UNDER_REVIEW.value
    assert f.reviewed_by_id == rev.id
    assert f.reviewed_at is not None
    assert AuditLogEntry.objects.filter(
        action=AuditAction.REVIEW_STARTED.value,
        target_id=str(f.id),
    ).exists()


@pytest.mark.django_db
def test_reviewer_can_approve_from_under_review(client: Client) -> None:
    reporter = _user("ap_p@example.com")
    rev = _user("ap_r@example.com", reviewer=True)
    f = _make_finding("AP-001", reporter, ReviewState.UNDER_REVIEW.value)
    client.force_login(rev)
    response = client.post(f"/findings/{f.id}/review/approve/")
    assert response.status_code == 302
    f.refresh_from_db()
    assert f.review_state == ReviewState.APPROVED.value
    assert AuditLogEntry.objects.filter(
        action=AuditAction.REVIEW_APPROVED.value,
        target_id=str(f.id),
    ).exists()


@pytest.mark.django_db
def test_reviewer_can_reject_from_under_review(client: Client) -> None:
    reporter = _user("rj_p@example.com")
    rev = _user("rj_r@example.com", reviewer=True)
    f = _make_finding("RJ-001", reporter, ReviewState.UNDER_REVIEW.value)
    client.force_login(rev)
    response = client.post(f"/findings/{f.id}/review/reject/")
    assert response.status_code == 302
    f.refresh_from_db()
    assert f.review_state == ReviewState.REJECTED.value
    assert AuditLogEntry.objects.filter(
        action=AuditAction.REVIEW_REJECTED.value,
        target_id=str(f.id),
    ).exists()


@pytest.mark.django_db
def test_reviewer_cannot_approve_their_own_report(client: Client) -> None:
    rev = _user("self_r@example.com", reviewer=True)
    f = _make_finding("SELF-001", rev, ReviewState.UNDER_REVIEW.value)
    client.force_login(rev)
    response = client.post(f"/findings/{f.id}/review/approve/")
    assert response.status_code == 404
    f.refresh_from_db()
    assert f.review_state == ReviewState.UNDER_REVIEW.value


@pytest.mark.django_db
def test_superadmin_can_approve_their_own_report(client: Client) -> None:
    """Superadmin override for emergency unblocks."""
    sa = _user("sa_self@example.com", role=Role.SUPERADMIN.value)
    f = _make_finding("SAS-001", sa, ReviewState.UNDER_REVIEW.value)
    client.force_login(sa)
    response = client.post(f"/findings/{f.id}/review/approve/")
    assert response.status_code == 302
    f.refresh_from_db()
    assert f.review_state == ReviewState.APPROVED.value


@pytest.mark.django_db
def test_regular_cannot_transition_review_state(client: Client) -> None:
    reg = _user("nr@example.com")
    reporter = _user("nr_p@example.com")
    f = _make_finding("NR-001", reporter, ReviewState.PENDING.value)
    client.force_login(reg)
    response = client.post(f"/findings/{f.id}/review/start/")
    assert response.status_code == 404


# ---- private review notes ACL ------------------------------------------


@pytest.mark.django_db
def test_reviewer_can_post_review_note(client: Client) -> None:
    reporter = _user("rn_p@example.com")
    rev = _user("rn_r@example.com", reviewer=True)
    f = _make_finding("RN-001", reporter, ReviewState.UNDER_REVIEW.value)
    client.force_login(rev)
    response = client.post(
        f"/findings/{f.id}/review/notes/add/",
        data={"body": "Needs more detail on the impact."},
    )
    assert response.status_code == 302
    assert FindingReviewNote.objects.filter(finding=f).count() == 1


@pytest.mark.django_db
def test_reporter_cannot_post_review_note(client: Client) -> None:
    reporter = _user("rrn_p@example.com")
    f = _make_finding("RRN-001", reporter, ReviewState.PENDING.value)
    client.force_login(reporter)
    client.post(
        f"/findings/{f.id}/review/notes/add/",
        data={"body": "Sneaking in"},
    )
    # Either 404 or 302 (with flash error); never 201 / 200 / 302 + row.
    assert FindingReviewNote.objects.filter(finding=f).count() == 0


@pytest.mark.django_db
def test_random_user_cannot_see_review_tab(client: Client) -> None:
    reporter = _user("rt_p@example.com")
    outsider = _user("rt_o@example.com")
    f = _make_finding("RT-001", reporter, ReviewState.APPROVED.value)
    client.force_login(outsider)
    body = client.get(f"/findings/{f.id}/?tab=review").content.decode()
    # No review tab link rendered for non-review-authority outsiders.
    assert 'data-tab-link="review"' not in body


@pytest.mark.django_db
def test_reporter_sees_review_tab_on_their_finding(client: Client) -> None:
    reporter = _user("rrt_p@example.com")
    f = _make_finding("RRT-001", reporter, ReviewState.PENDING.value)
    client.force_login(reporter)
    body = client.get(f"/findings/{f.id}/?tab=review").content.decode()
    assert 'data-tab-link="review"' in body


# ---- global queue ------------------------------------------------------


@pytest.mark.django_db
def test_queue_lists_pending_and_under_review(client: Client) -> None:
    reporter = _user("q_p@example.com")
    rev = _user("q_r@example.com", reviewer=True)
    _make_finding("Q-PEND", reporter, ReviewState.PENDING.value)
    _make_finding("Q-UND", reporter, ReviewState.UNDER_REVIEW.value)
    _make_finding("Q-APP", reporter, ReviewState.APPROVED.value)
    client.force_login(rev)
    body = client.get("/super/reviews/").content.decode()
    assert "Q-PEND" in body
    assert "Q-UND" in body
    # Approved findings appear in the "Recently decided" section,
    # not in Open. Check by section context.
    assert body.index("Open") < body.index("Q-PEND")


@pytest.mark.django_db
def test_queue_404s_for_non_review_authority(client: Client) -> None:
    reg = _user("qn@example.com")
    client.force_login(reg)
    response = client.get("/super/reviews/")
    assert response.status_code == 404


# ---- resubmit a rejected finding ---------------------------------------


@pytest.mark.django_db
def test_reporter_can_resubmit_rejected_finding(client: Client) -> None:
    reporter = _user("rs_p@example.com")
    f = _make_finding("RS-001", reporter, ReviewState.REJECTED.value)
    # Add some history that must survive the resubmit.
    FindingReviewNote.objects.create(
        finding=f,
        author=None,
        author_email="reviewer@example.com",
        author_is_reviewer=True,
        body="Initial rejection reason: missing PoC.",
    )
    client.force_login(reporter)
    response = client.post(f"/findings/{f.id}/review/resubmit/")
    assert response.status_code == 302
    f.refresh_from_db()
    assert f.review_state == ReviewState.PENDING.value
    # History preserved.
    assert FindingReviewNote.objects.filter(finding=f).count() == 1
    assert AuditLogEntry.objects.filter(
        action=AuditAction.REVIEW_RESUBMITTED.value,
        target_id=str(f.id),
    ).exists()


@pytest.mark.django_db
def test_non_owner_cannot_resubmit(client: Client) -> None:
    reporter = _user("rsno_p@example.com")
    other = _user("rsno_o@example.com")
    f = _make_finding("RSNO-001", reporter, ReviewState.REJECTED.value)
    client.force_login(other)
    response = client.post(f"/findings/{f.id}/review/resubmit/")
    assert response.status_code == 404
    f.refresh_from_db()
    assert f.review_state == ReviewState.REJECTED.value


@pytest.mark.django_db
def test_resubmit_only_from_rejected_state(client: Client) -> None:
    reporter = _user("rsnp_p@example.com")
    f = _make_finding("RSNP-001", reporter, ReviewState.APPROVED.value)
    client.force_login(reporter)
    response = client.post(f"/findings/{f.id}/review/resubmit/")
    # Redirects with a flash, no state change.
    assert response.status_code == 302
    f.refresh_from_db()
    assert f.review_state == ReviewState.APPROVED.value


@pytest.mark.django_db
def test_reporter_can_edit_their_rejected_finding(client: Client) -> None:
    """The reporter is in assigned_researchers by default, so edit
    rights cover all review states — they can patch content before
    resubmitting without losing notes history."""
    reporter = _user("re_p@example.com")
    f = _make_finding("RE-001", reporter, ReviewState.REJECTED.value)
    client.force_login(reporter)
    response = client.get(f"/findings/{f.id}/edit/")
    assert response.status_code == 200
