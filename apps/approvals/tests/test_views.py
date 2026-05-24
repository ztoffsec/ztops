"""Tests for the approvals operator UI."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from apps.accounts.models import Role, User
from apps.approvals.models import (
    ApprovableAction,
    ApprovalState,
)
from apps.approvals.services import request_approval

if TYPE_CHECKING:
    from django.test import Client


def _make_superadmin(email: str) -> User:
    return User.objects.create_user(email=email, display_name=email[:5], role=Role.SUPERADMIN)


def _make_regular(email: str) -> User:
    return User.objects.create_user(email=email, display_name=email[:5], role=Role.REGULAR)


# ---- access control -----------------------------------------------------


@pytest.mark.django_db
def test_anonymous_redirected_to_login(client: Client) -> None:
    response = client.get("/super/approvals/")
    assert response.status_code == 302
    assert "/super/login/" in response["Location"]
    # The next= hop-back is preserved.
    assert "next=" in response["Location"]


@pytest.mark.django_db
def test_regular_user_is_forbidden(client: Client) -> None:
    user = _make_regular("nope@example.com")
    client.force_login(user)
    response = client.get("/super/approvals/")
    assert response.status_code == 403


# ---- list view ----------------------------------------------------------


@pytest.mark.django_db
def test_list_excludes_own_pending_from_actionable(client: Client) -> None:
    me = _make_superadmin("me@example.com")
    other = _make_superadmin("other@example.com")

    my_pending = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={"slug": "x"},
        requested_by=me,
    )
    other_pending = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={"slug": "y"},
        requested_by=other,
    )

    client.force_login(me)
    response = client.get("/super/approvals/")
    body = response.content.decode()

    # Other's request shows up in the actionable list.
    assert str(other_pending.id) in body
    # My own request DOES appear in the "your requests" section but not the
    # actionable one — we look for the action mnemonic in the body either way.
    assert "Actionable (1)" in body
    assert "Your requests (1)" in body
    # And my own row must be present (in the "Your requests" table).
    assert str(my_pending.id) in body


@pytest.mark.django_db
def test_list_empty_state_when_no_approvals(client: Client) -> None:
    me = _make_superadmin("alone@example.com")
    client.force_login(me)
    response = client.get("/super/approvals/")
    assert response.status_code == 200
    assert b"No actionable approvals" in response.content
    assert b"You have no recent requests" in response.content


# ---- detail view --------------------------------------------------------


@pytest.mark.django_db
def test_detail_shows_action_buttons_for_actionable_pending(client: Client) -> None:
    requester = _make_superadmin("rq@example.com")
    approver = _make_superadmin("ap@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={"slug": "acme"},
        requested_by=requester,
    )

    client.force_login(approver)
    response = client.get(f"/super/approvals/{approval.id}/")
    assert response.status_code == 200
    assert b"Approve and execute" in response.content
    assert b"Deny" in response.content


@pytest.mark.django_db
def test_detail_blocks_self_action_buttons_when_own(client: Client) -> None:
    me = _make_superadmin("ownr@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=me,
    )

    client.force_login(me)
    response = client.get(f"/super/approvals/{approval.id}/")
    assert response.status_code == 200
    assert b"your own request" in response.content
    # Approve form is not rendered for own requests.
    assert b"Approve and execute" not in response.content


@pytest.mark.django_db
def test_detail_404_for_unknown_id(client: Client) -> None:
    me = _make_superadmin("nf@example.com")
    client.force_login(me)
    response = client.get("/super/approvals/00000000-0000-0000-0000-000000000000/")
    assert response.status_code == 404


# ---- approve POST -------------------------------------------------------


@pytest.mark.django_db
def test_approve_post_transitions_and_redirects(client: Client) -> None:
    requester = _make_superadmin("aq@example.com")
    approver = _make_superadmin("av@example.com")
    approval = request_approval(
        action="approve_test_unhandled",
        payload={},
        requested_by=requester,
    )

    client.force_login(approver)
    response = client.post(f"/super/approvals/{approval.id}/approve/")
    assert response.status_code == 302
    assert response["Location"] == f"/super/approvals/{approval.id}/"

    approval.refresh_from_db()
    # No handler registered for this action -> FAILED is the expected
    # terminal (state machine ran APPROVED → execute → FAILED).
    assert approval.state == ApprovalState.FAILED.value
    assert approval.approved_by_id == approver.id


@pytest.mark.django_db
def test_approve_post_rejects_self_and_shows_error(client: Client) -> None:
    me = _make_superadmin("se@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=me,
    )

    client.force_login(me)
    response = client.post(f"/super/approvals/{approval.id}/approve/")
    assert response.status_code == 400
    assert b"own request" in response.content
    approval.refresh_from_db()
    assert approval.state == ApprovalState.PENDING.value


# ---- deny POST ----------------------------------------------------------


@pytest.mark.django_db
def test_deny_post_with_reason_transitions_to_denied(client: Client) -> None:
    requester = _make_superadmin("dq@example.com")
    denier = _make_superadmin("dn@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=requester,
    )

    client.force_login(denier)
    response = client.post(
        f"/super/approvals/{approval.id}/deny/",
        data={"reason": "looks wrong"},
    )
    assert response.status_code == 302
    approval.refresh_from_db()
    assert approval.state == ApprovalState.DENIED.value
    assert approval.denied_reason == "looks wrong"


@pytest.mark.django_db
def test_deny_post_rejects_empty_reason(client: Client) -> None:
    requester = _make_superadmin("eq@example.com")
    denier = _make_superadmin("en@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=requester,
    )

    client.force_login(denier)
    response = client.post(
        f"/super/approvals/{approval.id}/deny/",
        data={"reason": "  "},
    )
    assert response.status_code == 400
    approval.refresh_from_db()
    assert approval.state == ApprovalState.PENDING.value


# ---- dashboard surfacing ------------------------------------------------


@pytest.mark.django_db
def test_dashboard_shows_actionable_approval_count(client: Client) -> None:
    me = _make_superadmin("dm@example.com")
    other = _make_superadmin("ot@example.com")
    request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=other,
    )
    request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=other,
    )
    request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=me,
    )  # my own — must not count

    client.force_login(me)
    response = client.get("/super/dashboard/")
    assert response.status_code == 200
    # Stat card shows "2" in its .value div (the body of which is just the number).
    assert b'<div class="value">2</div>' in response.content
    assert b"Open approvals" in response.content


@pytest.mark.django_db
def test_get_on_approve_endpoint_is_method_not_allowed(client: Client) -> None:
    me = _make_superadmin("ge@example.com")
    other = _make_superadmin("gt@example.com")
    approval = request_approval(
        action=ApprovableAction.REGISTER_SUPERADMIN,
        payload={},
        requested_by=other,
    )

    client.force_login(me)
    response = client.get(f"/super/approvals/{approval.id}/approve/")
    assert response.status_code == 405
