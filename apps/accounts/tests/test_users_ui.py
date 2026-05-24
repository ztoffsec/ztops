"""Tests for the /super/users/ user-management surface."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from apps.accounts.models import Role, User
from apps.approvals.models import ApprovableAction, SuperAdminApproval
from apps.audit.models import AuditAction, AuditLogEntry
from apps.webauthn_auth.models import EnrollmentToken

if TYPE_CHECKING:
    from django.test import Client


def _user(email: str, role: str = Role.REGULAR.value) -> User:
    return User.objects.create_user(email=email, display_name=email[:6], role=role)


# ---- access control -----------------------------------------------------


@pytest.mark.django_db
def test_users_list_anon_redirected(client: Client) -> None:
    response = client.get("/super/users/")
    assert response.status_code == 302
    assert "/super/login/" in response["Location"]


@pytest.mark.django_db
def test_users_list_regular_is_forbidden(client: Client) -> None:
    u = _user("reg@example.com")
    client.force_login(u)
    response = client.get("/super/users/")
    assert response.status_code == 403


@pytest.mark.django_db
def test_users_list_renders_for_superadmin(client: Client) -> None:
    sa = _user("sa@example.com", role=Role.SUPERADMIN.value)
    _user("other@example.com")
    client.force_login(sa)
    response = client.get("/super/users/")
    assert response.status_code == 200
    assert b"other@example.com" in response.content


# ---- create regular user (solo) -----------------------------------------


@pytest.mark.django_db
def test_create_regular_user_one_step(client: Client) -> None:
    sa = _user("creator@example.com", role=Role.SUPERADMIN.value)
    client.force_login(sa)
    response = client.post(
        "/super/users/new/",
        data={
            "email": "newreg@example.com",
            "display_name": "New Reg",
            "role": Role.REGULAR.value,
        },
    )
    assert response.status_code == 302
    user = User.objects.get(email="newreg@example.com")
    assert user.role == Role.REGULAR.value
    # Audit row emitted.
    assert AuditLogEntry.objects.filter(
        action=AuditAction.USER_CREATED.value,
        target_id=str(user.id),
    ).exists()
    # No approval row was created for a regular user.
    assert not SuperAdminApproval.objects.filter(
        action=ApprovableAction.REGISTER_SUPERADMIN.value,
    ).exists()


@pytest.mark.django_db
def test_create_with_duplicate_email_re_renders(client: Client) -> None:
    sa = _user("dup@example.com", role=Role.SUPERADMIN.value)
    existing = _user("existing@example.com")
    client.force_login(sa)
    response = client.post(
        "/super/users/new/",
        data={
            "email": "existing@example.com",
            "display_name": "Dup",
            "role": Role.REGULAR.value,
        },
    )
    assert response.status_code == 200
    assert b"already exists" in response.content
    # Existing user untouched.
    existing.refresh_from_db()
    assert existing.display_name != "Dup"


# ---- create superadmin (two-person rule) --------------------------------


@pytest.mark.django_db
def test_create_superadmin_routes_through_approval(client: Client) -> None:
    sa_a = _user("a@example.com", role=Role.SUPERADMIN.value)
    client.force_login(sa_a)
    response = client.post(
        "/super/users/new/",
        data={
            "email": "newsa@example.com",
            "display_name": "New SA",
            "role": Role.SUPERADMIN.value,
        },
    )
    # Redirects to the approval detail.
    assert response.status_code == 302
    approval = SuperAdminApproval.objects.get(
        action=ApprovableAction.REGISTER_SUPERADMIN.value,
    )
    assert approval.requested_by_id == sa_a.id
    assert approval.payload == {
        "email": "newsa@example.com",
        "display_name": "New SA",
    }
    # No User row exists yet; pending second approval.
    assert not User.objects.filter(email="newsa@example.com").exists()


@pytest.mark.django_db
def test_superadmin_approval_handler_creates_user(client: Client) -> None:
    """Once a second superadmin approves, the User row materializes."""
    sa_a = _user("aa@example.com", role=Role.SUPERADMIN.value)
    sa_b = _user("bb@example.com", role=Role.SUPERADMIN.value)

    # A submits.
    client.force_login(sa_a)
    client.post(
        "/super/users/new/",
        data={
            "email": "shipped@example.com",
            "display_name": "Shipped",
            "role": Role.SUPERADMIN.value,
        },
    )
    approval = SuperAdminApproval.objects.get(
        action=ApprovableAction.REGISTER_SUPERADMIN.value,
    )

    # B approves.
    client.force_login(sa_b)
    response = client.post(f"/super/approvals/{approval.id}/approve/")
    assert response.status_code == 302

    approval.refresh_from_db()
    assert approval.state == "executed"
    user = User.objects.get(email="shipped@example.com")
    assert user.role == Role.SUPERADMIN.value
    # Audit row from the handler.
    assert AuditLogEntry.objects.filter(
        action=AuditAction.USER_CREATED.value,
        target_id=str(user.id),
        metadata__via="approval",
    ).exists()


# ---- enrollment URL flow ------------------------------------------------


@pytest.mark.django_db
def test_issue_enrollment_renders_url_once(client: Client) -> None:
    sa = _user("issuer@example.com", role=Role.SUPERADMIN.value)
    target = _user("ent@example.com")
    client.force_login(sa)
    response = client.post(f"/super/users/{target.id}/enroll/")
    assert response.status_code == 200
    body = response.content.decode()
    assert "/webauthn/enroll/" in body
    # One token row was issued for the target.
    assert EnrollmentToken.objects.filter(user=target).count() == 1


@pytest.mark.django_db
def test_issue_enrollment_emits_audit(client: Client) -> None:
    sa = _user("audi@example.com", role=Role.SUPERADMIN.value)
    target = _user("audit_t@example.com")
    client.force_login(sa)
    client.post(f"/super/users/{target.id}/enroll/")
    assert AuditLogEntry.objects.filter(
        action=AuditAction.SUPERADMIN_TOKEN_ISSUED.value,
        target_id=str(target.id),
    ).exists()


@pytest.mark.django_db
def test_user_detail_does_not_leak_token_on_get(client: Client) -> None:
    sa = _user("g@example.com", role=Role.SUPERADMIN.value)
    target = _user("gt@example.com")
    EnrollmentToken.issue(target)  # raw token thrown away — only prefix persisted
    client.force_login(sa)
    response = client.get(f"/super/users/{target.id}/")
    assert response.status_code == 200
    # GET never shows a clickable enrollment URL; the issued-once banner
    # only appears on POST to /enroll/.
    assert b"Enrollment URL (shown once)" not in response.content
