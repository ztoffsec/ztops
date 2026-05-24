"""Tests for the register_superadmin_passkey management command."""

from __future__ import annotations

import io

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.accounts.models import Role, User
from apps.webauthn_auth.models import EnrollmentToken


@pytest.mark.django_db
def test_creates_new_superadmin_and_issues_token() -> None:
    out = io.StringIO()
    call_command(
        "register_superadmin_passkey",
        "--email=root@example.com",
        "--display-name=Root",
        stdout=out,
    )
    user = User.objects.get(email="root@example.com")
    assert user.role == Role.SUPERADMIN
    assert user.enrollment_tokens.filter(used_at__isnull=True).count() == 1
    # Output contains an enrollment URL with the raw token.
    output = out.getvalue()
    assert "/webauthn/enroll/zto_enr_" in output


@pytest.mark.django_db
def test_existing_superadmin_gets_fresh_token_no_role_change() -> None:
    User.objects.create_user(
        email="exist@example.com",
        display_name="Exist",
        role=Role.SUPERADMIN,
    )
    out = io.StringIO()
    call_command(
        "register_superadmin_passkey",
        "--email=exist@example.com",
        "--display-name=Exist",
        stdout=out,
    )
    user = User.objects.get(email="exist@example.com")
    assert user.role == Role.SUPERADMIN
    assert EnrollmentToken.objects.filter(user=user).count() == 1


@pytest.mark.django_db
def test_refuses_to_elevate_regular_user_without_flag() -> None:
    User.objects.create_user(
        email="regular@example.com",
        display_name="Reg",
        role=Role.REGULAR,
    )
    with pytest.raises(CommandError, match="--allow-elevate"):
        call_command(
            "register_superadmin_passkey",
            "--email=regular@example.com",
            "--display-name=Reg",
        )
    user = User.objects.get(email="regular@example.com")
    assert user.role == Role.REGULAR  # unchanged
    assert EnrollmentToken.objects.filter(user=user).count() == 0


@pytest.mark.django_db
def test_elevates_with_explicit_flag() -> None:
    User.objects.create_user(
        email="promote@example.com",
        display_name="Promo",
        role=Role.REGULAR,
    )
    out = io.StringIO()
    call_command(
        "register_superadmin_passkey",
        "--email=promote@example.com",
        "--display-name=Promo",
        "--allow-elevate",
        stdout=out,
    )
    user = User.objects.get(email="promote@example.com")
    assert user.role == Role.SUPERADMIN


@pytest.mark.django_db
def test_base_url_override_lands_in_printed_url() -> None:
    out = io.StringIO()
    call_command(
        "register_superadmin_passkey",
        "--email=base@example.com",
        "--display-name=Base",
        "--base-url=https://ztops.zerotrustoffsec.com",
        stdout=out,
    )
    output = out.getvalue()
    assert "https://ztops.zerotrustoffsec.com/webauthn/enroll/" in output
