"""Tests for the passwordless User model and UserManager."""

from __future__ import annotations

import uuid

import pytest
from django.db import IntegrityError

from apps.accounts.models import Role, User


@pytest.mark.django_db
def test_create_user_persists_a_row() -> None:
    user = User.objects.create_user(
        email="alice@example.com",
        display_name="Alice",
    )
    assert user.pk is not None
    assert User.objects.filter(email="alice@example.com").exists()


@pytest.mark.django_db
def test_user_pk_is_a_uuid_v7() -> None:
    user = User.objects.create_user(
        email="bob@example.com",
        display_name="Bob",
    )
    assert isinstance(user.id, uuid.UUID)
    # Version 7 is encoded in the upper 4 bits of the second 64-bit half.
    version = (user.id.int >> 76) & 0xF
    assert version == 7


@pytest.mark.django_db
def test_email_is_normalized_lowercase_domain() -> None:
    user = User.objects.create_user(
        email="Carol@Example.COM",
        display_name="Carol",
    )
    # BaseUserManager.normalize_email lowercases the domain part.
    assert user.email == "Carol@example.com"


@pytest.mark.django_db
def test_email_is_unique() -> None:
    User.objects.create_user(email="dup@example.com", display_name="A")
    with pytest.raises(IntegrityError):
        User.objects.create_user(email="dup@example.com", display_name="B")


@pytest.mark.django_db
def test_default_role_is_regular() -> None:
    user = User.objects.create_user(email="eve@example.com", display_name="Eve")
    assert user.role == Role.REGULAR
    assert user.is_superadmin is False


@pytest.mark.django_db
def test_superadmin_role_flag() -> None:
    user = User.objects.create_user(
        email="root@example.com",
        display_name="Root",
        role=Role.SUPERADMIN,
    )
    assert user.is_superadmin is True


@pytest.mark.django_db
def test_user_has_no_password_field() -> None:
    user = User.objects.create_user(email="nopass@example.com", display_name="NoPass")
    # The model declares `password = None`; the field is not in the schema.
    field_names = {f.name for f in user._meta.get_fields()}
    assert "password" not in field_names


@pytest.mark.django_db
def test_set_password_raises() -> None:
    user = User.objects.create_user(email="grace@example.com", display_name="Grace")
    with pytest.raises(RuntimeError, match="WebAuthn"):
        user.set_password("anything")


@pytest.mark.django_db
def test_check_password_always_false() -> None:
    user = User.objects.create_user(email="heidi@example.com", display_name="Heidi")
    assert user.check_password("anything") is False


@pytest.mark.django_db
def test_has_usable_password_false() -> None:
    user = User.objects.create_user(email="ivan@example.com", display_name="Ivan")
    assert user.has_usable_password() is False


@pytest.mark.django_db
def test_create_user_requires_email() -> None:
    with pytest.raises(ValueError, match="email"):
        User.objects.create_user(email="", display_name="Empty")


def test_manager_does_not_expose_create_superuser() -> None:
    # `createsuperuser` management command relies on this method. Its
    # absence is intentional: superadmins are created out-of-band via
    # `register_superadmin_passkey` in Paso 5.
    assert not hasattr(User.objects, "create_superuser")
