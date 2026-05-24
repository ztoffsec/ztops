"""Tests for the Vendor model."""

from __future__ import annotations

import pytest
from django.db import IntegrityError

from apps.accounts.models import User
from apps.vendors.models import Vendor


@pytest.mark.django_db
def test_vendor_creation_minimal() -> None:
    v = Vendor.objects.create(slug="acme", name="Acme Inc.")
    assert v.id is not None
    assert v.slug == "acme"
    assert v.created_at is not None


@pytest.mark.django_db
def test_vendor_slug_is_unique() -> None:
    Vendor.objects.create(slug="dupv", name="First")
    with pytest.raises(IntegrityError):
        Vendor.objects.create(slug="dupv", name="Second")


@pytest.mark.django_db
def test_vendor_creator_persists() -> None:
    user = User.objects.create_user(email="c@example.com", display_name="C")
    v = Vendor.objects.create(
        slug="vc",
        name="VC",
        created_by=user,
        created_by_email=user.email,
    )
    assert v.created_by_id == user.id
    assert v.created_by_email == "c@example.com"


@pytest.mark.django_db
def test_vendor_creator_fk_set_null_on_user_delete() -> None:
    user = User.objects.create_user(email="d@example.com", display_name="D")
    v = Vendor.objects.create(
        slug="vd",
        name="VD",
        created_by=user,
        created_by_email=user.email,
    )
    user.delete()
    v.refresh_from_db()
    assert v.created_by is None
    assert v.created_by_email == "d@example.com"  # snapshot preserved


@pytest.mark.django_db
def test_vendor_str_returns_name() -> None:
    v = Vendor.objects.create(slug="sv", name="Display Name")
    assert str(v) == "Display Name"
