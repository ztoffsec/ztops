"""Tests for the reassign_internal_ids backfill command."""

from __future__ import annotations

import re

import pytest
from django.core.management import call_command

from apps.accounts.models import User
from apps.findings.models import Channel, Finding
from apps.vendors.models import Vendor

_CANONICAL = re.compile(r"^ZT-\d{4}-\d{7}$")


def _reporter() -> User:
    return User.objects.create_user(email="rep@example.com", display_name="Rep")


def _finding(internal_id: str, reporter: User, slug: str) -> Finding:
    vendor, _ = Vendor.objects.get_or_create(slug=slug, defaults={"name": slug.title()})
    # Bypass save()'s auto-id so we can seed a legacy/manual id verbatim.
    f = Finding(
        internal_id=internal_id,
        title="x",
        vendor=vendor,
        channel=Channel.OTHER.value,
        reported_by=reporter,
    )
    super(Finding, f).save()  # type: ignore[misc]
    return f


@pytest.mark.django_db
def test_dry_run_changes_nothing() -> None:
    reporter = _reporter()
    _finding("MAT-001", reporter, "mat")
    call_command("reassign_internal_ids")  # no --apply
    assert Finding.objects.get(title="x").internal_id == "MAT-001"


@pytest.mark.django_db
def test_apply_reassigns_legacy_ids() -> None:
    reporter = _reporter()
    _finding("MAT-001", reporter, "mat")
    _finding("K8S-002", reporter, "glo")

    call_command("reassign_internal_ids", "--apply")

    for f in Finding.objects.all():
        assert _CANONICAL.match(f.internal_id), f.internal_id
    # No collisions.
    ids = list(Finding.objects.values_list("internal_id", flat=True))
    assert len(ids) == len(set(ids))


@pytest.mark.django_db
def test_already_canonical_is_left_untouched() -> None:
    reporter = _reporter()
    keep = _finding("ZT-2026-0000001", reporter, "can")
    _finding("LEGACY-9", reporter, "leg")

    call_command("reassign_internal_ids", "--apply")

    keep.refresh_from_db()
    assert keep.internal_id == "ZT-2026-0000001"  # canonical → preserved
    legacy = Finding.objects.exclude(pk=keep.pk).get()
    assert _CANONICAL.match(legacy.internal_id)


@pytest.mark.django_db
def test_idempotent_second_run_is_noop() -> None:
    reporter = _reporter()
    _finding("MAT-001", reporter, "mat")

    call_command("reassign_internal_ids", "--apply")
    after_first = Finding.objects.get(title="x").internal_id

    call_command("reassign_internal_ids", "--apply")
    after_second = Finding.objects.get(title="x").internal_id

    assert after_first == after_second  # nothing re-rolled
