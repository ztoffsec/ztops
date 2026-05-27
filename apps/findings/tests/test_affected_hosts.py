"""Tests for the affected-hosts feature on findings (Phase 2).

Focus: bulk-paste parsing, vendor-scoped reuse, and the cross-vendor
isolation guarantee — a finding can never link to another vendor's hosts.
"""

from __future__ import annotations

import pytest

from apps.accounts.models import Role, User
from apps.findings.models import AffectedHost, Channel, Finding
from apps.findings.views import _sync_affected_hosts
from apps.vendors.models import Vendor


def _reporter(email: str = "ah@example.com") -> User:
    return User.objects.create_user(email=email, display_name="AH", role=Role.SUPERADMIN)


def _finding(reporter: User, vendor: Vendor, internal: str = "") -> Finding:
    return Finding.objects.create(
        internal_id=internal,
        title="x",
        vendor=vendor,
        channel=Channel.OTHER.value,
        reported_by=reporter,
    )


@pytest.mark.django_db
def test_sync_parses_dedups_and_scopes_to_vendor() -> None:
    rep = _reporter()
    vendor = Vendor.objects.create(name="Acme", slug="acme")
    f = _finding(rep, vendor)

    _sync_affected_hosts(f, "example.com\n  EXAMPLE.com \n10.0.0.5\n\nexample.com")

    values = sorted(f.affected_hosts.values_list("value", flat=True))
    # "example.com" / "EXAMPLE.com" collapse (case-insensitive); blank dropped.
    assert values == ["10.0.0.5", "example.com"]
    # All hosts belong to this finding's vendor.
    assert all(h.vendor_id == vendor.id for h in f.affected_hosts.all())


@pytest.mark.django_db
def test_hosts_are_reused_within_a_vendor() -> None:
    rep = _reporter()
    vendor = Vendor.objects.create(name="Acme", slug="acme")
    f1 = _finding(rep, vendor)
    f2 = _finding(rep, vendor)

    _sync_affected_hosts(f1, "shared.example.com")
    _sync_affected_hosts(f2, "shared.example.com")

    # Same vendor + same value → one AffectedHost row, linked to both.
    host = AffectedHost.objects.get(vendor=vendor, value="shared.example.com")
    assert set(host.findings.values_list("id", flat=True)) == {f1.id, f2.id}


@pytest.mark.django_db
def test_same_value_different_vendor_is_a_separate_host() -> None:
    """Cross-vendor isolation: an identical host string under vendor B never
    links to vendor A's finding; each vendor gets its own AffectedHost row."""
    rep = _reporter()
    vendor_a = Vendor.objects.create(name="Acme", slug="acme")
    vendor_b = Vendor.objects.create(name="Globex", slug="globex")
    fa = _finding(rep, vendor_a)
    fb = _finding(rep, vendor_b)

    _sync_affected_hosts(fa, "portal.example.com")
    _sync_affected_hosts(fb, "portal.example.com")

    host_a = AffectedHost.objects.get(vendor=vendor_a, value="portal.example.com")
    host_b = AffectedHost.objects.get(vendor=vendor_b, value="portal.example.com")
    assert host_a.id != host_b.id
    # vendor A's finding links only vendor A's host — never B's.
    assert list(fa.affected_hosts.all()) == [host_a]
    assert host_b not in fa.affected_hosts.all()


@pytest.mark.django_db
def test_resync_replaces_the_set() -> None:
    rep = _reporter()
    vendor = Vendor.objects.create(name="Acme", slug="acme")
    f = _finding(rep, vendor)

    _sync_affected_hosts(f, "a.example.com\nb.example.com")
    assert f.affected_hosts.count() == 2

    _sync_affected_hosts(f, "b.example.com")  # drop a, keep b
    assert sorted(f.affected_hosts.values_list("value", flat=True)) == ["b.example.com"]
