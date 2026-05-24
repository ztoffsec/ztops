"""Tests for the Attachment metadata model."""

from __future__ import annotations

import hashlib

import pytest

from apps.accounts.models import User
from apps.attachments.models import Attachment, ScanStatus
from apps.findings.models import Channel, Finding
from apps.vendors.models import Vendor


def _finding(internal_id: str) -> Finding:
    reporter = User.objects.create_user(
        email=f"{internal_id.lower()}@example.com",
        display_name=internal_id,
    )
    vendor, _ = Vendor.objects.get_or_create(slug="v", defaults={"name": "V"})
    return Finding.objects.create(
        internal_id=internal_id,
        title="x",
        vendor=vendor,
        channel=Channel.OTHER,
        reported_by=reporter,
    )


@pytest.mark.django_db
def test_attachment_persists_metadata() -> None:
    f = _finding("ATT-001")
    body = b"fake poc body"
    a = Attachment.objects.create(
        finding=f,
        filename="poc.py",
        content_type="text/x-python",
        size_bytes=len(body),
        sha256_hash=hashlib.sha256(body).hexdigest(),
        storage_path="attachments/2026/05/poc.py",
        uploaded_by_email="me@example.com",
    )
    assert a.scan_status == ScanStatus.PENDING.value
    assert len(a.sha256_hash) == 64


@pytest.mark.django_db
def test_attachment_cascade_delete_with_finding() -> None:
    f = _finding("ATT-002")
    Attachment.objects.create(
        finding=f,
        filename="a",
        content_type="text/plain",
        size_bytes=1,
        sha256_hash="a" * 64,
    )
    f_id = f.id
    f.delete()
    assert Attachment.objects.filter(finding_id=f_id).count() == 0


@pytest.mark.django_db
def test_attachment_default_ordering_newest_first() -> None:
    f = _finding("ATT-003")
    first = Attachment.objects.create(
        finding=f,
        filename="1",
        content_type="text/plain",
        size_bytes=1,
        sha256_hash="b" * 64,
    )
    second = Attachment.objects.create(
        finding=f,
        filename="2",
        content_type="text/plain",
        size_bytes=1,
        sha256_hash="c" * 64,
    )
    ids = list(Attachment.objects.values_list("id", flat=True)[:2])
    assert ids == [second.id, first.id]


@pytest.mark.django_db
def test_attachment_scan_status_transitions() -> None:
    f = _finding("ATT-004")
    a = Attachment.objects.create(
        finding=f,
        filename="x",
        content_type="text/plain",
        size_bytes=1,
        sha256_hash="d" * 64,
    )
    a.scan_status = ScanStatus.CLEAN
    a.save()
    a.refresh_from_db()
    assert a.scan_status == ScanStatus.CLEAN.value
