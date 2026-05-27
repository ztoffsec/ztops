"""Tests for the Artifacts upload/download/delete views."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings

from apps.accounts.models import Role, User
from apps.attachments.models import Attachment
from apps.findings.models import Channel, Finding, ReviewState
from apps.vendors.models import Vendor

if TYPE_CHECKING:
    from django.test import Client


def _user(email: str, role: str = Role.REGULAR.value) -> User:
    return User.objects.create_user(email=email, display_name=email[:6], role=role)


def _finding(owner: User, internal_id: str = "ART-001") -> Finding:
    vendor, _ = Vendor.objects.get_or_create(slug="vart", defaults={"name": "VArt"})
    return Finding.objects.create(
        internal_id=internal_id,
        title="x",
        vendor=vendor,
        channel=Channel.OTHER,
        reported_by=owner,
    )


# ---- upload --------------------------------------------------------------


@pytest.mark.django_db
def test_owner_can_upload(client: Client, settings_root: Path) -> None:
    owner = _user("ow@example.com")
    f = _finding(owner)
    client.force_login(owner)
    payload = b"poc-bytes"
    response = client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={"file": SimpleUploadedFile("poc.py", payload, content_type="text/x-python")},
    )
    assert response.status_code == 302
    att = Attachment.objects.get(finding=f)
    assert att.filename == "poc.py"
    assert att.size_bytes == len(payload)
    assert att.sha256_hash == hashlib.sha256(payload).hexdigest()
    # File on disk.
    assert (settings_root / str(f.id) / att.sha256_hash).read_bytes() == payload


@pytest.mark.django_db
def test_owner_can_upload_multiple_files_at_once(client: Client, settings_root: Path) -> None:
    owner = _user("multi@example.com")
    f = _finding(owner)
    client.force_login(owner)
    response = client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={
            "file": [
                SimpleUploadedFile("a.txt", b"alpha"),
                SimpleUploadedFile("b.txt", b"bravo"),
                SimpleUploadedFile("c.txt", b"charlie"),
            ],
        },
    )
    assert response.status_code == 302
    assert Attachment.objects.filter(finding=f).count() == 3
    assert set(Attachment.objects.filter(finding=f).values_list("filename", flat=True)) == {
        "a.txt",
        "b.txt",
        "c.txt",
    }
    _ = settings_root


@pytest.mark.django_db
def test_non_assigned_cannot_upload(client: Client, settings_root: Path) -> None:
    owner = _user("real@example.com")
    intruder = _user("intr@example.com")
    f = _finding(owner)
    client.force_login(intruder)
    response = client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={"file": SimpleUploadedFile("evil.sh", b"x", content_type="text/plain")},
    )
    assert response.status_code == 404
    assert not Attachment.objects.filter(finding=f).exists()
    _ = settings_root  # fixture isolation


@pytest.mark.django_db
def test_upload_rejects_oversized_file(client: Client, settings_root: Path) -> None:
    owner = _user("big@example.com")
    f = _finding(owner)
    client.force_login(owner)
    with override_settings(ATTACHMENTS_MAX_SIZE=8):
        response = client.post(
            f"/findings/artifacts/{f.id}/upload/",
            data={"file": SimpleUploadedFile("huge.bin", b"X" * 32)},
        )
    assert response.status_code == 302  # redirects with flash
    assert not Attachment.objects.filter(finding=f).exists()
    _ = settings_root


@pytest.mark.django_db
def test_upload_dedup_does_not_create_duplicate_row(
    client: Client,
    settings_root: Path,
) -> None:
    owner = _user("dd@example.com")
    f = _finding(owner)
    client.force_login(owner)
    payload = b"identical"
    client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={"file": SimpleUploadedFile("a.txt", payload)},
    )
    client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={"file": SimpleUploadedFile("a.txt", payload)},
    )
    assert Attachment.objects.filter(finding=f).count() == 1
    _ = settings_root


# ---- download ------------------------------------------------------------


@pytest.mark.django_db
def test_any_authenticated_user_can_download_approved(
    client: Client,
    settings_root: Path,
) -> None:
    """Approved findings: any authenticated researcher may download artifacts."""
    owner = _user("dl_ow@example.com")
    viewer = _user("dl_vw@example.com")  # not assigned
    f = _finding(owner)
    payload = b"hello"

    client.force_login(owner)
    client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={"file": SimpleUploadedFile("hi.txt", payload, content_type="text/plain")},
    )
    att = Attachment.objects.get(finding=f)

    # Make the team-visibility explicit (this is also the model default).
    f.review_state = ReviewState.APPROVED.value
    f.save(update_fields=["review_state"])

    client.force_login(viewer)
    response = client.get(f"/findings/artifacts/{f.id}/{att.id}/download/")
    assert response.status_code == 200
    # Must NEVER serve as text/html or the original mime — application/octet-stream.
    assert response["Content-Type"] == "application/octet-stream"
    assert response["X-Content-Type-Options"] == "nosniff"
    assert response["Content-Disposition"].startswith("attachment;")
    body = b"".join(response.streaming_content)
    assert body == payload
    _ = settings_root


@pytest.mark.django_db
def test_unauthorized_user_cannot_download_non_approved(
    client: Client,
    settings_root: Path,
) -> None:
    """ZT-001: a non-reporter, non-reviewer cannot download artifacts of a
    finding that is not approved (pending / under_review / rejected)."""
    owner = _user("na_ow@example.com")
    outsider = _user("na_out@example.com")  # not reporter, reviewer, or superadmin
    f = _finding(owner)

    client.force_login(owner)
    client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={"file": SimpleUploadedFile("secret.txt", b"poc", content_type="text/plain")},
    )
    att = Attachment.objects.get(finding=f)

    # Move out of the publicly-visible (approved) default into review limbo.
    f.review_state = ReviewState.PENDING.value
    f.save(update_fields=["review_state"])
    assert not f.is_publicly_visible

    client.force_login(outsider)
    response = client.get(f"/findings/artifacts/{f.id}/{att.id}/download/")
    assert response.status_code == 404
    _ = settings_root


@pytest.mark.django_db
def test_anonymous_download_redirects(client: Client, settings_root: Path) -> None:
    owner = _user("anon@example.com")
    f = _finding(owner)
    client.force_login(owner)
    client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={"file": SimpleUploadedFile("x.bin", b"x")},
    )
    att = Attachment.objects.get(finding=f)
    client.logout()
    response = client.get(f"/findings/artifacts/{f.id}/{att.id}/download/")
    assert response.status_code == 302
    assert "/super/login/" in response["Location"]
    _ = settings_root


# ---- delete --------------------------------------------------------------


@pytest.mark.django_db
def test_uploader_can_delete_their_attachment(
    client: Client,
    settings_root: Path,
) -> None:
    owner = _user("u@example.com")
    f = _finding(owner)
    client.force_login(owner)
    client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={"file": SimpleUploadedFile("rm.txt", b"y")},
    )
    att = Attachment.objects.get(finding=f)
    blob = settings_root / str(f.id) / att.sha256_hash
    assert blob.exists()

    response = client.post(f"/findings/artifacts/{f.id}/{att.id}/delete/")
    assert response.status_code == 302
    assert not Attachment.objects.filter(pk=att.id).exists()
    assert not blob.exists()


@pytest.mark.django_db
def test_random_user_cannot_delete_someone_elses(
    client: Client,
    settings_root: Path,
) -> None:
    owner = _user("orig@example.com")
    other = _user("oth@example.com")
    f = _finding(owner)
    client.force_login(owner)
    client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={"file": SimpleUploadedFile("a.txt", b"a")},
    )
    att = Attachment.objects.get(finding=f)

    client.force_login(other)
    response = client.post(f"/findings/artifacts/{f.id}/{att.id}/delete/")
    assert response.status_code == 404
    assert Attachment.objects.filter(pk=att.id).exists()
    _ = settings_root


@pytest.mark.django_db
def test_superadmin_can_delete_anyones(
    client: Client,
    settings_root: Path,
) -> None:
    owner = _user("sao@example.com")
    su = _user("su@example.com", role=Role.SUPERADMIN.value)
    f = _finding(owner)
    client.force_login(owner)
    client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={"file": SimpleUploadedFile("sa.txt", b"sa")},
    )
    att = Attachment.objects.get(finding=f)

    client.force_login(su)
    response = client.post(f"/findings/artifacts/{f.id}/{att.id}/delete/")
    assert response.status_code == 302
    assert not Attachment.objects.filter(pk=att.id).exists()
    _ = settings_root


# ---- finding deletion cascades to attachment blobs ----------------------


@pytest.mark.django_db
def test_finding_delete_purges_attachment_bucket(
    client: Client,
    settings_root: Path,
) -> None:
    owner = _user("p@example.com")
    f = _finding(owner)
    client.force_login(owner)
    client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={"file": SimpleUploadedFile("p.txt", b"p")},
    )
    bucket = settings_root / str(f.id)
    assert bucket.exists()

    response = client.post(f"/findings/{f.id}/delete/")
    assert response.status_code == 302
    assert not bucket.exists()
