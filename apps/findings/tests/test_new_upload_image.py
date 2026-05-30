"""Tests for the lazy create + image upload endpoint (findings:new_upload_image).

The new-finding form has no finding id yet, so the per-finding image upload
endpoint cannot be wired. This endpoint takes the current form state along
with the image, creates the Finding when the form validates, attaches the
image as an inline attachment, and returns the IDs the client needs to
migrate the form to the edit URL. A rejected image must not leave a
phantom Finding behind.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image

from apps.accounts.models import Role, User
from apps.attachments.models import Attachment
from apps.findings.models import Channel, Finding, ReviewState, Status
from apps.vendors.models import Vendor

if TYPE_CHECKING:
    from pathlib import Path

    from django.test import Client


URL = "/findings/new/upload-image/"


def _user(email: str, role: str = Role.SUPERADMIN.value) -> User:
    return User.objects.create_user(email=email, display_name=email[:5], role=role)


def _vendor() -> Vendor:
    v, _ = Vendor.objects.get_or_create(slug="acme", defaults={"name": "Acme"})
    return v


def _png_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (4, 4), "blue").save(buf, format="PNG")
    return buf.getvalue()


def _valid_form_data(vendor: Vendor) -> dict:
    return {
        "vendor": str(vendor.id),
        "title": "Drafted via image drop",
        "channel": Channel.OTHER.value,
        "channel_program": "",
        "narrative": "stub",
        "poc": "",
        "remediation": "",
        "cve_id": "",
        "cvss_31_score": "",
        "cvss_31_vector": "",
        "cvss_4_score": "",
        "cvss_4_vector": "",
        "cwe_ids": "[]",
        "references": "[]",
        "status": Status.IN_TRIAGE.value,
        "affected_hosts_text": "",
    }


@pytest.mark.django_db
def test_anonymous_redirects_to_login(client: Client) -> None:
    resp = client.post(URL, data={})
    assert resp.status_code in (302, 301)
    assert "/super/login/" in resp["Location"]


@pytest.mark.django_db
def test_missing_image_returns_400(client: Client) -> None:
    client.force_login(_user("a@example.com"))
    resp = client.post(URL, data=_valid_form_data(_vendor()))
    assert resp.status_code == 400
    assert resp.json()["error"] == "no_file"
    assert not Finding.objects.exists()


@pytest.mark.django_db
def test_invalid_form_returns_400_and_does_not_create(client: Client) -> None:
    client.force_login(_user("b@example.com"))
    payload = _valid_form_data(_vendor())
    payload["vendor"] = ""  # required FK missing
    payload["title"] = ""  # required field missing
    payload["image"] = SimpleUploadedFile("p.png", _png_bytes(), content_type="image/png")
    resp = client.post(URL, data=payload)
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "form_invalid"
    assert "vendor" in body["errors"] or "title" in body["errors"]
    assert not Finding.objects.exists()
    assert not Attachment.objects.exists()


@pytest.mark.django_db
def test_valid_payload_creates_finding_and_inline_attachment(
    client: Client,
    settings_root: Path,
) -> None:
    user = _user("c@example.com")
    client.force_login(user)
    payload = _valid_form_data(_vendor())
    payload["image"] = SimpleUploadedFile("shot.png", _png_bytes(), content_type="image/png")

    resp = client.post(URL, data=payload)

    assert resp.status_code == 200
    body = resp.json()
    finding = Finding.objects.get(pk=body["finding_id"])
    assert finding.title == "Drafted via image drop"
    assert finding.reported_by == user
    # A review_authority (superadmin) auto approves their own submissions.
    assert finding.review_state == ReviewState.APPROVED.value
    assert body["internal_id"] == finding.internal_id
    assert body["edit_url"].endswith(f"/findings/{finding.id}/edit/")
    assert body["image_upload_url"].endswith(f"/findings/artifacts/{finding.id}/image/upload/")
    att = Attachment.objects.get(finding=finding)
    assert att.is_inline_image is True
    assert att.content_type == "image/png"
    assert body["image_url"].endswith("/image/")
    _ = settings_root


@pytest.mark.django_db
def test_non_image_rejected_and_rolls_back_finding(client: Client) -> None:
    """A bad image must not leave a phantom Finding behind."""
    client.force_login(_user("d@example.com"))
    payload = _valid_form_data(_vendor())
    payload["image"] = SimpleUploadedFile(
        "not.svg",
        b"<svg><script>x</script></svg>",
        content_type="image/svg+xml",
    )
    resp = client.post(URL, data=payload)
    assert resp.status_code == 400
    assert resp.json()["error"] == "not_an_image"
    assert not Finding.objects.exists()
    assert not Attachment.objects.exists()


@pytest.mark.django_db
def test_non_reviewer_creates_finding_in_pending(client: Client, settings_root: Path) -> None:
    """Non review authorities land in PENDING review state."""
    user = _user("e@example.com", role=Role.REGULAR.value)
    client.force_login(user)
    payload = _valid_form_data(_vendor())
    payload["image"] = SimpleUploadedFile("p.png", _png_bytes(), content_type="image/png")
    resp = client.post(URL, data=payload)
    assert resp.status_code == 200
    finding = Finding.objects.get(pk=resp.json()["finding_id"])
    assert finding.review_state == ReviewState.PENDING.value
    _ = settings_root
