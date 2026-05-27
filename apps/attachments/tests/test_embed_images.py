"""Tests for inline embedded images (Phase 3b).

Security focus: only re-encoded raster images are servable inline; every
other artifact stays download-only (no stored-XSS bypass), non-images are
rejected, and the re-encode actually rewrites the bytes.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image

from apps.accounts.models import Role, User
from apps.attachments.images import ImageRejected, reencode_image
from apps.attachments.models import Attachment
from apps.findings.models import Channel, Finding, ReviewState
from apps.vendors.models import Vendor

if TYPE_CHECKING:
    from pathlib import Path

    from django.test import Client


def _user(email: str, role: str = Role.SUPERADMIN.value) -> User:
    return User.objects.create_user(email=email, display_name=email[:5], role=role)


def _finding(owner: User) -> Finding:
    vendor, _ = Vendor.objects.get_or_create(slug="v", defaults={"name": "V"})
    return Finding.objects.create(
        internal_id="",
        title="x",
        vendor=vendor,
        channel=Channel.OTHER.value,
        reported_by=owner,
        review_state=ReviewState.APPROVED.value,
    )


def _png_bytes(color: str = "red", size: tuple[int, int] = (3, 3)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="PNG")
    return buf.getvalue()


# ---- reencode_image unit ------------------------------------------------


def test_reencode_accepts_and_rewrites_a_png() -> None:
    clean, content_type, ext = reencode_image(_png_bytes())
    assert content_type == "image/png"
    assert ext == "png"
    # The bytes are a real, decodable PNG after re-encode.
    assert Image.open(io.BytesIO(clean)).format == "PNG"


def test_reencode_rejects_svg() -> None:
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    with pytest.raises(ImageRejected):
        reencode_image(svg)


def test_reencode_rejects_non_image() -> None:
    with pytest.raises(ImageRejected):
        reencode_image(b"this is not an image at all")


# ---- upload_image view --------------------------------------------------


@pytest.mark.django_db
def test_upload_image_creates_inline_attachment(client: Client, settings_root: Path) -> None:
    owner = _user("img@example.com")
    f = _finding(owner)
    client.force_login(owner)
    resp = client.post(
        f"/findings/artifacts/{f.id}/image/upload/",
        data={"image": SimpleUploadedFile("shot.png", _png_bytes(), content_type="image/png")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["url"].endswith("/image/")
    att = Attachment.objects.get(finding=f)
    assert att.is_inline_image is True
    assert att.content_type == "image/png"
    _ = settings_root


@pytest.mark.django_db
def test_upload_image_rejects_non_image(client: Client, settings_root: Path) -> None:
    owner = _user("bad@example.com")
    f = _finding(owner)
    client.force_login(owner)
    resp = client.post(
        f"/findings/artifacts/{f.id}/image/upload/",
        data={"image": SimpleUploadedFile("x.svg", b"<svg><script>x</script></svg>")},
    )
    assert resp.status_code == 400
    assert not Attachment.objects.filter(finding=f).exists()
    _ = settings_root


@pytest.mark.django_db
def test_upload_image_dedups(client: Client, settings_root: Path) -> None:
    owner = _user("dup@example.com")
    f = _finding(owner)
    client.force_login(owner)
    png = _png_bytes()
    for _ in range(2):
        client.post(
            f"/findings/artifacts/{f.id}/image/upload/",
            data={"image": SimpleUploadedFile("a.png", png, content_type="image/png")},
        )
    assert Attachment.objects.filter(finding=f).count() == 1
    _ = settings_root


@pytest.mark.django_db
def test_non_editor_cannot_upload_image(client: Client, settings_root: Path) -> None:
    owner = _user("o@example.com")
    outsider = _user("out@example.com", role=Role.REGULAR.value)
    f = _finding(owner)
    client.force_login(outsider)
    resp = client.post(
        f"/findings/artifacts/{f.id}/image/upload/",
        data={"image": SimpleUploadedFile("a.png", _png_bytes(), content_type="image/png")},
    )
    assert resp.status_code == 404
    _ = settings_root


# ---- serve_image view ---------------------------------------------------


@pytest.mark.django_db
def test_serve_image_returns_inline_image(client: Client, settings_root: Path) -> None:
    owner = _user("s@example.com")
    f = _finding(owner)
    client.force_login(owner)
    up = client.post(
        f"/findings/artifacts/{f.id}/image/upload/",
        data={"image": SimpleUploadedFile("a.png", _png_bytes(), content_type="image/png")},
    )
    url = up.json()["url"]
    resp = client.get(url)
    assert resp.status_code == 200
    assert resp["Content-Type"] == "image/png"
    assert resp["X-Content-Type-Options"] == "nosniff"
    assert "inline" in resp["Content-Disposition"]
    _ = settings_root


@pytest.mark.django_db
def test_serve_image_refuses_a_regular_attachment(client: Client, settings_root: Path) -> None:
    """The XSS-prevention guarantee: a normal (download-only) artifact can
    NEVER be served inline through the image endpoint, even if someone crafts
    the URL."""
    owner = _user("g@example.com")
    f = _finding(owner)
    client.force_login(owner)
    # Upload a normal artifact (not via the image path → is_inline_image False).
    client.post(
        f"/findings/artifacts/{f.id}/upload/",
        data={"file": SimpleUploadedFile("evil.html", b"<script>alert(1)</script>")},
    )
    att = Attachment.objects.get(finding=f)
    assert att.is_inline_image is False
    resp = client.get(f"/findings/artifacts/{f.id}/{att.id}/image/")
    assert resp.status_code == 404  # refused — not an inline image
    _ = settings_root
