"""Tests for the references XSS defense (form validator + template filter).

A reference like `javascript:alert(1)` used to land in the JSONField, then
the detail page rendered it inside an <a href> and any click executed in
the victim's session. The fix is two layered:

1. ``FindingForm.clean_references`` rejects anything that is not an http
   or https URL on save.
2. ``safe_external_url`` template filter degrades a bad URL to '' so the
   template renders the reference as plain text, never a clickable link,
   if a bad value ever lands in the DB by another path.

These tests cover both layers and the integration on the detail page.
"""

from __future__ import annotations

import pytest
from django.test import Client

from apps.accounts.models import Role, User
from apps.findings.forms import FindingForm
from apps.findings.models import Channel, Finding, ReviewState, Status
from apps.findings.templatetags.safe_url import safe_external_url
from apps.vendors.models import Vendor

# ---- safe_external_url filter -------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(1)",
        "JavaScript:alert(1)",  # case-insensitive scheme
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "vbscript:msgbox",
        "mailto:user@example.com",  # mailto not allowed for references
        "ftp://example.com/x",
        "//example.com/no-scheme",
        "/relative/path",
        "http://",  # missing host
        "",
        "   ",
        None,
        42,
        ["http://example.com"],
    ],
)
def test_filter_rejects_unsafe_or_invalid(value: object) -> None:
    assert safe_external_url(value) == ""


@pytest.mark.parametrize(
    "value",
    [
        "http://example.com",
        "https://example.com/path?q=1#frag",
        "HTTPS://EXAMPLE.COM",  # scheme casing
        "  https://example.com/x  ",  # surrounding whitespace
    ],
)
def test_filter_returns_url_for_http_https(value: str) -> None:
    out = safe_external_url(value)
    assert out
    assert out == value.strip()


# ---- FindingForm.clean_references ---------------------------------------


def _valid_form_data(vendor: Vendor, references: list[str] | None = None) -> dict:
    return {
        "title": "x",
        "vendor": str(vendor.id),
        "channel": Channel.OTHER.value,
        "channel_program": "",
        "cve_id": "",
        "cvss_31_score": "",
        "cvss_31_vector": "",
        "cvss_4_score": "",
        "cvss_4_vector": "",
        "status": Status.IN_TRIAGE.value,
        "narrative": "",
        "poc": "",
        "remediation": "",
        "cwe_ids": "[]",
        "references": references if references is not None else "[]",
        "disclosed_at": "",
        "acknowledged_at": "",
        "patched_at": "",
        "published_at": "",
        "affected_hosts_text": "",
    }


@pytest.mark.django_db
@pytest.mark.parametrize(
    "bad",
    [
        '["javascript:alert(1)"]',
        '["data:text/html,<script>alert(1)</script>"]',
        '["file:///etc/passwd"]',
        '["vbscript:msgbox"]',
        '["http://"]',
        '["not-a-url"]',
    ],
)
def test_form_rejects_unsafe_reference(bad: str) -> None:
    vendor, _ = Vendor.objects.get_or_create(slug="v", defaults={"name": "V"})
    form = FindingForm(data=_valid_form_data(vendor, references=bad))
    assert not form.is_valid()
    assert "references" in form.errors


@pytest.mark.django_db
def test_form_accepts_http_https_references() -> None:
    vendor, _ = Vendor.objects.get_or_create(slug="v", defaults={"name": "V"})
    form = FindingForm(
        data=_valid_form_data(
            vendor,
            references='["http://example.com", "https://example.com/path"]',
        ),
    )
    assert form.is_valid(), form.errors
    assert form.cleaned_data["references"] == [
        "http://example.com",
        "https://example.com/path",
    ]


@pytest.mark.django_db
def test_form_strips_whitespace_and_drops_empties() -> None:
    vendor, _ = Vendor.objects.get_or_create(slug="v", defaults={"name": "V"})
    form = FindingForm(
        data=_valid_form_data(
            vendor,
            references='["  https://example.com/x  ", "", "   "]',
        ),
    )
    assert form.is_valid(), form.errors
    assert form.cleaned_data["references"] == ["https://example.com/x"]


# ---- Detail page render -------------------------------------------------


@pytest.mark.django_db
def test_detail_does_not_render_bad_reference_as_link(client: Client) -> None:
    """Force a bad reference into the DB and confirm the template strips it.

    Belt-and-suspenders for the filter: even if the validator is bypassed
    (raw SQL, restored backup) the page must not emit a clickable link.
    """
    user = User.objects.create_user(
        email="r@example.com",
        display_name="r",
        role=Role.SUPERADMIN.value,
    )
    vendor, _ = Vendor.objects.get_or_create(slug="v", defaults={"name": "V"})
    f = Finding.objects.create(
        internal_id="",
        title="t",
        vendor=vendor,
        channel=Channel.OTHER.value,
        reported_by=user,
        review_state=ReviewState.APPROVED.value,
    )
    # Bypass the form, mimicking a stale backup or future code path.
    Finding.objects.filter(pk=f.pk).update(
        references=["javascript:alert(1)", "https://example.com/ok"],
    )

    client.force_login(user)
    resp = client.get(f"/findings/{f.id}/")
    html = resp.content.decode()
    # The unsafe entry is shown as plain text, not as an href.
    assert 'href="javascript:' not in html
    assert "javascript:alert(1)" in html  # text still visible
    # The clean entry still becomes a real link.
    assert 'href="https://example.com/ok"' in html
