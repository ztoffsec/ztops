"""Forms for the Finding CRUD surface."""

from __future__ import annotations

from urllib.parse import urlparse

from django import forms

from .models import Finding, FindingNote

# Schemes allowed in Finding.references. Anything else (javascript:, data:,
# file:, vbscript:, custom URI schemes) would render as a clickable link in
# detail.html and a javascript: link executes in the victim's session, so
# the form refuses to save it. Mirrors the bleach allowlist for markdown.
_REFERENCE_ALLOWED_SCHEMES = frozenset({"http", "https"})


class FindingForm(forms.ModelForm):
    """Editable Finding fields. `severity` is derived on save and excluded."""

    # Not a model field: free-text, one affected host per line. Parsed and
    # vendor-scoped in the view (_sync_affected_hosts). Declared here so the
    # value arrives validated via cleaned_data, not raw request.POST.
    affected_hosts_text = forms.CharField(
        required=False,
        widget=forms.Textarea(
            attrs={
                "rows": 4,
                "placeholder": "example.com\nhttps://example.com/admin?id=1\n10.0.0.5",
            },
        ),
    )

    class Meta:
        model = Finding
        fields = (
            "title",
            "vendor",
            "channel",
            "channel_program",
            "cve_id",
            "cvss_31_score",
            "cvss_31_vector",
            "cvss_4_score",
            "cvss_4_vector",
            "status",
            "narrative",
            "poc",
            "remediation",
            "cwe_ids",
            "references",
            "disclosed_at",
            "acknowledged_at",
            "patched_at",
            "published_at",
        )
        widgets = {  # noqa: RUF012 — Django ModelForm convention
            "narrative": forms.Textarea(attrs={"rows": 10}),
            "poc": forms.Textarea(attrs={"rows": 8}),
            "remediation": forms.Textarea(attrs={"rows": 6}),
            # cwe_ids + references are rendered by the chip-style tag-input
            # widget in the template. The hidden input holds the JSON array
            # the JS keeps in sync. Default to an empty array.
            "cwe_ids": forms.HiddenInput(attrs={"data-tag-input-value": ""}),
            "references": forms.HiddenInput(attrs={"data-tag-input-value": ""}),
            "disclosed_at": forms.DateInput(attrs={"type": "date"}),
            "acknowledged_at": forms.DateInput(attrs={"type": "date"}),
            "patched_at": forms.DateInput(attrs={"type": "date"}),
            "published_at": forms.DateInput(attrs={"type": "date"}),
            # data-* attrs wire these inputs to the CVSS calculator JS.
            "cvss_31_score": forms.NumberInput(
                attrs={"step": "0.1", "min": "0", "max": "10", "data-cvss31-score": ""},
            ),
            "cvss_31_vector": forms.TextInput(
                attrs={
                    "placeholder": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "data-cvss31-vector": "",
                },
            ),
            "cvss_4_score": forms.NumberInput(
                attrs={"step": "0.1", "min": "0", "max": "10", "data-cvss40-score": ""},
            ),
            "cvss_4_vector": forms.TextInput(
                attrs={
                    "placeholder": (
                        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                    ),
                    "data-cvss40-vector": "",
                },
            ),
        }

    def clean_references(self) -> list[str]:
        """Reject references that aren't http/https URLs.

        The chip input lets the user type any string. Without this, a
        reference like `javascript:alert(document.cookie)` lands in the
        JSONField and detail.html renders it inside an <a href>, executing
        in the clicker's session. Strip whitespace, drop empties, and
        require a valid http/https scheme on every survivor.
        """
        raw = self.cleaned_data.get("references") or []
        if not isinstance(raw, list):
            msg = "References must be a list of URLs."
            raise forms.ValidationError(msg)
        cleaned: list[str] = []
        for entry in raw:
            if not isinstance(entry, str):
                msg = "References must be a list of URL strings."
                raise forms.ValidationError(msg)
            value = entry.strip()
            if not value:
                continue
            parsed = urlparse(value)
            if parsed.scheme.lower() not in _REFERENCE_ALLOWED_SCHEMES:
                msg = (
                    f"Reference {value!r} must start with http:// or https://. "
                    "Other URL schemes are not allowed."
                )
                raise forms.ValidationError(msg)
            if not parsed.netloc:
                msg = f"Reference {value!r} is missing a host."
                raise forms.ValidationError(msg)
            cleaned.append(value)
        return cleaned


class FindingNoteForm(forms.ModelForm):
    """Append-only note on a Finding. Author + email are set by the view."""

    class Meta:
        model = FindingNote
        fields = ("body",)
        widgets = {  # noqa: RUF012
            "body": forms.Textarea(
                attrs={"rows": 4, "placeholder": "Add a note (markdown supported)..."},
            ),
        }
