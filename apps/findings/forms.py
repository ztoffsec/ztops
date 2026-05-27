"""Forms for the Finding CRUD surface."""

from __future__ import annotations

from django import forms

from .models import Finding, FindingNote


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
            "engagement",
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
