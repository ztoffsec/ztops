"""Forms for the report builder (metadata step)."""

from __future__ import annotations

from django import forms

from apps.findings.forms import FindingForm

from .models import PointOfContact, Report


class ReportFindingForm(FindingForm):
    """FindingForm for the report context: the vendor is fixed to the
    report's client (set server-side), so it is not a user-editable field."""

    class Meta(FindingForm.Meta):
        fields = tuple(f for f in FindingForm.Meta.fields if f != "vendor")


class _ResearcherMultiple(forms.ModelMultipleChoiceField):
    def label_from_instance(self, obj: object) -> str:
        return getattr(obj, "display_name", "") or getattr(obj, "email", "")


class _ManagerChoice(forms.ModelChoiceField):
    def label_from_instance(self, obj: object) -> str:
        return getattr(obj, "display_name", "") or getattr(obj, "email", "")


class ReportForm(forms.ModelForm):
    # Classification is a fixed CONFIDENTIAL (model default) — never editable,
    # so it is intentionally absent from this form.
    class Meta:
        model = Report
        fields = (
            "name",
            "client",
            "researchers",
            "engagement_manager",
            "scope_categories",
            "engagement_start",
            "engagement_end",
        )
        field_classes = {  # noqa: RUF012
            "researchers": _ResearcherMultiple,
            "engagement_manager": _ManagerChoice,
        }
        widgets = {  # noqa: RUF012
            # Checkbox list (click to toggle) instead of a native multi-select
            # that needs ctrl+click. Labels are display names (field_classes).
            "researchers": forms.CheckboxSelectMultiple,
            "scope_categories": forms.CheckboxSelectMultiple,
            "engagement_start": forms.DateInput(attrs={"type": "date"}),
            "engagement_end": forms.DateInput(attrs={"type": "date"}),
        }


PointOfContactFormSet = forms.inlineformset_factory(
    Report,
    PointOfContact,
    fields=("name", "role", "email", "phone"),
    extra=1,
    can_delete=True,
    widgets={
        "name": forms.TextInput(attrs={"placeholder": "Jane Doe"}),
        "email": forms.EmailInput(attrs={"placeholder": "jane@client.example"}),
        "phone": forms.TextInput(attrs={"placeholder": "+1 555 0100"}),
    },
)
