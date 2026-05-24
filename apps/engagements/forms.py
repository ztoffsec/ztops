"""Forms for Engagement, Asset, and ScopeRule CRUD."""

from __future__ import annotations

from django import forms

from .models import Asset, Engagement, ScopeRule


class EngagementForm(forms.ModelForm):
    class Meta:
        model = Engagement
        fields = (
            "slug",
            "name",
            "engagement_type",
            "status",
            "target_vendor",
            "description",
            "started_at",
            "completed_at",
        )
        widgets = {  # noqa: RUF012
            "description": forms.Textarea(attrs={"rows": 6}),
            "started_at": forms.DateInput(attrs={"type": "date"}),
            "completed_at": forms.DateInput(attrs={"type": "date"}),
        }


class AssetForm(forms.ModelForm):
    class Meta:
        model = Asset
        fields = ("kind", "identifier", "description", "in_scope")
        widgets = {  # noqa: RUF012
            "description": forms.Textarea(attrs={"rows": 3}),
        }


class ScopeRuleForm(forms.ModelForm):
    class Meta:
        model = ScopeRule
        fields = ("rule_type", "pattern", "notes")
        widgets = {  # noqa: RUF012
            "notes": forms.Textarea(attrs={"rows": 3}),
        }
