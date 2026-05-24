"""Form for Vendor create/edit."""

from __future__ import annotations

from django import forms

from .models import Vendor


class VendorForm(forms.ModelForm):
    class Meta:
        model = Vendor
        fields = ("slug", "name", "description", "website")
        widgets = {  # noqa: RUF012
            "description": forms.Textarea(attrs={"rows": 3}),
            "slug": forms.TextInput(attrs={"placeholder": "acme"}),
            "name": forms.TextInput(attrs={"placeholder": "Acme Corp"}),
            "website": forms.URLInput(attrs={"placeholder": "https://acme.example"}),
        }
