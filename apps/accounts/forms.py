"""Forms for the accounts surface."""

from __future__ import annotations

from django import forms

from .models import Role, User


class UserCreateForm(forms.Form):
    """Create a User. Role choice triggers different downstream flows.

    `regular` users are created directly by a superadmin (single-step).
    `superadmin` users go through the two-person rule via a
    SuperAdminApproval; the User row is created by the approval handler
    after a second superadmin endorses.
    """

    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={"placeholder": "researcher@example.com"}),
    )
    display_name = forms.CharField(
        max_length=200,
        label="Display name",
        widget=forms.TextInput(attrs={"placeholder": "First Last (handle)"}),
    )
    role = forms.ChoiceField(
        choices=Role.choices,
        initial=Role.REGULAR.value,
        label="Role",
    )

    def clean_email(self) -> str:
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            msg = "A user with this email already exists."
            raise forms.ValidationError(msg)
        return email
