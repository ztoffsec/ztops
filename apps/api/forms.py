"""Forms for the API token management UI."""

from __future__ import annotations

from django import forms
from django.conf import settings
from django.core.validators import RegexValidator

from .models import NAME_MAX_LEN
from .scopes import Scope
from .services import lifetime_choices

_NAME_VALIDATOR = RegexValidator(
    regex=r"\A[A-Za-z0-9 ._:@()\-]+\Z",
    message="Use letters, digits, spaces and . _ : @ ( ) - only.",
)


class ApiTokenCreateForm(forms.Form):
    name = forms.CharField(
        max_length=NAME_MAX_LEN,
        label="Name",
        validators=[_NAME_VALIDATOR],
        widget=forms.TextInput(
            attrs={"placeholder": "laptop research agent", "autocomplete": "off"}
        ),
    )
    scopes = forms.MultipleChoiceField(
        choices=Scope.choices,
        widget=forms.CheckboxSelectMultiple,
        label="Scopes",
    )
    lifetime_days = forms.TypedChoiceField(
        coerce=int,
        label="Expires in",
        choices=(),
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        field = self.fields["lifetime_days"]
        field.choices = [(d, f"{d} days") for d in lifetime_choices()]  # type: ignore[attr-defined]
        field.initial = int(settings.API_TOKEN_DEFAULT_LIFETIME_DAYS)
