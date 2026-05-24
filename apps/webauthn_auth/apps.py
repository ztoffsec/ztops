"""AppConfig for apps.webauthn_auth."""

from __future__ import annotations

from django.apps import AppConfig


class WebAuthnAuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.webauthn_auth"
    label = "webauthn_auth"
