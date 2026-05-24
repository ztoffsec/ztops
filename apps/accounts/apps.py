"""AppConfig for apps.accounts."""

from __future__ import annotations

from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.accounts"
    label = "accounts"

    def ready(self) -> None:
        # Register the REGISTER_SUPERADMIN approval handler. Import for
        # side-effect; the handler binds itself via @register_handler.
        from . import handlers  # noqa: F401, PLC0415
