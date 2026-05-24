"""AppConfig for apps.findings."""

from __future__ import annotations

from django.apps import AppConfig


class FindingsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.findings"
    label = "findings"

    def ready(self) -> None:
        # Wire the post_save signal that auto-adds reported_by to
        # assigned_researchers on first save.
        from . import signals  # noqa: F401, PLC0415 — import for side-effect
