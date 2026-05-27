"""Seed the default engagement scope categories.

Idempotent (get_or_create by slug); a superadmin can add/remove/reorder
these from the UI in a later phase.
"""

from __future__ import annotations

from django.db import migrations

_DEFAULTS = [
    "Web Application",
    "External Network Testing",
    "Internal Network Testing",
    "API Security",
    "Mobile Application",
    "Cloud Security",
    "Binary Analysis",
    "Kernel Exploitation",
    "Social Engineering",
    "Wireless",
    "Red Team",
    "Physical",
]


def _slugify(name: str) -> str:
    return name.lower().replace(" ", "-")


def seed(apps, schema_editor) -> None:  # noqa: ANN001
    ScopeCategory = apps.get_model("reports", "ScopeCategory")
    for order, name in enumerate(_DEFAULTS):
        ScopeCategory.objects.get_or_create(
            slug=_slugify(name),
            defaults={"name": name, "order": order},
        )


def unseed(apps, schema_editor) -> None:  # noqa: ANN001
    ScopeCategory = apps.get_model("reports", "ScopeCategory")
    ScopeCategory.objects.filter(slug__in=[_slugify(n) for n in _DEFAULTS]).delete()


class Migration(migrations.Migration):
    dependencies = [("reports", "0001_initial")]
    operations = [migrations.RunPython(seed, unseed)]
