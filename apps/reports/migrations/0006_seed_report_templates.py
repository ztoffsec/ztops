"""Seed the two report templates (Pen Test, Red Team) with default sections.

Idempotent (get_or_create by slug). Superadmins edit sections/boilerplate
and can add/reorder/remove them from the UI afterwards.
"""

from __future__ import annotations

from django.db import migrations
from django.utils.text import slugify

_SECTIONS = [
    ("cover", "Cover"),
    ("confidentiality", "Confidentiality"),
    ("index", "Index"),
    ("executive_summary", "Executive Summary"),
    ("findings_summary", "Findings Summary"),
    ("methodology", "Methodology"),
    ("findings", "Findings"),
    ("conclusion", "Conclusion"),
    ("annexes", "Annexes"),
]

_CONFIDENTIALITY = (
    "This document contains confidential and proprietary information intended "
    "solely for the named client. It must not be disclosed, copied, or "
    "distributed to any third party without prior written consent. All "
    "findings are provided for remediation purposes only."
)

_METHODOLOGY_INTRO = (
    "The assessment followed an industry-standard methodology tailored to the "
    "engagement scope. The scope-specific approach for this engagement is "
    "detailed below."
)

_TEMPLATES = [
    ("Pen Test", True),
    ("Red Team", False),
]


def seed(apps, schema_editor) -> None:  # noqa: ANN001
    ReportTemplate = apps.get_model("reports", "ReportTemplate")
    TemplateSection = apps.get_model("reports", "TemplateSection")
    for name, is_default in _TEMPLATES:
        tpl, _ = ReportTemplate.objects.get_or_create(
            slug=slugify(name),
            defaults={"name": name, "is_default": is_default},
        )
        if tpl.sections.exists():
            continue
        for order, (kind, title) in enumerate(_SECTIONS):
            body = ""
            if kind == "confidentiality":
                body = _CONFIDENTIALITY
            elif kind == "methodology":
                body = _METHODOLOGY_INTRO
            TemplateSection.objects.create(
                template=tpl,
                kind=kind,
                title=title,
                body=body,
                order=order,
            )


def unseed(apps, schema_editor) -> None:  # noqa: ANN001
    ReportTemplate = apps.get_model("reports", "ReportTemplate")
    ReportTemplate.objects.filter(slug__in=["pen-test", "red-team"]).delete()


class Migration(migrations.Migration):
    dependencies = [("reports", "0005_reporttemplate_report_template_templatesection")]
    operations = [migrations.RunPython(seed, unseed)]
