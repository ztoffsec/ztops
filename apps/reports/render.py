"""Assemble a report into the context a PDF template renders.

Walks the report's template sections (enabled, in order) and produces, for
each, the HTML to render. Dynamic sections (cover, index, findings summary,
findings, annexes) are generated from the report's data; the static ones
(confidentiality, methodology, custom) use the template's editable
boilerplate. Methodology concatenates a per-scope snippet for each selected
scope category.

`safe_url_fetcher` is the security boundary for PDF rendering: WeasyPrint
does not honour CSP, so without it a crafted ``<img src>`` in report content
would make the server fetch an arbitrary URL (SSRF). The fetcher blocks every
network/filesystem URL and allows only ``data:`` URIs (the logo is embedded
as one).
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import TYPE_CHECKING

from django.conf import settings

from apps.findings.markdown import render_markdown

if TYPE_CHECKING:
    from .models import Report

# Severity ordering for the findings section (worst first).
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}

# The canonical fallback section order when a report has no template.
_FALLBACK_SECTIONS = [
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


def safe_url_fetcher(url: str, *args: object, **kwargs: object) -> dict:
    """WeasyPrint URL fetcher that allows only ``data:`` URIs.

    Blocks http/https/file/etc. so PDF rendering can never be coerced into
    fetching an arbitrary URL (SSRF) via a crafted image/link in report
    content.
    """
    if url.startswith("data:"):
        from weasyprint import default_url_fetcher  # noqa: PLC0415

        return default_url_fetcher(url)
    msg = f"Blocked non-data URL during PDF render: {url[:60]}"
    raise ValueError(msg)


def _logo_data_uri() -> str:
    """The brand logo as a data: URI (embedded so no network fetch is needed)."""
    for name in ("img/zerotrust-logo-light.png", "img/zerotrust-logo-dark.png"):
        for root in [*settings.STATICFILES_DIRS, getattr(settings, "STATIC_ROOT", "")]:
            if not root:
                continue
            path = Path(root) / name
            if path.exists():
                data = base64.b64encode(path.read_bytes()).decode()
                return f"data:image/png;base64,{data}"
    return ""


def _finding_html(finding: object) -> dict:
    return {
        "finding": finding,
        "narrative_html": render_markdown(finding.narrative),
        "poc_html": render_markdown(finding.poc),
        "remediation_html": render_markdown(finding.remediation),
        "affected_hosts": list(finding.affected_hosts.order_by("value")),
    }


def assemble_report(report: Report) -> dict:
    """Build the full render context for a report's PDF."""
    template = report.template
    if template is not None:
        section_specs = [
            (s.kind, s.title, s.body)
            for s in template.sections.filter(enabled=True).order_by("order")
        ]
    else:
        section_specs = [(kind, title, "") for kind, title in _FALLBACK_SECTIONS]

    scopes = list(report.scope_categories.order_by("order", "name"))
    findings = sorted(
        report.findings.select_related("vendor").all(),
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 5), f.internal_id),
    )

    days = None
    if report.engagement_start and report.engagement_end:
        days = (report.engagement_end - report.engagement_start).days + 1

    # Per-template colour theme (navy for Pen Test/default, red for Red Team).
    slug = template.slug if template is not None else ""
    if slug == "red-team":
        theme = {
            "accent": "#dc2626",
            "g1": "rgba(220,38,38,0.40)",
            "g2": "rgba(120,20,20,0.30)",
        }
    else:
        theme = {
            "accent": "#1e40af",
            "g1": "rgba(30,64,175,0.45)",
            "g2": "rgba(13,28,68,0.35)",
        }

    sections: list[dict] = []
    for kind, title, body in section_specs:
        block: dict = {"kind": kind, "title": title}
        if kind == "confidentiality":
            block["html"] = render_markdown(body)
        elif kind == "executive_summary":
            block["html"] = render_markdown(report.executive_summary)
        elif kind == "conclusion":
            block["html"] = render_markdown(report.conclusion)
        elif kind == "methodology":
            block["intro_html"] = render_markdown(body)
            block["scopes"] = [
                {"name": s.name, "html": render_markdown(s.methodology)}
                for s in scopes
                if s.methodology
            ]
        elif kind == "custom":
            block["html"] = render_markdown(body)
        elif kind == "annexes":
            block["annexes"] = [
                {"letter": chr(65 + i), "title": a.title, "html": render_markdown(a.body)}
                for i, a in enumerate(report.annexes.order_by("order", "title"))
            ]
        # cover / index / findings_summary / findings use top-level context below.
        sections.append(block)

    return {
        "report": report,
        "sections": sections,
        "scopes": scopes,
        "findings": [_finding_html(f) for f in findings],
        "findings_raw": findings,
        "days": days,
        "logo": _logo_data_uri(),
        "theme": theme,
    }
