"""Report builder views (Phase 4a: list / create / detail / edit metadata)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from apps.findings.markdown import render_markdown
from apps.findings.models import Finding, ReviewState
from apps.findings.views import _sync_affected_hosts

from .forms import (
    AnnexForm,
    PointOfContactFormSet,
    ReportContentForm,
    ReportFindingForm,
    ReportForm,
)
from .models import Annex, Report

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


@login_required(login_url="/super/login/")
def reports_list(request: HttpRequest) -> HttpResponse:
    reports = list(
        Report.objects.select_related("client", "engagement_manager")
        .prefetch_related("scope_categories")
        .all(),
    )
    return render(request, "tenant/reports/list.html", {"reports": reports})


@login_required(login_url="/super/login/")
@csrf_protect
def report_new(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = ReportForm(request.POST)
        formset = PointOfContactFormSet(request.POST)
        if form.is_valid() and formset.is_valid():
            report = form.save(commit=False)
            report.created_by = request.user
            report.save()
            form.save_m2m()
            formset.instance = report
            formset.save()
            messages.success(request, f"Report “{report.name}” created.")
            return redirect("reports:detail", report_id=report.id)
    else:
        form = ReportForm()
        formset = PointOfContactFormSet()
    return render(
        request,
        "tenant/reports/form.html",
        {"form": form, "formset": formset, "mode": "create"},
    )


@login_required(login_url="/super/login/")
def report_detail(request: HttpRequest, report_id: str) -> HttpResponse:
    report = get_object_or_404(
        Report.objects.select_related(
            "client", "engagement_manager", "created_by"
        ).prefetch_related("researchers", "scope_categories", "contacts", "findings"),
        pk=report_id,
    )
    report_findings = list(
        report.findings.select_related("vendor").order_by("-created_at"),
    )
    can_edit = report.can_user_edit(request.user)
    # "Add from DB" choices: the client's findings not already in this report.
    addable_findings: list[Finding] = []
    if can_edit:
        in_report = {f.id for f in report_findings}
        addable_findings = [
            f
            for f in Finding.objects.filter(vendor=report.client).order_by("internal_id")
            if f.id not in in_report
        ]
    annexes = [
        {"annex": a, "letter": chr(65 + i), "body_html": render_markdown(a.body)}
        for i, a in enumerate(report.annexes.order_by("order", "title"))
    ]
    return render(
        request,
        "tenant/reports/detail.html",
        {
            "report": report,
            "can_edit": can_edit,
            "contacts": list(report.contacts.all()),
            "scope_categories": list(report.scope_categories.all()),
            "researchers": list(report.researchers.all()),
            "report_findings": report_findings,
            "addable_findings": addable_findings,
            "executive_summary_html": render_markdown(report.executive_summary),
            "conclusion_html": render_markdown(report.conclusion),
            "annexes": annexes,
        },
    )


@login_required(login_url="/super/login/")
@csrf_protect
def report_edit(request: HttpRequest, report_id: str) -> HttpResponse:
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_edit(request.user):
        raise Http404
    if request.method == "POST":
        form = ReportForm(request.POST, instance=report)
        formset = PointOfContactFormSet(request.POST, instance=report)
        if form.is_valid() and formset.is_valid():
            form.save()
            formset.save()
            messages.success(request, f"Report “{report.name}” updated.")
            return redirect("reports:detail", report_id=report.id)
    else:
        form = ReportForm(instance=report)
        formset = PointOfContactFormSet(instance=report)
    return render(
        request,
        "tenant/reports/form.html",
        {"form": form, "formset": formset, "mode": "edit", "report": report},
    )


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def report_add_finding(request: HttpRequest, report_id: str) -> HttpResponse:
    """Attach an existing finding to the report.

    Cross-vendor guard: only findings whose vendor IS the report's client may
    be added, enforced server-side (not just in the dropdown), so a report can
    never reference another client's findings.
    """
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_edit(request.user):
        raise Http404
    finding = get_object_or_404(Finding, pk=request.POST.get("finding_id"))
    if finding.vendor_id != report.client_id:
        messages.error(request, "That finding belongs to a different client.")
        return redirect("reports:detail", report_id=report.id)
    report.findings.add(finding)
    messages.success(request, f"Added {finding.internal_id} to the report.")
    return redirect("reports:detail", report_id=report.id)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def report_remove_finding(request: HttpRequest, report_id: str, finding_id: str) -> HttpResponse:
    """Unlink a finding from the report (does NOT delete the finding)."""
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_edit(request.user):
        raise Http404
    finding = get_object_or_404(Finding, pk=finding_id)
    report.findings.remove(finding)
    messages.success(request, "Finding removed from the report.")
    return redirect("reports:detail", report_id=report.id)


@login_required(login_url="/super/login/")
@csrf_protect
def report_create_finding(request: HttpRequest, report_id: str) -> HttpResponse:
    """Create a new finding inside a report.

    The vendor is fixed to the report's client (set server-side, not chosen by
    the user), so the finding is automatically mapped to the right client and
    counts in the global total. Mirrors finding_new's review-state gating.
    """
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_edit(request.user):
        raise Http404
    if request.method == "POST":
        form = ReportFindingForm(request.POST)
        if form.is_valid():
            finding = form.save(commit=False)
            finding.vendor = report.client
            finding.reported_by = request.user
            finding.reported_by_email = request.user.email
            finding.review_state = (
                ReviewState.APPROVED.value
                if request.user.is_review_authority
                else ReviewState.PENDING.value
            )
            finding.save()
            form.save_m2m()
            _sync_affected_hosts(finding, form.cleaned_data.get("affected_hosts_text", ""))
            report.findings.add(finding)
            messages.success(request, f"Created {finding.internal_id} in the report.")
            return redirect("reports:detail", report_id=report.id)
    else:
        form = ReportFindingForm()
    return render(
        request,
        "tenant/reports/finding_form.html",
        {"form": form, "report": report, "mode": "create"},
    )


@login_required(login_url="/super/login/")
@csrf_protect
def report_edit_finding(request: HttpRequest, report_id: str, finding_id: str) -> HttpResponse:
    """Edit a finding in place from the report (no round-trip to /findings/).

    Gated by report.can_user_edit; the finding must already belong to this
    report and its vendor stays the report's client.
    """
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_edit(request.user):
        raise Http404
    finding = get_object_or_404(report.findings, pk=finding_id)
    if request.method == "POST":
        form = ReportFindingForm(request.POST, instance=finding)
        if form.is_valid():
            updated = form.save(commit=False)
            updated.vendor = report.client  # vendor stays the report's client
            updated.save()
            form.save_m2m()
            _sync_affected_hosts(updated, form.cleaned_data.get("affected_hosts_text", ""))
            messages.success(request, f"Updated {finding.internal_id}.")
            return redirect("reports:detail", report_id=report.id)
    else:
        form = ReportFindingForm(
            instance=finding,
            initial={
                "affected_hosts_text": "\n".join(
                    finding.affected_hosts.order_by("value").values_list("value", flat=True),
                ),
            },
        )
    return render(
        request,
        "tenant/reports/finding_form.html",
        {"form": form, "report": report, "mode": "edit", "finding": finding},
    )


@login_required(login_url="/super/login/")
@csrf_protect
def report_content_edit(request: HttpRequest, report_id: str) -> HttpResponse:
    """Edit the executive summary + conclusion (markdown)."""
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_edit(request.user):
        raise Http404
    if request.method == "POST":
        form = ReportContentForm(request.POST, instance=report)
        if form.is_valid():
            form.save()
            messages.success(request, "Report content updated.")
            return redirect("reports:detail", report_id=report.id)
    else:
        form = ReportContentForm(instance=report)
    return render(
        request,
        "tenant/reports/content_form.html",
        {"form": form, "report": report},
    )


@login_required(login_url="/super/login/")
@csrf_protect
def report_annex_new(request: HttpRequest, report_id: str) -> HttpResponse:
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_edit(request.user):
        raise Http404
    if request.method == "POST":
        form = AnnexForm(request.POST)
        if form.is_valid():
            annex = form.save(commit=False)
            annex.report = report
            last = report.annexes.order_by("-order").first()
            annex.order = (last.order + 1) if last else 0
            annex.save()
            messages.success(request, f"Annex “{annex.title}” added.")
            return redirect("reports:detail", report_id=report.id)
    else:
        form = AnnexForm()
    return render(
        request,
        "tenant/reports/annex_form.html",
        {"form": form, "report": report, "mode": "create"},
    )


@login_required(login_url="/super/login/")
@csrf_protect
def report_annex_edit(request: HttpRequest, report_id: str, annex_id: str) -> HttpResponse:
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_edit(request.user):
        raise Http404
    annex = get_object_or_404(report.annexes, pk=annex_id)
    if request.method == "POST":
        form = AnnexForm(request.POST, instance=annex)
        if form.is_valid():
            form.save()
            messages.success(request, f"Annex “{annex.title}” updated.")
            return redirect("reports:detail", report_id=report.id)
    else:
        form = AnnexForm(instance=annex)
    return render(
        request,
        "tenant/reports/annex_form.html",
        {"form": form, "report": report, "mode": "edit", "annex": annex},
    )


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def report_annex_remove(request: HttpRequest, report_id: str, annex_id: str) -> HttpResponse:
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_edit(request.user):
        raise Http404
    annex = get_object_or_404(report.annexes, pk=annex_id)
    annex.delete()
    messages.success(request, "Annex removed.")
    return redirect("reports:detail", report_id=report.id)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def report_annex_move(
    request: HttpRequest,
    report_id: str,
    annex_id: str,
    direction: str,
) -> HttpResponse:
    """Swap an annex's order with its neighbour (up/down) to reorder."""
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_edit(request.user):
        raise Http404
    ordered = list(report.annexes.order_by("order", "title"))
    idx = next((i for i, a in enumerate(ordered) if str(a.pk) == str(annex_id)), None)
    if idx is None:
        raise Http404
    swap = idx - 1 if direction == "up" else idx + 1
    if 0 <= swap < len(ordered):
        a, b = ordered[idx], ordered[swap]
        a.order, b.order = b.order, a.order
        # Guard against equal/zero order values producing no change.
        if a.order == b.order:
            a.order, b.order = swap, idx
        Annex.objects.bulk_update([a, b], ["order"])
    return redirect("reports:detail", report_id=report.id)
