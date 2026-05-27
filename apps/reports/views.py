"""Report builder views (Phase 4a: list / create / detail / edit metadata)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from apps.audit.models import AuditAction
from apps.audit.services import audit
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
from .models import Annex, Report, ReportReviewNote, ReportStatus

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


@login_required(login_url="/super/login/")
def reports_list(request: HttpRequest) -> HttpResponse:
    qs = Report.objects.select_related("client", "engagement_manager").prefetch_related(
        "scope_categories",
    )
    # Non-reviewers see approved reports + the ones they are involved in.
    if not request.user.is_review_authority:
        from django.db.models import Q  # noqa: PLC0415

        qs = qs.filter(
            Q(status=ReportStatus.APPROVED.value)
            | Q(created_by=request.user)
            | Q(engagement_manager=request.user)
            | Q(researchers=request.user),
        ).distinct()
    return render(request, "tenant/reports/list.html", {"reports": list(qs)})


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
    # Visibility gate: non-approved reports are involved-parties + reviewers only.
    if not report.can_user_view(request.user):
        raise Http404
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
            "can_review": report.can_user_review(request.user),
            "can_view_review_notes": report.can_user_view_review_notes(request.user),
            "review_notes_rendered": (
                [
                    {"note": n, "body_html": render_markdown(n.body)}
                    for n in report.review_notes.select_related("author").order_by("created_at")
                ]
                if report.can_user_view_review_notes(request.user)
                else []
            ),
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


# ---- Autosave (server-side draft) ---------------------------------------

# Strict per-model allowlist of fields autosave may write, with CharField
# length caps (None = TextField, capped at _TEXT_CAP). This is the security
# boundary: autosave can NEVER touch review_state, vendor, reported_by, etc.
_TEXT_CAP = 200_000
_AUTOSAVE_FIELDS: dict[str, dict[str, int | None]] = {
    "report": {"name": 300, "executive_summary": None, "conclusion": None},
    "annex": {"title": 200, "body": None},
    "finding": {
        "title": 300,
        "narrative": None,
        "poc": None,
        "remediation": None,
        "channel_program": 100,
        "cve_id": 30,
        "cvss_31_vector": 200,
        "cvss_4_vector": 200,
    },
}


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def report_autosave(request: HttpRequest, report_id: str) -> JsonResponse:
    """Persist a single edited field as a draft (text fields only).

    Body JSON: {"model": report|annex|finding, "pk": "...", "field": "...",
    "value": "..."}. Gated by report.can_user_edit; the field must be in the
    per-model allowlist and the target object must belong to this report.
    """
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_edit(request.user):
        raise Http404
    try:
        body = json.loads(request.body or b"{}")
    except (ValueError, TypeError):
        return JsonResponse({"error": "invalid_json"}, status=400)

    model = body.get("model")
    field = body.get("field")
    pk = str(body.get("pk") or "")
    value = body.get("value")
    allowed = _AUTOSAVE_FIELDS.get(model or "")
    if allowed is None or field not in allowed or not isinstance(value, str):
        return JsonResponse({"error": "not_allowed"}, status=400)

    cap = allowed[field]
    value = value[: cap if cap is not None else _TEXT_CAP]

    if model == "report":
        if pk != str(report.id):
            raise Http404
        target = Report.objects.filter(pk=report.id)
    elif model == "annex":
        get_object_or_404(report.annexes, pk=pk)  # membership check
        from .models import Annex  # noqa: PLC0415

        target = Annex.objects.filter(pk=pk)
    else:  # finding
        get_object_or_404(report.findings, pk=pk)  # membership check
        target = Finding.objects.filter(pk=pk)

    target.update(**{field: value})
    return JsonResponse({"ok": True, "saved_at": timezone.now().strftime("%H:%M:%S")})


# ---- Report review workflow (mirrors findings) --------------------------


def _set_report_state(
    request: HttpRequest,
    report: Report,
    new_state: str,
    action: AuditAction,
) -> None:
    report.status = new_state
    report.reviewed_by = request.user
    report.reviewed_at = timezone.now()
    report.save(update_fields=["status", "reviewed_by", "reviewed_at"])
    audit(
        action=action,
        actor=request.user,
        request=request,
        target_kind="report",
        target_id=str(report.id),
        target_label=report.name,
        metadata={"new_state": new_state},
    )


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def report_submit_review(request: HttpRequest, report_id: str) -> HttpResponse:
    """Submit a draft (or re-submit a rejected report) for review. Involved
    editors only."""
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_edit(request.user):
        raise Http404
    if report.status not in {ReportStatus.DRAFT.value, ReportStatus.REJECTED.value}:
        messages.error(request, "Only a draft or rejected report can be submitted for review.")
        return redirect("reports:detail", report_id=report.id)
    was_rejected = report.status == ReportStatus.REJECTED.value
    _set_report_state(
        request,
        report,
        ReportStatus.IN_REVIEW.value,
        AuditAction.REVIEW_RESUBMITTED if was_rejected else AuditAction.REVIEW_STARTED,
    )
    messages.success(request, "Report submitted for review.")
    return redirect("reports:detail", report_id=report.id)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def report_approve(request: HttpRequest, report_id: str) -> HttpResponse:
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_review(request.user):
        raise Http404
    if report.status != ReportStatus.IN_REVIEW.value:
        messages.error(request, "Only a report in review can be approved.")
        return redirect("reports:detail", report_id=report.id)
    _set_report_state(request, report, ReportStatus.APPROVED.value, AuditAction.REVIEW_APPROVED)
    messages.success(request, "Report approved — now visible to everyone and exportable.")
    return redirect("reports:detail", report_id=report.id)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def report_reject(request: HttpRequest, report_id: str) -> HttpResponse:
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_review(request.user):
        raise Http404
    if report.status != ReportStatus.IN_REVIEW.value:
        messages.error(request, "Only a report in review can be rejected.")
        return redirect("reports:detail", report_id=report.id)
    _set_report_state(request, report, ReportStatus.REJECTED.value, AuditAction.REVIEW_REJECTED)
    messages.success(request, "Report rejected.")
    return redirect("reports:detail", report_id=report.id)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def report_reopen(request: HttpRequest, report_id: str) -> HttpResponse:
    """Re-open an approved report for review. Superadmin only."""
    report = get_object_or_404(Report, pk=report_id)
    if not request.user.is_superadmin:
        raise Http404
    if report.status != ReportStatus.APPROVED.value:
        messages.error(request, "Only an approved report can be re-opened.")
        return redirect("reports:detail", report_id=report.id)
    _set_report_state(request, report, ReportStatus.IN_REVIEW.value, AuditAction.REVIEW_STARTED)
    messages.success(request, "Report re-opened for review.")
    return redirect("reports:detail", report_id=report.id)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def report_review_note_add(request: HttpRequest, report_id: str) -> HttpResponse:
    report = get_object_or_404(Report, pk=report_id)
    if not report.can_user_view_review_notes(request.user):
        raise Http404
    body = (request.POST.get("body") or "").strip()
    if not body:
        messages.error(request, "Note body is empty.")
        return redirect("reports:detail", report_id=report.id)
    ReportReviewNote.objects.create(
        report=report,
        author=request.user,
        author_email=request.user.email,
        author_is_reviewer=report.can_user_review(request.user),
        body=body[:200_000],
    )
    messages.success(request, "Review note added.")
    return redirect("reports:detail", report_id=report.id)


@login_required(login_url="/super/login/")
def report_reviews_queue(request: HttpRequest) -> HttpResponse:
    """Report-review queue (the 'Report reviews' sub-tab). Review authority
    sees all; others see the reports they are involved in that are in review."""
    open_qs = Report.objects.filter(status=ReportStatus.IN_REVIEW.value).select_related(
        "client",
        "created_by",
    )
    closed_qs = Report.objects.filter(
        status__in=[ReportStatus.APPROVED.value, ReportStatus.REJECTED.value],
    ).select_related("client", "reviewed_by")[:25]
    if not request.user.is_review_authority:
        from django.db.models import Q  # noqa: PLC0415

        involved = (
            Q(created_by=request.user)
            | Q(engagement_manager=request.user)
            | Q(researchers=request.user)
        )
        open_qs = open_qs.filter(involved).distinct()
        closed_qs = closed_qs.filter(involved).distinct()
    return render(
        request,
        "tenant/reports/review_queue.html",
        {"open_reports": list(open_qs), "closed_reports": list(closed_qs)},
    )
