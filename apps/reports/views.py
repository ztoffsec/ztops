"""Report builder views (Phase 4a: list / create / detail / edit metadata)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.csrf import csrf_protect

from .forms import PointOfContactFormSet, ReportForm
from .models import Report

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
    return render(
        request,
        "tenant/reports/detail.html",
        {
            "report": report,
            "can_edit": report.can_user_edit(request.user),
            "contacts": list(report.contacts.all()),
            "scope_categories": list(report.scope_categories.all()),
            "researchers": list(report.researchers.all()),
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
