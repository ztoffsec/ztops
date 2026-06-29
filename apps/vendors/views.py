"""CRUD views for Vendor.

Permission model:
- View list / view detail: any authenticated user.
- Create: any authenticated user.
- Edit / delete: only the creator + superadmin.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models.functions import Lower
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST, require_safe

from .forms import VendorForm
from .models import Vendor

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


def _can_edit(vendor: Vendor, user: object) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    if getattr(user, "is_superadmin", False):
        return True
    return vendor.created_by_id == user.pk


def _require_edit(vendor: Vendor, user: object) -> None:
    if not _can_edit(vendor, user):
        raise Http404


@login_required(login_url="/super/login/")
@require_safe
def vendors_list(request: HttpRequest) -> HttpResponse:
    # Lower("name") so the sort is case-insensitive. Without it Postgres
    # compares by codepoint and a vendor whose name starts with a lowercase
    # letter lands after every uppercase Z.
    rows = list(Vendor.objects.all().order_by(Lower("name")))
    return render(
        request,
        "tenant/vendors/list.html",
        {"vendors": rows, "form": VendorForm()},
    )


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def vendor_new(request: HttpRequest) -> HttpResponse:
    form = VendorForm(request.POST)
    if form.is_valid():
        vendor = form.save(commit=False)
        vendor.created_by = request.user
        vendor.created_by_email = request.user.email
        vendor.save()
        messages.success(request, f"Vendor {vendor.name} created.")
        return redirect("vendors:detail", slug=vendor.slug)
    # Re-render list with errors. form_open=True so the modal stays open
    # showing the validation errors instead of vanishing behind the button.
    rows = list(Vendor.objects.all().order_by(Lower("name")))
    return render(
        request,
        "tenant/vendors/list.html",
        {"vendors": rows, "form": form, "form_open": True},
    )


@login_required(login_url="/super/login/")
@require_safe
def vendor_detail(request: HttpRequest, slug: str) -> HttpResponse:
    vendor = get_object_or_404(Vendor, slug=slug)
    findings = list(
        vendor.findings.select_related("reported_by").order_by("-created_at")[:200],
    )
    affected_hosts = list(vendor.affected_hosts.order_by("value"))
    return render(
        request,
        "tenant/vendors/detail.html",
        {
            "vendor": vendor,
            "findings": findings,
            "affected_hosts": affected_hosts,
            "can_edit": _can_edit(vendor, request.user),
        },
    )


@login_required(login_url="/super/login/")
@csrf_protect
def vendor_edit(request: HttpRequest, slug: str) -> HttpResponse:
    vendor = get_object_or_404(Vendor, slug=slug)
    _require_edit(vendor, request.user)
    if request.method == "POST":
        form = VendorForm(request.POST, instance=vendor)
        if form.is_valid():
            form.save()
            messages.success(request, f"Vendor {vendor.name} updated.")
            return redirect("vendors:detail", slug=vendor.slug)
    else:
        form = VendorForm(instance=vendor)
    return render(
        request,
        "tenant/vendors/form.html",
        {"form": form, "vendor": vendor},
    )


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def vendor_delete(request: HttpRequest, slug: str) -> HttpResponse:
    vendor = get_object_or_404(Vendor, slug=slug)
    _require_edit(vendor, request.user)
    if vendor.findings.exists():
        messages.error(
            request,
            f"Cannot delete {vendor.name}: it has findings reported against it.",
        )
        return redirect("vendors:detail", slug=vendor.slug)
    name = vendor.name
    vendor.delete()
    messages.success(request, f"Vendor {name} deleted.")
    return redirect("vendors:list")
