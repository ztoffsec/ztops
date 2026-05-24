"""CRUD views for Engagement / Asset / ScopeRule."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST, require_safe

from .forms import AssetForm, EngagementForm, ScopeRuleForm
from .models import Asset, Engagement, ScopeRule

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


# ---- Engagement -------------------------------------------------------


@login_required(login_url="/super/login/")
@require_safe
def engagements_list(request: HttpRequest) -> HttpResponse:
    rows = list(
        Engagement.objects.all().order_by("-created_at")[:200],
    )
    return render(request, "tenant/engagements/list.html", {"engagements": rows})


@login_required(login_url="/super/login/")
@require_safe
def engagement_detail(request: HttpRequest, engagement_id: str) -> HttpResponse:
    engagement = get_object_or_404(
        Engagement.objects.prefetch_related("assets", "scope_rules", "findings"),
        pk=engagement_id,
    )
    return render(
        request,
        "tenant/engagements/detail.html",
        {
            "engagement": engagement,
            "assets": list(engagement.assets.all()),
            "scope_rules": list(engagement.scope_rules.all()),
            "findings": list(engagement.findings.all()[:50]),
            "asset_form": AssetForm(),
            "scope_form": ScopeRuleForm(),
        },
    )


@login_required(login_url="/super/login/")
@csrf_protect
def engagement_new(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = EngagementForm(request.POST)
        if form.is_valid():
            engagement = form.save()
            messages.success(request, f"Engagement {engagement.slug} created.")
            return redirect("engagements:detail", engagement_id=engagement.id)
    else:
        form = EngagementForm()
    return render(
        request,
        "tenant/engagements/form.html",
        {"form": form, "mode": "create"},
    )


@login_required(login_url="/super/login/")
@csrf_protect
def engagement_edit(request: HttpRequest, engagement_id: str) -> HttpResponse:
    engagement = get_object_or_404(Engagement, pk=engagement_id)
    if request.method == "POST":
        form = EngagementForm(request.POST, instance=engagement)
        if form.is_valid():
            form.save()
            messages.success(request, f"Engagement {engagement.slug} updated.")
            return redirect("engagements:detail", engagement_id=engagement.id)
    else:
        form = EngagementForm(instance=engagement)
    return render(
        request,
        "tenant/engagements/form.html",
        {"form": form, "mode": "edit", "engagement": engagement},
    )


# ---- Asset (nested under Engagement) ----------------------------------


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def asset_add(request: HttpRequest, engagement_id: str) -> HttpResponse:
    engagement = get_object_or_404(Engagement, pk=engagement_id)
    form = AssetForm(request.POST)
    if form.is_valid():
        asset = form.save(commit=False)
        asset.engagement = engagement
        asset.save()
        messages.success(request, f"Asset {asset.kind}:{asset.identifier} added.")
    else:
        messages.error(request, "Asset form invalid.")
    return redirect("engagements:detail", engagement_id=engagement.id)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def asset_delete(request: HttpRequest, engagement_id: str, asset_id: str) -> HttpResponse:
    asset = get_object_or_404(Asset, pk=asset_id, engagement_id=engagement_id)
    label = asset.identifier
    asset.delete()
    messages.success(request, f"Asset {label} removed.")
    return redirect("engagements:detail", engagement_id=engagement_id)


# ---- ScopeRule (nested under Engagement) ------------------------------


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def scope_rule_add(request: HttpRequest, engagement_id: str) -> HttpResponse:
    engagement = get_object_or_404(Engagement, pk=engagement_id)
    form = ScopeRuleForm(request.POST)
    if form.is_valid():
        rule = form.save(commit=False)
        rule.engagement = engagement
        rule.save()
        messages.success(request, f"Scope rule {rule.rule_type} added.")
    else:
        messages.error(request, "Scope-rule form invalid.")
    return redirect("engagements:detail", engagement_id=engagement.id)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def scope_rule_delete(
    request: HttpRequest,
    engagement_id: str,
    rule_id: str,
) -> HttpResponse:
    rule = get_object_or_404(ScopeRule, pk=rule_id, engagement_id=engagement_id)
    rule.delete()
    messages.success(request, "Scope rule removed.")
    return redirect("engagements:detail", engagement_id=engagement_id)
