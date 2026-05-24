"""HTTP views for the two-person-rule operator UI.

Five views, all gated by `superadmin_required`:

- `list_view`     (GET)  /super/approvals/                — actionable + own
- `detail_view`   (GET)  /super/approvals/<id>/           — full row + buttons
- `approve_view`  (POST) /super/approvals/<id>/approve/   — runs services.approve()
- `deny_view`     (POST) /super/approvals/<id>/deny/      — runs services.deny()

Approve/deny redirect back to the detail page on success so the user
can see the post-transition state. On ApprovalError they re-render the
detail with the error banner.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST, require_safe

from apps.accounts.decorators import superadmin_required

from .models import ApprovalState, SuperAdminApproval
from .services import ApprovalError, approve, deny

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


def _render_detail(
    request: HttpRequest,
    approval: SuperAdminApproval,
    *,
    error: str | None = None,
    status: int = 200,
) -> HttpResponse:
    return render(
        request,
        "tenant/approvals/detail.html",
        {
            "approval": approval,
            "is_own": approval.requested_by_id == request.user.id,
            "error": error,
            "payload_json": json.dumps(approval.payload, indent=2, sort_keys=True),
        },
        status=status,
    )


@superadmin_required
@require_safe
def list_view(request: HttpRequest) -> HttpResponse:
    actionable = (
        SuperAdminApproval.objects.filter(state=ApprovalState.PENDING.value)
        .exclude(requested_by=request.user)
        .select_related("requested_by")
    )
    own = SuperAdminApproval.objects.filter(requested_by=request.user).select_related(
        "approved_by", "denied_by"
    )[:25]
    return render(
        request,
        "tenant/approvals/list.html",
        {"actionable": list(actionable), "own": list(own)},
    )


@superadmin_required
@require_safe
def detail_view(request: HttpRequest, approval_id: str) -> HttpResponse:
    approval = get_object_or_404(
        SuperAdminApproval.objects.select_related(
            "requested_by",
            "approved_by",
            "denied_by",
        ),
        pk=approval_id,
    )
    return _render_detail(request, approval)


@superadmin_required
@csrf_protect
@require_POST
def approve_view(request: HttpRequest, approval_id: str) -> HttpResponse:
    approval = get_object_or_404(SuperAdminApproval, pk=approval_id)
    try:
        approve(approval, by=request.user, request=request)
    except ApprovalError as exc:
        approval.refresh_from_db()
        return _render_detail(request, approval, error=str(exc), status=400)
    return HttpResponseRedirect(reverse("approvals:detail", args=[approval.id]))


@superadmin_required
@csrf_protect
@require_POST
def deny_view(request: HttpRequest, approval_id: str) -> HttpResponse:
    approval = get_object_or_404(SuperAdminApproval, pk=approval_id)
    reason = (request.POST.get("reason") or "").strip()
    try:
        deny(approval, by=request.user, reason=reason, request=request)
    except ApprovalError as exc:
        approval.refresh_from_db()
        return _render_detail(request, approval, error=str(exc), status=400)
    return HttpResponseRedirect(reverse("approvals:detail", args=[approval.id]))
