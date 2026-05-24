"""User-facing views for the superadmin surface.

- `login_view`: renders the email-entry form. When the visitor is
  already authenticated, redirects straight to the dashboard so we
  don't re-prompt them for a passkey.
- `dashboard_view`: post-login landing. Real metrics across the team:
  finding counts, severity breakdown, top vendors, per-researcher
  contribution table.
- `profile_view`: account info + registered passkeys (moved off the
  dashboard so the landing surface is workspace-focused).
- `logout_view`: clears the session. POST-only (CSRF-protected).
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth import logout as django_logout
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.decorators.http import require_POST, require_safe

from apps.accounts.decorators import superadmin_required
from apps.accounts.forms import UserCreateForm
from apps.accounts.models import Role, User
from apps.approvals.models import ApprovableAction, ApprovalState, SuperAdminApproval
from apps.approvals.services import ApprovalError, request_approval
from apps.audit.models import AuditAction
from apps.audit.services import audit
from apps.findings.models import Finding, ReviewState, Severity, Status
from apps.vendors.models import Vendor
from apps.webauthn_auth.models import EnrollmentToken

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


_OPEN_STATUSES: tuple[str, ...] = (
    Status.DRAFTED.value,
    Status.IN_TRIAGE.value,
    Status.VENDOR_ACK.value,
    Status.AWAITING_CVE.value,
)

_SEVERITY_COLORS: dict[str, str] = {
    Severity.CRITICAL.value: "#b91c1c",
    Severity.HIGH.value: "#c2410c",
    Severity.MEDIUM.value: "#b45309",
    Severity.LOW.value: "#15803d",
    Severity.NONE.value: "#a3a3a3",
}


_RADAR_AXES: tuple[str, ...] = (
    Severity.CRITICAL.value,
    Severity.HIGH.value,
    Severity.MEDIUM.value,
    Severity.LOW.value,
    Severity.NONE.value,
)
_RADAR_RINGS: tuple[float, ...] = (0.25, 0.5, 0.75, 1.0)


def _severity_radar(
    rows: list[dict],
    *,
    cx: float = 100,
    cy: float = 100,
    r: float = 82,
) -> dict | None:
    """Geometry for an SVG radar/spider chart of the five severity bands.

    Emits the canonical 5 axes in fixed order — Critical at the top,
    going clockwise — so the chart shape stays comparable across
    dashboards even when some bands are empty. Returns `None` when
    there's nothing to plot so the caller can render its empty state.
    """
    counts = {row["value"]: row["count"] for row in rows}
    max_count = max(counts.values(), default=0)
    total = sum(counts.values())
    if total <= 0 or max_count <= 0:
        return None

    label_lookup = dict(Severity.choices)
    n_axes = len(_RADAR_AXES)
    axes: list[dict] = []
    polygon_pts: list[str] = []
    for i, value in enumerate(_RADAR_AXES):
        angle = (2 * math.pi * i / n_axes) - (math.pi / 2)
        cos_a = math.cos(angle)
        sin_a = math.sin(angle)
        ax_x = cx + r * cos_a
        ax_y = cy + r * sin_a
        # Label sits a touch outside the axis end.
        lx = cx + (r + 16) * cos_a
        ly = cy + (r + 16) * sin_a
        n = counts.get(value, 0)
        frac = n / max_count
        vx = cx + r * frac * cos_a
        vy = cy + r * frac * sin_a
        axes.append(
            {
                "value": value,
                "label": label_lookup.get(value, value),
                "count": n,
                "ax_x": round(ax_x, 3),
                "ax_y": round(ax_y, 3),
                "lx": round(lx, 3),
                "ly": round(ly, 3),
                "vx": round(vx, 3),
                "vy": round(vy, 3),
                "color": _SEVERITY_COLORS.get(value, "#a3a3a3"),
            },
        )
        polygon_pts.append(f"{vx:.3f},{vy:.3f}")

    grid_polygons: list[str] = []
    for ring_frac in _RADAR_RINGS:
        ring_pts: list[str] = []
        for i in range(n_axes):
            angle = (2 * math.pi * i / n_axes) - (math.pi / 2)
            rx = cx + r * ring_frac * math.cos(angle)
            ry = cy + r * ring_frac * math.sin(angle)
            ring_pts.append(f"{rx:.3f},{ry:.3f}")
        grid_polygons.append(" ".join(ring_pts))

    return {
        "cx": cx,
        "cy": cy,
        "r": r,
        "axes": axes,
        "polygon_points": " ".join(polygon_pts),
        "grid_polygons": grid_polygons,
        "max_count": max_count,
        "total": total,
    }


@require_safe
@ensure_csrf_cookie
def login_view(request: HttpRequest) -> HttpResponse:
    """Render the email + WebAuthn-button form."""
    if request.user.is_authenticated:
        return HttpResponseRedirect(reverse("accounts:dashboard"))
    return render(request, "public/login.html")


@login_required(login_url="/super/login/")
@require_safe
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """Team metrics dashboard.

    Filters to APPROVED findings only — pending / under-review /
    rejected reports shouldn't move the public metrics until they're
    vetted (mirrors the global-feed visibility rule). Reviewers and
    superadmins additionally see a "Pending review" stat card with the
    queue depth.
    """
    approved_qs = Finding.objects.filter(review_state=ReviewState.APPROVED.value)
    total_findings = approved_qs.count()

    my_assigned_qs = Finding.objects.filter(assigned_researchers=request.user)
    my_open = my_assigned_qs.filter(status__in=_OPEN_STATUSES).count()
    my_total = my_assigned_qs.count()

    critical_high = approved_qs.filter(
        severity__in=(Severity.CRITICAL.value, Severity.HIGH.value),
    ).count()
    total_vendors = Vendor.objects.count()
    pending_reviews = 0
    if request.user.is_review_authority:
        pending_reviews = Finding.objects.filter(
            review_state__in=(
                ReviewState.PENDING.value,
                ReviewState.UNDER_REVIEW.value,
            ),
        ).count()

    # Severity breakdown across approved findings only.
    severity_rows = list(
        approved_qs.values("severity").annotate(n=Count("id")).order_by("-n"),
    )
    severity_lookup = {Severity(s).value: Severity(s).label for s in Severity}
    severity_breakdown = [
        {
            "value": row["severity"],
            "label": severity_lookup.get(row["severity"], row["severity"]),
            "count": row["n"],
        }
        for row in severity_rows
    ]
    severity_radar = _severity_radar(severity_breakdown)

    # Status breakdown — also approved-only so unreviewed clutter
    # doesn't skew the disclosure-lifecycle picture.
    status_rows = list(
        approved_qs.values("status").annotate(n=Count("id")).order_by("-n"),
    )
    status_lookup = {Status(s).value: Status(s).label for s in Status}
    status_breakdown = [
        {
            "value": row["status"],
            "label": status_lookup.get(row["status"], row["status"]),
            "count": row["n"],
        }
        for row in status_rows
    ]

    # Top vendors (by approved-finding count).
    top_vendors = list(
        Vendor.objects.annotate(
            n=Count(
                "findings",
                filter=Q(findings__review_state=ReviewState.APPROVED.value),
            ),
        )
        .filter(n__gt=0)
        .order_by("-n", "name")[:10],
    )

    # Researcher contribution: every user who participates in a finding
    # — as reporter or invited collaborator — is counted. The post_save
    # signal puts the reporter into assigned_researchers, so this single
    # reverse-M2M traversal covers both. Approved-only so unreviewed /
    # rejected work doesn't inflate the leaderboard.
    approved_filter = Q(findings_assigned__review_state=ReviewState.APPROVED.value)
    per_researcher = list(
        User.objects.filter(findings_assigned__isnull=False)
        .annotate(
            reported_total=Count(
                "findings_assigned",
                filter=approved_filter,
                distinct=True,
            ),
            reported_critical=Count(
                "findings_assigned",
                filter=approved_filter & Q(findings_assigned__severity=Severity.CRITICAL.value),
                distinct=True,
            ),
            reported_high=Count(
                "findings_assigned",
                filter=approved_filter & Q(findings_assigned__severity=Severity.HIGH.value),
                distinct=True,
            ),
            reported_open=Count(
                "findings_assigned",
                filter=approved_filter & Q(findings_assigned__status__in=_OPEN_STATUSES),
                distinct=True,
            ),
        )
        .filter(reported_total__gt=0)
        .order_by("-reported_total")[:20],
    )

    # Recent activity: approved findings only.
    recent_findings = list(
        approved_qs.select_related("vendor", "reported_by").order_by(
            "-created_at",
        )[:8],
    )

    actionable_approvals = 0
    if request.user.is_superadmin:
        actionable_approvals = (
            SuperAdminApproval.objects.filter(state=ApprovalState.PENDING.value)
            .exclude(requested_by=request.user)
            .count()
        )

    return render(
        request,
        "tenant/dashboard.html",
        {
            "stats": {
                "total_findings": total_findings,
                "my_open": my_open,
                "my_total": my_total,
                "critical_high": critical_high,
                "total_vendors": total_vendors,
                "actionable_approvals": actionable_approvals,
                "pending_reviews": pending_reviews,
            },
            "severity_breakdown": severity_breakdown,
            "severity_radar": severity_radar,
            "status_breakdown": status_breakdown,
            "top_vendors": top_vendors,
            "per_researcher": per_researcher,
            "recent_findings": recent_findings,
        },
    )


@login_required(login_url="/super/login/")
@require_safe
def profile_view(request: HttpRequest) -> HttpResponse:
    """Account info + registered passkeys for the signed-in user."""
    credentials = list(request.user.credentials.all())
    return render(
        request,
        "tenant/profile.html",
        {"credentials": credentials},
    )


@csrf_protect
@require_POST
def logout_view(request: HttpRequest) -> HttpResponse:
    actor = request.user if request.user.is_authenticated else None
    django_logout(request)
    if actor is not None:
        audit(
            action=AuditAction.USER_SIGNED_OUT,
            actor=actor,
            request=request,
            target_kind="user",
            target_id=str(actor.id),
            target_label=actor.email,
        )
    return HttpResponseRedirect(reverse("accounts:login"))


# ---- User management (superadmin only) ----------------------------------


def _enrollment_url(request: HttpRequest, raw_token: str) -> str:
    return request.build_absolute_uri(f"/webauthn/enroll/{raw_token}/")


@superadmin_required
@require_safe
def users_list(request: HttpRequest) -> HttpResponse:
    users = list(
        User.objects.annotate(passkey_count=Count("credentials")).order_by("email"),
    )
    return render(request, "tenant/users/list.html", {"users": users})


@superadmin_required
@csrf_protect
def user_new(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = UserCreateForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            display_name = form.cleaned_data["display_name"]
            role = form.cleaned_data["role"]

            if role == Role.SUPERADMIN.value:
                # Two-person rule: submit an approval; another superadmin
                # must endorse before the User row is created.
                try:
                    approval = request_approval(
                        action=ApprovableAction.REGISTER_SUPERADMIN,
                        payload={
                            "email": email,
                            "display_name": display_name,
                        },
                        requested_by=request.user,
                        request=request,
                    )
                except ApprovalError as exc:
                    messages.error(request, str(exc))
                    return render(
                        request,
                        "tenant/users/new.html",
                        {"form": form},
                    )
                messages.success(
                    request,
                    f"Approval requested for new superadmin {email}. "
                    "A second superadmin must approve before the account is created.",
                )
                return redirect("approvals:detail", approval_id=approval.id)

            # Regular role: create directly.
            user = User.objects.create_user(
                email=email,
                display_name=display_name,
                role=Role.REGULAR,
            )
            audit(
                action=AuditAction.USER_CREATED,
                actor=request.user,
                request=request,
                target_kind="user",
                target_id=str(user.id),
                target_label=user.email,
                metadata={"role": Role.REGULAR.value, "via": "direct"},
            )
            messages.success(request, f"User {user.email} created.")
            return redirect("accounts:user_detail", user_id=user.id)
    else:
        form = UserCreateForm()
    return render(request, "tenant/users/new.html", {"form": form})


@superadmin_required
@require_safe
def user_detail(request: HttpRequest, user_id: str) -> HttpResponse:
    target = get_object_or_404(User, pk=user_id)
    credentials = list(target.credentials.all())
    # Any unused, unexpired token still floats around? Show prefix only.
    pending_tokens = list(
        EnrollmentToken.objects.filter(user=target, used_at__isnull=True),
    )
    return render(
        request,
        "tenant/users/detail.html",
        {
            "target": target,
            "credentials": credentials,
            "pending_tokens": pending_tokens,
            # Surface raw token only on the response from POST to /enroll/;
            # context["issued_url"] is empty on GET so the page renders
            # without leaking anything across navigation.
            "issued_url": None,
        },
    )


@superadmin_required
@csrf_protect
@require_POST
def user_issue_enrollment(request: HttpRequest, user_id: str) -> HttpResponse:
    target = get_object_or_404(User, pk=user_id)
    _, raw_token = EnrollmentToken.issue(target)
    audit(
        action=AuditAction.SUPERADMIN_TOKEN_ISSUED,
        actor=request.user,
        request=request,
        target_kind="user",
        target_id=str(target.id),
        target_label=target.email,
        metadata={"surface": "ui"},
    )
    issued_url = _enrollment_url(request, raw_token)
    credentials = list(target.credentials.all())
    pending_tokens = list(
        EnrollmentToken.objects.filter(user=target, used_at__isnull=True),
    )
    return render(
        request,
        "tenant/users/detail.html",
        {
            "target": target,
            "credentials": credentials,
            "pending_tokens": pending_tokens,
            "issued_url": issued_url,
        },
    )
