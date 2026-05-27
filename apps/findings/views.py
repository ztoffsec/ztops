"""CRUD views for Finding + FindingNote.

Permission model (single-instance team app):
- View list / view detail: any authenticated user.
- Tabs: `mine` (default) shows findings where the user is assigned;
  `all` shows every finding in the system.
- Edit a finding: only assigned researchers + superadmin.
- Add a note: only assigned researchers + superadmin.
- Manage assigned_researchers (add/remove): only the reporter + superadmin.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Case, IntegerField, Q, Value, When
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST, require_safe

from apps.accounts.models import User
from apps.audit.models import AuditAction
from apps.audit.services import audit

from .forms import FindingForm, FindingNoteForm
from .markdown import render_markdown
from .models import (
    AffectedHost,
    Channel,
    Finding,
    FindingReviewNote,
    ReviewState,
    Severity,
    Status,
)

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


_SCOPE_MINE = "mine"
_SCOPE_ALL = "all"

# Map of sort key → ORM field path. The severity entry resolves to a
# numeric annotation so the qualitative band orders correctly
# (critical > high > medium > low > none).
_SORT_FIELDS: dict[str, str] = {
    "id": "internal_id",
    "title": "title",
    "vendor": "vendor__name",
    "reporter": "reported_by__display_name",
    "channel": "channel",
    "cve": "cve_id",
    "severity": "_sev_rank",
    "status": "status",
    "created": "created_at",
}
_DEFAULT_SORT_KEY = "created"
_DEFAULT_SORT_DESC = True

_PER_PAGE_CHOICES: tuple[int, ...] = (25, 50, 100)
_DEFAULT_PER_PAGE = 50


def _require_edit(finding: Finding, user: object) -> None:
    if not finding.can_user_edit(user):
        raise Http404


def _require_owner(finding: Finding, user: object) -> None:
    if not finding.can_user_manage_collaborators(user):
        raise Http404


def _parse_sort(raw: str | None) -> tuple[str, bool]:
    """Return (sort_key, descending). Fall back to defaults on bad input."""
    if not raw:
        return _DEFAULT_SORT_KEY, _DEFAULT_SORT_DESC
    descending = raw.startswith("-")
    key = raw.lstrip("-")
    if key not in _SORT_FIELDS:
        return _DEFAULT_SORT_KEY, _DEFAULT_SORT_DESC
    return key, descending


def _parse_per_page(raw: str | None) -> int:
    try:
        n = int(raw or _DEFAULT_PER_PAGE)
    except (TypeError, ValueError):
        return _DEFAULT_PER_PAGE
    return n if n in _PER_PAGE_CHOICES else _DEFAULT_PER_PAGE


def _qs(params: dict[str, str | int]) -> str:
    """urlencode helper that drops empty values."""
    return urlencode({k: v for k, v in params.items() if v not in (None, "")})


@login_required(login_url="/super/login/")
@require_safe
def findings_list(request: HttpRequest) -> HttpResponse:  # noqa: PLR0912, PLR0915 — single composed view
    scope = request.GET.get("scope") or _SCOPE_MINE
    if scope not in (_SCOPE_MINE, _SCOPE_ALL):
        scope = _SCOPE_MINE

    sort_key, sort_desc = _parse_sort(request.GET.get("sort"))
    per_page = _parse_per_page(request.GET.get("per_page"))

    qs = Finding.objects.select_related("vendor", "engagement", "reported_by")
    if scope == _SCOPE_MINE:
        # "My findings" shows the user's own reports + anything they
        # collaborate on, regardless of review_state — the reporter
        # still gets to see their pending/rejected reports here.
        qs = qs.filter(
            Q(assigned_researchers=request.user) | Q(reported_by=request.user),
        )
    elif not request.user.is_review_authority:
        # "All findings" only surfaces approved work to non-review-
        # authority users. Reviewers + superadmins see everything.
        qs = qs.filter(review_state=ReviewState.APPROVED.value)

    filter_status = (request.GET.get("status") or "").strip()
    filter_severity = (request.GET.get("severity") or "").strip()
    filter_channel = (request.GET.get("channel") or "").strip()
    filter_vendor = (request.GET.get("vendor") or "").strip()
    filter_reporter = (request.GET.get("reporter") or "").strip()
    filter_q = (request.GET.get("q") or "").strip()

    if filter_status:
        qs = qs.filter(status=filter_status)
    if filter_severity:
        qs = qs.filter(severity=filter_severity)
    if filter_channel:
        qs = qs.filter(channel=filter_channel)
    if filter_vendor:
        qs = qs.filter(vendor__name__icontains=filter_vendor)
    if filter_reporter:
        qs = qs.filter(reported_by_id=filter_reporter)
    if filter_q:
        qs = qs.filter(Q(internal_id__icontains=filter_q) | Q(title__icontains=filter_q))

    # Annotate a numeric severity rank so qualitative ordering works.
    qs = qs.annotate(
        _sev_rank=Case(
            When(severity=Severity.CRITICAL.value, then=Value(4)),
            When(severity=Severity.HIGH.value, then=Value(3)),
            When(severity=Severity.MEDIUM.value, then=Value(2)),
            When(severity=Severity.LOW.value, then=Value(1)),
            default=Value(0),
            output_field=IntegerField(),
        ),
    )

    order = ("-" if sort_desc else "") + _SORT_FIELDS[sort_key]
    qs = qs.order_by(order, "-created_at").distinct()

    paginator = Paginator(qs, per_page)
    page_obj = paginator.get_page(request.GET.get("page") or 1)
    rows = list(page_obj.object_list)
    total = paginator.count

    editable_ids: set
    if request.user.is_superadmin:
        editable_ids = {f.id for f in rows}
    else:
        editable_ids = set(
            Finding.objects.filter(
                pk__in=[f.id for f in rows],
                assigned_researchers=request.user,
            ).values_list("id", flat=True),
        )

    mine_qs = Finding.objects.filter(
        Q(assigned_researchers=request.user) | Q(reported_by=request.user),
    ).distinct()
    if request.user.is_review_authority:
        all_count = Finding.objects.count()
    else:
        all_count = Finding.objects.filter(
            review_state=ReviewState.APPROVED.value,
        ).count()
    counts = {
        "mine": mine_qs.count(),
        "all": all_count,
    }

    # Reporter filter options: users who have reported at least one finding.
    reporter_options = list(
        User.objects.filter(findings_reported__isnull=False)
        .distinct()
        .order_by("display_name", "email"),
    )

    # Build sortable-header metadata. base_params is every active param
    # except `sort` and `page`; appended below to compose new URLs.
    base_params: dict[str, str | int] = {
        "scope": scope,
        "per_page": per_page,
        "q": filter_q,
        "status": filter_status,
        "severity": filter_severity,
        "channel": filter_channel,
        "vendor": filter_vendor,
        "reporter": filter_reporter,
    }
    header_specs: list[tuple[str, str]] = [
        ("id", "ID"),
        ("title", "Title"),
        ("vendor", "Vendor"),
        ("reporter", "Reporter"),
        ("channel", "Channel"),
        ("cve", "CVE"),
        ("severity", "Severity"),
        ("status", "Status"),
    ]
    sort_headers = []
    for key, label in header_specs:
        is_active = key == sort_key
        # Clicking the active header reverses direction; clicking another
        # column starts descending (most-common case for ranked data).
        next_desc = (not sort_desc) if is_active else True
        next_value = ("-" if next_desc else "") + key
        sort_headers.append(
            {
                "key": key,
                "label": label,
                "url": "?" + _qs({**base_params, "sort": next_value}),
                "is_active": is_active,
                "is_desc": is_active and sort_desc,
                "is_asc": is_active and not sort_desc,
            },
        )

    sort_param = ("-" if sort_desc else "") + sort_key
    pagination_params = {**base_params, "sort": sort_param}
    per_page_options = [
        {
            "n": n,
            "url": "?" + _qs({**pagination_params, "per_page": n, "page": 1}),
            "is_active": n == per_page,
        }
        for n in _PER_PAGE_CHOICES
    ]
    page_prev_url = (
        "?" + _qs({**pagination_params, "page": page_obj.previous_page_number()})
        if page_obj.has_previous()
        else None
    )
    page_next_url = (
        "?" + _qs({**pagination_params, "page": page_obj.next_page_number()})
        if page_obj.has_next()
        else None
    )

    return render(
        request,
        "tenant/findings/list.html",
        {
            "findings": rows,
            "editable_ids": editable_ids,
            "total": total,
            "scope": scope,
            "counts": counts,
            "filter_status": filter_status,
            "filter_severity": filter_severity,
            "filter_channel": filter_channel,
            "filter_vendor": filter_vendor,
            "filter_reporter": filter_reporter,
            "filter_q": filter_q,
            "reporter_options": reporter_options,
            "statuses": Status.choices,
            "severities": Severity.choices,
            "channels": Channel.choices,
            "sort_headers": sort_headers,
            "sort_param": sort_param,
            "per_page": per_page,
            "per_page_options": per_page_options,
            "page_obj": page_obj,
            "page_prev_url": page_prev_url,
            "page_next_url": page_next_url,
        },
    )


@login_required(login_url="/super/login/")
@require_safe
def finding_detail(request: HttpRequest, finding_id: str) -> HttpResponse:
    finding = get_object_or_404(
        Finding.objects.select_related(
            "vendor",
            "engagement",
            "reported_by",
            "reviewed_by",
        ).prefetch_related("notes", "assigned_researchers"),
        pk=finding_id,
    )
    # Visibility gate: pending/under_review/rejected findings 404 for
    # anyone other than the reporter, reviewers, or superadmins.
    if not finding.can_user_view(request.user):
        raise Http404
    assigned = list(finding.assigned_researchers.all())
    can_manage = finding.can_user_manage_collaborators(request.user)
    addable_users: list[User] = []
    if can_manage:
        assigned_ids = {u.pk for u in assigned}
        addable_users = list(
            User.objects.filter(is_active=True)
            .exclude(pk__in=assigned_ids)
            .order_by("display_name", "email"),
        )
    notes = list(finding.notes.all())
    notes_rendered = [{"note": n, "body_html": render_markdown(n.body)} for n in notes]
    attachments = list(
        finding.attachments.select_related("uploaded_by").order_by("-uploaded_at"),
    )
    # Review tab data — gated by the same set as the review actions.
    can_review = finding.can_user_review(request.user)
    can_view_review = finding.can_user_view_private_notes(request.user)
    review_notes_rendered: list[dict] = []
    if can_view_review:
        review_notes = list(
            finding.review_notes.select_related("author").order_by("created_at"),
        )
        review_notes_rendered = [
            {"note": n, "body_html": render_markdown(n.body)} for n in review_notes
        ]
    tab = (request.GET.get("tab") or "overview").lower()
    allowed_tabs = {"overview", "notes", "researchers", "artifacts", "metadata"}
    if can_view_review:
        allowed_tabs.add("review")
    if tab not in allowed_tabs:
        tab = "overview"
    return render(
        request,
        "tenant/findings/detail.html",
        {
            "finding": finding,
            "narrative_html": render_markdown(finding.narrative),
            "poc_html": render_markdown(finding.poc),
            "remediation_html": render_markdown(finding.remediation),
            "affected_hosts": list(finding.affected_hosts.order_by("value")),
            "notes": notes,
            "notes_rendered": notes_rendered,
            "note_form": FindingNoteForm(),
            "attachments": attachments,
            "can_edit": finding.can_user_edit(request.user),
            "can_manage_collaborators": can_manage,
            "can_review": can_review,
            "can_view_review": can_view_review,
            "review_notes_rendered": review_notes_rendered,
            "review_states": ReviewState.choices,
            "assigned_researchers": assigned,
            "addable_users": addable_users,
            "active_tab": tab,
        },
    )


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def preview_markdown(request: HttpRequest) -> HttpResponse:
    """Render the form's markdown body to sanitized HTML for live preview.

    Cap the payload to 100KB so a runaway paste can't hog the worker.
    """
    body = (request.POST.get("body") or "")[:100_000]
    html = render_markdown(body)
    return HttpResponse(html, content_type="text/html; charset=utf-8")


@login_required(login_url="/super/login/")
@csrf_protect
def finding_new(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = FindingForm(request.POST)
        if form.is_valid():
            finding = form.save(commit=False)
            finding.reported_by = request.user
            finding.reported_by_email = request.user.email
            # Quality gate: non-review-authority reporters land in
            # PENDING; their report is invisible to the team feed
            # until a reviewer approves. Reviewers + superadmins
            # auto-approve their own submissions (they ARE the gate).
            if request.user.is_review_authority:
                finding.review_state = ReviewState.APPROVED.value
            else:
                finding.review_state = ReviewState.PENDING.value
            finding.save()
            _sync_affected_hosts(finding, form.cleaned_data.get("affected_hosts_text", ""))
            if finding.review_state == ReviewState.PENDING.value:
                messages.success(
                    request,
                    f"Finding {finding.internal_id} submitted for review. "
                    "It will appear in the global feed once a reviewer "
                    "approves it.",
                )
            else:
                messages.success(request, f"Finding {finding.internal_id} created.")
            return redirect("findings:detail", finding_id=finding.id)
    else:
        form = FindingForm()
    return render(
        request,
        "tenant/findings/form.html",
        {"form": form, "mode": "create"},
    )


def _sync_affected_hosts(finding: Finding, raw_text: str) -> None:
    """Parse newline-separated host values and attach them to the finding.

    Every host is get-or-created **scoped to the finding's own vendor**, so a
    value that also exists under another vendor never links across vendors
    (cross-vendor isolation). De-dups case-insensitively and caps length.
    """
    seen: set[str] = set()
    hosts: list[AffectedHost] = []
    for line in (raw_text or "").splitlines():
        value = line.strip()[:500]
        key = value.lower()
        if not value or key in seen:
            continue
        seen.add(key)
        host, _ = AffectedHost.objects.get_or_create(vendor=finding.vendor, value=value)
        hosts.append(host)
    finding.affected_hosts.set(hosts)


@login_required(login_url="/super/login/")
@csrf_protect
def finding_edit(request: HttpRequest, finding_id: str) -> HttpResponse:
    finding = get_object_or_404(Finding, pk=finding_id)
    _require_edit(finding, request.user)
    if request.method == "POST":
        form = FindingForm(request.POST, instance=finding)
        if form.is_valid():
            form.save()
            _sync_affected_hosts(finding, form.cleaned_data.get("affected_hosts_text", ""))
            messages.success(request, f"Finding {finding.internal_id} updated.")
            return redirect("findings:detail", finding_id=finding.id)
    else:
        form = FindingForm(
            instance=finding,
            initial={
                "affected_hosts_text": "\n".join(
                    finding.affected_hosts.order_by("value").values_list("value", flat=True),
                ),
            },
        )
    return render(
        request,
        "tenant/findings/form.html",
        {
            "form": form,
            "mode": "edit",
            "finding": finding,
            "vendor_hosts": list(
                finding.vendor.affected_hosts.order_by("value").values_list("value", flat=True),
            ),
        },
    )


@login_required(login_url="/super/login/")
@csrf_protect
def finding_delete(request: HttpRequest, finding_id: str) -> HttpResponse:
    """Two-step delete. GET renders a confirmation page; POST performs
    the deletion. Restricted to the reporter + superadmins (same rule
    as collaborator management — only the owner can destroy)."""
    finding = get_object_or_404(Finding, pk=finding_id)
    _require_owner(finding, request.user)

    if request.method == "POST":
        # Snapshot what we want preserved before delete blows it away.
        snapshot = {
            "internal_id": finding.internal_id,
            "title": finding.title,
            "vendor": finding.vendor.name if finding.vendor_id else "",
            "severity": finding.severity,
            "status": finding.status,
            "reported_by_email": finding.reported_by_email,
        }
        finding.delete()
        audit(
            action=AuditAction.FINDING_DELETED,
            actor=request.user,
            request=request,
            target_kind="finding",
            target_id=str(finding_id),
            target_label=snapshot["internal_id"],
            metadata=snapshot,
        )
        messages.success(
            request,
            f"Finding {snapshot['internal_id']} deleted.",
        )
        return redirect("findings:list")

    return render(
        request,
        "tenant/findings/confirm_delete.html",
        {"finding": finding},
    )


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def add_note(request: HttpRequest, finding_id: str) -> HttpResponse:
    finding = get_object_or_404(Finding, pk=finding_id)
    _require_edit(finding, request.user)
    form = FindingNoteForm(request.POST)
    if form.is_valid():
        note = form.save(commit=False)
        note.finding = finding
        note.author = request.user
        note.author_email = request.user.email
        note.save()
        messages.success(request, "Note added.")
    else:
        messages.error(request, "Note body is required.")
    return redirect("findings:detail", finding_id=finding.id)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def collaborator_add(request: HttpRequest, finding_id: str) -> HttpResponse:
    finding = get_object_or_404(Finding, pk=finding_id)
    _require_owner(finding, request.user)
    user_id = (request.POST.get("user_id") or "").strip()
    if not user_id:
        messages.error(request, "Pick a user.")
        return redirect("findings:detail", finding_id=finding.id)
    try:
        user = User.objects.get(pk=user_id, is_active=True)
    except (User.DoesNotExist, ValueError):
        messages.error(request, "No active user with that ID.")
        return redirect("findings:detail", finding_id=finding.id)
    if finding.assigned_researchers.filter(pk=user.pk).exists():
        messages.warning(request, f"{user.display_name} is already assigned.")
    else:
        finding.assigned_researchers.add(user)
        messages.success(request, f"{user.display_name} added as collaborator.")
    return redirect("findings:detail", finding_id=finding.id)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def collaborator_remove(
    request: HttpRequest,
    finding_id: str,
    user_id: str,
) -> HttpResponse:
    finding = get_object_or_404(Finding, pk=finding_id)
    _require_owner(finding, request.user)
    target = get_object_or_404(User, pk=user_id)
    if target.pk == finding.reported_by_id:
        messages.error(request, "Cannot remove the reporter.")
        return redirect("findings:detail", finding_id=finding.id)
    finding.assigned_researchers.remove(target)
    messages.success(request, f"{target.email} removed.")
    return redirect("findings:detail", finding_id=finding.id)


# ---- Review workflow ----------------------------------------------------

_ALLOWED_REVIEW_TRANSITIONS: dict[str, set[str]] = {
    ReviewState.PENDING.value: {ReviewState.UNDER_REVIEW.value},
    ReviewState.UNDER_REVIEW.value: {
        ReviewState.APPROVED.value,
        ReviewState.REJECTED.value,
        # Allow back-to-pending if a reviewer accidentally claimed it
        # and wants to defer to another reviewer.
        ReviewState.PENDING.value,
    },
    # Already-terminal states (approved / rejected) can be re-opened
    # only by a superadmin. The view enforces this with an explicit
    # role check, not the transition table.
    ReviewState.APPROVED.value: {ReviewState.UNDER_REVIEW.value},
    ReviewState.REJECTED.value: {ReviewState.UNDER_REVIEW.value},
}


def _audit_action_for(target_state: str) -> AuditAction | None:
    return {
        ReviewState.UNDER_REVIEW.value: AuditAction.REVIEW_STARTED,
        ReviewState.APPROVED.value: AuditAction.REVIEW_APPROVED,
        ReviewState.REJECTED.value: AuditAction.REVIEW_REJECTED,
    }.get(target_state)


def _transition_review(
    request: HttpRequest,
    finding: Finding,
    target_state: str,
) -> HttpResponse:
    """Shared body for review state transitions. Validates the move,
    rolls the columns, audits, and bounces back to the Review tab."""
    if not finding.can_user_review(request.user):
        raise Http404

    allowed = _ALLOWED_REVIEW_TRANSITIONS.get(finding.review_state, set())
    # Reopening a terminal state (approved/rejected) requires superadmin
    # authority; everything else has to match the transition table.
    if target_state not in allowed and not request.user.is_superadmin:
        messages.error(
            request,
            f"Cannot move review from {finding.get_review_state_display()} "
            f"to {dict(ReviewState.choices)[target_state]}.",
        )
        return redirect(f"/findings/{finding.id}/?tab=review")

    finding.review_state = target_state
    finding.reviewed_by = request.user
    finding.reviewed_at = timezone.now()
    finding.save(update_fields=["review_state", "reviewed_by", "reviewed_at"])

    action = _audit_action_for(target_state)
    if action is not None:
        audit(
            action=action,
            actor=request.user,
            request=request,
            target_kind="finding",
            target_id=str(finding.id),
            target_label=finding.internal_id,
            metadata={"new_state": target_state},
        )
    messages.success(
        request,
        f"Review state → {finding.get_review_state_display()}.",
    )
    return redirect(f"/findings/{finding.id}/?tab=review")


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def review_start(request: HttpRequest, finding_id: str) -> HttpResponse:
    finding = get_object_or_404(Finding, pk=finding_id)
    return _transition_review(request, finding, ReviewState.UNDER_REVIEW.value)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def review_approve(request: HttpRequest, finding_id: str) -> HttpResponse:
    finding = get_object_or_404(Finding, pk=finding_id)
    return _transition_review(request, finding, ReviewState.APPROVED.value)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def review_reject(request: HttpRequest, finding_id: str) -> HttpResponse:
    finding = get_object_or_404(Finding, pk=finding_id)
    return _transition_review(request, finding, ReviewState.REJECTED.value)


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def review_resubmit(request: HttpRequest, finding_id: str) -> HttpResponse:
    """Re-submit a rejected finding for another round of review.

    Only the reporter (or a superadmin acting on their behalf) can
    re-submit. Notes + review-thread history live in their own tables
    and are intentionally preserved across resubmits — the reviewer
    can see what the reporter fixed and why the previous decision was
    made.
    """
    finding = get_object_or_404(Finding, pk=finding_id)
    is_owner = finding.reported_by_id == request.user.pk
    if not (is_owner or request.user.is_superadmin):
        raise Http404
    if finding.review_state != ReviewState.REJECTED.value:
        messages.error(
            request,
            "Only rejected findings can be re-submitted for review.",
        )
        return redirect(f"/findings/{finding.id}/?tab=review")

    finding.review_state = ReviewState.PENDING.value
    finding.reviewed_by = request.user
    finding.reviewed_at = timezone.now()
    finding.save(update_fields=["review_state", "reviewed_by", "reviewed_at"])
    audit(
        action=AuditAction.REVIEW_RESUBMITTED,
        actor=request.user,
        request=request,
        target_kind="finding",
        target_id=str(finding.id),
        target_label=finding.internal_id,
        metadata={"new_state": ReviewState.PENDING.value, "by_owner": is_owner},
    )
    messages.success(
        request,
        f"Finding {finding.internal_id} re-submitted for review.",
    )
    return redirect(f"/findings/{finding.id}/?tab=review")


@login_required(login_url="/super/login/")
@csrf_protect
@require_POST
def review_note_add(request: HttpRequest, finding_id: str) -> HttpResponse:
    """Append a private review note. The audience is reporter +
    reviewers + superadmins. Authors are restricted to reviewers +
    superadmins — the reporter posts public notes via add_note."""
    finding = get_object_or_404(Finding, pk=finding_id)
    if not finding.can_user_review(request.user) and not request.user.is_superadmin:
        # The reporter can READ but not WRITE on this thread.
        if finding.reported_by_id == request.user.pk:
            messages.error(
                request,
                "Reporters post on the public Notes tab; the private review "
                "thread is reviewer-only.",
            )
        raise Http404
    body = (request.POST.get("body") or "").strip()
    if not body:
        messages.error(request, "Review note body is required.")
        return redirect(f"/findings/{finding.id}/?tab=review")
    FindingReviewNote.objects.create(
        finding=finding,
        author=request.user,
        author_email=request.user.email,
        author_is_reviewer=True,
        body=body,
    )
    messages.success(request, "Review note posted.")
    return redirect(f"/findings/{finding.id}/?tab=review")


@login_required(login_url="/super/login/")
@require_safe
def reviews_queue(request: HttpRequest) -> HttpResponse:
    """Global review queue — pending + under_review findings.
    Reviewer + superadmin only."""
    if not request.user.is_review_authority:
        raise Http404

    open_states = (ReviewState.PENDING.value, ReviewState.UNDER_REVIEW.value)
    open_findings = list(
        Finding.objects.filter(review_state__in=open_states)
        .select_related("vendor", "reported_by", "reviewed_by")
        .order_by("-created_at"),
    )
    # Show the last 50 closed reviews so reviewers have context for
    # what's been decided recently. Keeps the page from being a wall
    # if there's a long history.
    closed_findings = list(
        Finding.objects.filter(
            review_state__in=(ReviewState.APPROVED.value, ReviewState.REJECTED.value),
        )
        .select_related("vendor", "reported_by", "reviewed_by")
        .order_by("-reviewed_at", "-created_at")[:50],
    )
    return render(
        request,
        "tenant/reviews/queue.html",
        {
            "open_findings": open_findings,
            "closed_findings": closed_findings,
            "open_count": len(open_findings),
        },
    )
