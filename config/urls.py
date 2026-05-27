"""Root URLconf — single-instance app, one urlpatterns table.

Two URL spaces:
- `/super/...` — superadmin shell: login, dashboard, logout,
  approvals, admin, audit. Gated by `@superadmin_required` where
  appropriate.
- everything else — the everyday team UI: findings, engagements,
  attachments. Gated by `@login_required` (any authenticated active
  user). No more tenant subdomains.
"""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import include, path
from django.views.decorators.http import require_safe

from apps.accounts.admin import superadmin_site


@require_safe
def healthcheck(_request: HttpRequest) -> HttpResponse:
    """Cheap liveness probe. Accepts GET and HEAD."""
    return HttpResponse("ok", content_type="text/plain")


@require_safe
def root_redirect(request: HttpRequest) -> HttpResponse:
    """Send `/` to the dashboard if signed in, otherwise to the login page."""
    if request.user.is_authenticated:
        return HttpResponseRedirect("/super/dashboard/")
    return HttpResponseRedirect("/super/login/")


urlpatterns = [
    path("", root_redirect, name="root"),
    path("healthz/", healthcheck, name="healthcheck"),
    path("webauthn/", include("apps.webauthn_auth.urls")),
    path("findings/", include("apps.findings.urls")),
    path("findings/artifacts/", include("apps.attachments.urls")),
    path("vendors/", include("apps.vendors.urls")),
    path("reports/", include("apps.reports.urls")),
    path("super/", include("apps.accounts.urls")),
    path("super/approvals/", include("apps.approvals.urls")),
    # Report reviews sub-tab must precede the findings reviews include
    # (which matches the bare "super/reviews/" path).
    path("super/reviews/reports/", include("apps.reports.review_urls")),
    path("super/reviews/", include("apps.findings.reviews_urls")),
    path("super/report-config/", include("apps.reports.admin_urls")),
    path("super/admin/", superadmin_site.urls),
]
