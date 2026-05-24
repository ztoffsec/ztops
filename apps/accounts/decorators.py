"""Role-gated view decorators.

`superadmin_required` is the only role gate. Everyday read/write
views use Django's stock `@login_required` (any authenticated active
user can access — this is an internal team app).
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse

if TYPE_CHECKING:
    from django.http import HttpRequest


def _redirect_to_login(request: HttpRequest) -> HttpResponseRedirect:
    login_url = reverse("accounts:login")
    qs = urlencode({"next": request.get_full_path()})
    return HttpResponseRedirect(f"{login_url}?{qs}")


def superadmin_required(
    view_func: Callable[..., HttpResponse],
) -> Callable[..., HttpResponse]:
    """Restrict the wrapped view to authenticated superadmins."""

    @wraps(view_func)
    def _wrapped(request: HttpRequest, *args: object, **kwargs: object) -> HttpResponse:
        if not request.user.is_authenticated:
            return _redirect_to_login(request)
        if not getattr(request.user, "is_superadmin", False):
            return HttpResponse(
                "Forbidden: superadmin role required.",
                status=403,
                content_type="text/plain",
            )
        return view_func(request, *args, **kwargs)

    return _wrapped
