"""Custom AdminSite gated to superadmins + ModelAdmin for User.

The default Django `admin.site` is replaced by `superadmin_site` mounted
at `/super/admin/`. It overrides:

- `has_permission` to require `is_superadmin` instead of `is_staff`.
- `login` to bounce unauthenticated visitors to our WebAuthn flow at
  `/super/login/` rather than Django's default password form.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from django.contrib import admin
from django.http import HttpResponseRedirect
from django.urls import reverse

from .models import User

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


class SuperadminAdminSite(admin.AdminSite):
    """Django admin restricted to users carrying role=superadmin."""

    site_header = "ZTOps Superadmin"
    site_title = "ZTOps"
    index_title = "Administration"

    def has_permission(self, request: HttpRequest) -> bool:
        return bool(
            request.user.is_active
            and request.user.is_authenticated
            and getattr(request.user, "is_superadmin", False),
        )

    def login(
        self,
        request: HttpRequest,
        extra_context: dict[str, object] | None = None,  # noqa: ARG002
    ) -> HttpResponse:
        # Reroute Django's built-in admin login form to our WebAuthn flow.
        # urlencode the `next` param so the redirect URL is unambiguously
        # under our control (avoids semgrep's open-redirect heuristic).
        target = reverse("accounts:login")
        qs = urlencode({"next": request.path})
        return HttpResponseRedirect(f"{target}?{qs}")


superadmin_site = SuperadminAdminSite(name="superadmin")


# ---- User ----------------------------------------------------------------


@admin.register(User, site=superadmin_site)
class UserAdmin(admin.ModelAdmin):
    list_display = ("email", "display_name", "role", "is_active", "created_at")
    list_filter = ("role", "is_active")
    search_fields = ("email", "display_name")
    readonly_fields = ("id", "created_at", "last_login")
    ordering = ("email",)

    # User creation requires a WebAuthn enrollment ceremony — adding from
    # admin is not supported. Use `register_superadmin_passkey` or the
    # invite flow instead.
    def has_add_permission(self, request: HttpRequest) -> bool:
        return False
