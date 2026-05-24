"""SuperAdminApproval on the superadmin AdminSite — read-only inspector.

Mutations to approval state must go through services.approve / .deny so
the audit chain stays intact and the state-machine guards run. The admin
is for inspection only.
"""

from __future__ import annotations

from django.contrib import admin

from apps.accounts.admin import superadmin_site

from .models import SuperAdminApproval


@admin.register(SuperAdminApproval, site=superadmin_site)
class SuperAdminApprovalAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "action",
        "state",
        "requested_by",
        "approved_by",
        "denied_by",
        "expires_at",
    )
    list_filter = ("state", "action")
    search_fields = (
        "requested_by__email",
        "approved_by__email",
        "denied_by__email",
        "action",
    )
    readonly_fields = tuple(  # noqa: RUF012
        f.name for f in SuperAdminApproval._meta.get_fields()
    )
    ordering = ("-created_at",)
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
