"""AuditLogEntry on the superadmin AdminSite — read-only.

Add / change / delete are all disabled at the admin layer to match the
DB-layer triggers that reject UPDATE / DELETE / TRUNCATE on this table.
"""

from __future__ import annotations

from django.contrib import admin

from apps.accounts.admin import superadmin_site

from .models import AuditLogEntry


@admin.register(AuditLogEntry, site=superadmin_site)
class AuditLogEntryAdmin(admin.ModelAdmin):
    list_display = (
        "timestamp",
        "action",
        "actor_email",
        "target_kind",
        "target_label",
        "actor_ip",
    )
    list_filter = ("action", "target_kind")
    search_fields = ("actor_email", "target_id", "target_label", "action")
    readonly_fields = tuple(  # noqa: RUF012 — Django admin convention
        f.name for f in AuditLogEntry._meta.get_fields()
    )
    ordering = ("-timestamp",)
    date_hierarchy = "timestamp"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        # Listing/viewing is allowed; editing isn't.
        return False

    def has_delete_permission(self, request, obj=None):
        return False
