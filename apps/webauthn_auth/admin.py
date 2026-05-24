"""WebAuthnCredential + EnrollmentToken on the superadmin AdminSite."""

from __future__ import annotations

from django.contrib import admin

from apps.accounts.admin import superadmin_site

from .models import EnrollmentToken, WebAuthnCredential


@admin.register(WebAuthnCredential, site=superadmin_site)
class WebAuthnCredentialAdmin(admin.ModelAdmin):
    list_display = ("user", "nickname", "aaguid", "sign_count", "created_at", "last_used_at")
    list_filter = ("transports",)
    search_fields = ("user__email", "nickname")
    readonly_fields = (
        "id",
        "credential_id",
        "public_key",
        "sign_count",
        "aaguid",
        "created_at",
        "last_used_at",
    )
    ordering = ("-created_at",)


@admin.register(EnrollmentToken, site=superadmin_site)
class EnrollmentTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "token_prefix", "expires_at", "used_at", "created_at")
    list_filter = ("used_at",)
    search_fields = ("user__email", "token_prefix")
    readonly_fields = ("id", "token_hash", "token_prefix", "created_at", "used_at")
    ordering = ("-created_at",)

    def has_add_permission(self, request):
        # Tokens are issued by `register_superadmin_passkey`, not the admin.
        return False
