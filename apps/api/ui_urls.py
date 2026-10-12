"""Token management UI for the signed-in user (`/super/profile/api-tokens/...`)."""

from __future__ import annotations

from django.urls import path

from . import ui_views

app_name = "api_tokens"

urlpatterns = [
    path("", ui_views.tokens_page, name="list"),
    path("<uuid:token_id>/revoke/", ui_views.token_revoke, name="revoke"),
]
