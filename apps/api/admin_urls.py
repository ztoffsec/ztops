"""Superadmin overview of every user's API tokens (`/super/api-tokens/`)."""

from __future__ import annotations

from django.urls import path

from . import ui_views

app_name = "api_tokens_admin"

urlpatterns = [
    path("", ui_views.admin_tokens_list, name="list"),
]
