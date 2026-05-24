"""URL patterns for the approvals operator UI (`/super/approvals/...`)."""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "approvals"

urlpatterns = [
    path("", views.list_view, name="list"),
    path("<uuid:approval_id>/", views.detail_view, name="detail"),
    path("<uuid:approval_id>/approve/", views.approve_view, name="approve"),
    path("<uuid:approval_id>/deny/", views.deny_view, name="deny"),
]
