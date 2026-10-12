"""URL patterns for the agent API (`/api/v1/...`)."""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "api"

urlpatterns = [
    path("me/", views.MeView.as_view(), name="me"),
]
