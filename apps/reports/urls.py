"""URL patterns for the Reports surface, mounted at /reports/."""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "reports"

urlpatterns = [
    path("", views.reports_list, name="list"),
    path("new/", views.report_new, name="new"),
    path("<uuid:report_id>/", views.report_detail, name="detail"),
    path("<uuid:report_id>/edit/", views.report_edit, name="edit"),
]
