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
    path("<uuid:report_id>/findings/add/", views.report_add_finding, name="add_finding"),
    path("<uuid:report_id>/findings/new/", views.report_create_finding, name="create_finding"),
    path(
        "<uuid:report_id>/findings/<uuid:finding_id>/edit/",
        views.report_edit_finding,
        name="edit_finding",
    ),
    path(
        "<uuid:report_id>/findings/<uuid:finding_id>/remove/",
        views.report_remove_finding,
        name="remove_finding",
    ),
]
