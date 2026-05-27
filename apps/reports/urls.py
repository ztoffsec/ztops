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
    path("<uuid:report_id>/content/", views.report_content_edit, name="content_edit"),
    path("<uuid:report_id>/autosave/", views.report_autosave, name="autosave"),
    # Review workflow
    path("<uuid:report_id>/review/submit/", views.report_submit_review, name="submit_review"),
    path("<uuid:report_id>/review/approve/", views.report_approve, name="approve"),
    path("<uuid:report_id>/review/reject/", views.report_reject, name="reject"),
    path("<uuid:report_id>/review/reopen/", views.report_reopen, name="reopen"),
    path("<uuid:report_id>/review/note/", views.report_review_note_add, name="review_note_add"),
    path("<uuid:report_id>/annexes/new/", views.report_annex_new, name="annex_new"),
    path(
        "<uuid:report_id>/annexes/<uuid:annex_id>/edit/", views.report_annex_edit, name="annex_edit"
    ),
    path(
        "<uuid:report_id>/annexes/<uuid:annex_id>/remove/",
        views.report_annex_remove,
        name="annex_remove",
    ),
    path(
        "<uuid:report_id>/annexes/<uuid:annex_id>/move/<str:direction>/",
        views.report_annex_move,
        name="annex_move",
    ),
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
