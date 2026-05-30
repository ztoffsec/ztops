"""URL patterns for the Finding CRUD surface."""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "findings"

urlpatterns = [
    path("", views.findings_list, name="list"),
    path("new/", views.finding_new, name="new"),
    path("new/upload-image/", views.finding_new_upload_image, name="new_upload_image"),
    path("preview-markdown/", views.preview_markdown, name="preview_markdown"),
    path("<uuid:finding_id>/", views.finding_detail, name="detail"),
    path("<uuid:finding_id>/edit/", views.finding_edit, name="edit"),
    path("<uuid:finding_id>/delete/", views.finding_delete, name="delete"),
    path("<uuid:finding_id>/notes/add/", views.add_note, name="add_note"),
    path(
        "<uuid:finding_id>/collaborators/add/",
        views.collaborator_add,
        name="collaborator_add",
    ),
    path(
        "<uuid:finding_id>/collaborators/<uuid:user_id>/remove/",
        views.collaborator_remove,
        name="collaborator_remove",
    ),
    path("<uuid:finding_id>/review/start/", views.review_start, name="review_start"),
    path("<uuid:finding_id>/review/approve/", views.review_approve, name="review_approve"),
    path("<uuid:finding_id>/review/reject/", views.review_reject, name="review_reject"),
    path(
        "<uuid:finding_id>/review/resubmit/",
        views.review_resubmit,
        name="review_resubmit",
    ),
    path(
        "<uuid:finding_id>/review/notes/add/",
        views.review_note_add,
        name="review_note_add",
    ),
]
