"""URL patterns for the Artifacts surface, mounted under /findings/."""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "attachments"

urlpatterns = [
    path("<uuid:finding_id>/upload/", views.upload, name="upload"),
    path("<uuid:finding_id>/image/upload/", views.upload_image, name="image_upload"),
    path(
        "<uuid:finding_id>/<uuid:attachment_id>/image/",
        views.serve_image,
        name="image",
    ),
    path(
        "<uuid:finding_id>/<uuid:attachment_id>/download/",
        views.download,
        name="download",
    ),
    path(
        "<uuid:finding_id>/<uuid:attachment_id>/delete/",
        views.delete_attachment,
        name="delete",
    ),
]
