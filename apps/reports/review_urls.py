"""Report-review queue, mounted under /super/reviews/reports/."""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "report_reviews"

urlpatterns = [
    path("", views.report_reviews_queue, name="queue"),
]
