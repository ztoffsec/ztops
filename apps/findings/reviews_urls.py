"""URL patterns for the /super/reviews/ global queue."""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "reviews"

urlpatterns = [
    path("", views.reviews_queue, name="queue"),
]
