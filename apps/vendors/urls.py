"""URL patterns for the Vendor surface."""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "vendors"

urlpatterns = [
    path("", views.vendors_list, name="list"),
    path("new/", views.vendor_new, name="new"),
    path("<slug:slug>/", views.vendor_detail, name="detail"),
    path("<slug:slug>/edit/", views.vendor_edit, name="edit"),
    path("<slug:slug>/delete/", views.vendor_delete, name="delete"),
]
