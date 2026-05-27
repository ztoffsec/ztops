"""Superadmin report-config URLs (scope categories), mounted under /super/."""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "report_admin"

urlpatterns = [
    path("", views.templates_list, name="templates_list"),
    path("templates/new/", views.template_new, name="template_new"),
    path("templates/<slug:slug>/edit/", views.template_edit, name="template_edit"),
    path("templates/<slug:slug>/remove/", views.template_remove, name="template_remove"),
    path("templates/<slug:slug>/sections/new/", views.section_new, name="section_new"),
    path(
        "templates/<slug:slug>/sections/<uuid:section_id>/edit/",
        views.section_edit,
        name="section_edit",
    ),
    path(
        "templates/<slug:slug>/sections/<uuid:section_id>/remove/",
        views.section_remove,
        name="section_remove",
    ),
    path(
        "templates/<slug:slug>/sections/<uuid:section_id>/move/<str:direction>/",
        views.section_move,
        name="section_move",
    ),
    path("scope/", views.scope_categories_list, name="scope_list"),
    path("scope/new/", views.scope_category_new, name="scope_new"),
    path("scope/<slug:slug>/edit/", views.scope_category_edit, name="scope_edit"),
    path("scope/<slug:slug>/remove/", views.scope_category_remove, name="scope_remove"),
    path("scope/<slug:slug>/move/<str:direction>/", views.scope_category_move, name="scope_move"),
]
