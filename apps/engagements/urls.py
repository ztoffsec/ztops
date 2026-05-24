"""URL patterns for the tenant-scoped Engagements UI."""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "engagements"

urlpatterns = [
    path("", views.engagements_list, name="list"),
    path("new/", views.engagement_new, name="new"),
    path("<uuid:engagement_id>/", views.engagement_detail, name="detail"),
    path("<uuid:engagement_id>/edit/", views.engagement_edit, name="edit"),
    path("<uuid:engagement_id>/assets/add/", views.asset_add, name="asset_add"),
    path(
        "<uuid:engagement_id>/assets/<uuid:asset_id>/delete/",
        views.asset_delete,
        name="asset_delete",
    ),
    path(
        "<uuid:engagement_id>/scope-rules/add/",
        views.scope_rule_add,
        name="scope_rule_add",
    ),
    path(
        "<uuid:engagement_id>/scope-rules/<uuid:rule_id>/delete/",
        views.scope_rule_delete,
        name="scope_rule_delete",
    ),
]
