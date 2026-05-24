"""URL patterns for the superadmin surface (`/super/...`)."""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("profile/", views.profile_view, name="profile"),
    path("logout/", views.logout_view, name="logout"),
    path("users/", views.users_list, name="users_list"),
    path("users/new/", views.user_new, name="user_new"),
    path("users/<uuid:user_id>/", views.user_detail, name="user_detail"),
    path(
        "users/<uuid:user_id>/enroll/",
        views.user_issue_enrollment,
        name="user_issue_enrollment",
    ),
]
