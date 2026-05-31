"""URL patterns for the WebAuthn ceremony endpoints."""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "webauthn_auth"

urlpatterns = [
    path("enroll/<str:token>/", views.enroll_page, name="enroll"),
    path("register/start/<str:token>/", views.registration_start, name="register_start"),
    path("register/finish/<str:token>/", views.registration_finish, name="register_finish"),
    path("login/start/", views.login_start, name="login_start"),
    path("login/finish/", views.login_finish, name="login_finish"),
    path(
        "login/start-usernameless/",
        views.login_start_usernameless,
        name="login_start_usernameless",
    ),
    path(
        "login/finish-usernameless/",
        views.login_finish_usernameless,
        name="login_finish_usernameless",
    ),
]
