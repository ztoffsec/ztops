"""Smoke tests: assert the Django wiring loads cleanly under the test settings."""

from __future__ import annotations

from typing import TYPE_CHECKING

import django
import pytest
from django.conf import settings

if TYPE_CHECKING:
    from django.test import Client


def test_django_is_importable() -> None:
    assert django.get_version().startswith("5.")


def test_settings_module_is_test_env() -> None:
    assert settings.SETTINGS_MODULE == "config.settings.test"


def test_debug_is_off_under_tests() -> None:
    # Tests must run with the same DEBUG posture as production —
    # otherwise we'd never notice if a regression flipped it on.
    assert settings.DEBUG is False


def test_secret_key_is_not_the_dev_placeholder() -> None:
    # The base.py fallback exists so `manage.py check` can run without a real
    # env, but test settings must inject their own value.
    assert "dev-only-secret" not in settings.SECRET_KEY


# The healthcheck tests below need `django_db` because TenantMainMiddleware
# now resolves the inbound Host against the Domain table on every request.
# The session bootstrap fixture in tests/conftest.py creates the required
# Domain('testserver') row before these tests run.


@pytest.mark.django_db
def test_healthcheck_returns_ok(client: Client) -> None:
    response = client.get("/healthz/")
    assert response.status_code == 200
    assert response.content == b"ok"
    assert response["Content-Type"].startswith("text/plain")


@pytest.mark.django_db
def test_healthcheck_accepts_head(client: Client) -> None:
    # HEAD is the standard probe method for load-balancers / Caddy upstream.
    response = client.head("/healthz/")
    assert response.status_code == 200
    assert response.content == b""  # HEAD responses have no body


@pytest.mark.django_db
def test_healthcheck_emits_security_headers(client: Client) -> None:
    # SecurityHeadersMiddleware must apply to ALL responses — incl. /healthz/.
    response = client.get("/healthz/")
    assert "Content-Security-Policy" in response.headers
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cross-Origin-Embedder-Policy"] == "require-corp"
