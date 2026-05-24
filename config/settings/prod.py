"""Production settings. All secrets read from environment, presence asserted."""

from __future__ import annotations

import os

from .base import *  # noqa: F401, F403
from .base import DATABASES, WEBAUTHN_RP_ORIGINS

DEBUG = False  # Never flip this. Ever. The 500 page must not leak stack traces.

# Strict env-presence checks: prod must not fall through to dev defaults.
_REQUIRED_ENV: tuple[str, ...] = (
    "DJANGO_SECRET_KEY",
    "DJANGO_ALLOWED_HOSTS",
    "POSTGRES_PASSWORD",
)
for _name in _REQUIRED_ENV:
    if not os.environ.get(_name):
        raise RuntimeError(f"Production requires environment variable {_name}")

# Cookies + HSTS — Caddy terminates TLS in front of us.
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"

CSRF_COOKIE_SECURE = True
# Must stay False: the WebAuthn ceremony, login, markdown preview and
# tag-input fetch() calls all read `csrftoken` from document.cookie to
# put it in the X-CSRFToken header. HttpOnly would silently break every
# JS-driven POST.
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Strict"

SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31_536_000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SECURE_CONTENT_TYPE_NOSNIFF = True

# Caddy is the only thing in front of us; trust its X-Forwarded-Proto only.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Django 4+ requires HTTPS POST origins to be enumerated explicitly when
# the request comes through a reverse proxy. Mirror the WebAuthn origin
# set so the two never drift: every host that can run the passkey
# ceremony also owes Django a trusted-origin entry.
CSRF_TRUSTED_ORIGINS = list(WEBAUTHN_RP_ORIGINS)

# Force TLS on the Postgres connection — managed PG accepts but doesn't require by default.
DATABASES["default"]["OPTIONS"]["sslmode"] = "require"
