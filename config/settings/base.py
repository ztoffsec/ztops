"""Baseline Django settings shared across all environments.

Never put secrets in this file. Environment-specific modules (dev/test/prod)
inherit from this and override what differs.

History note: this project was originally multi-tenant via
django-tenants. The "internal team app, only us" pivot on 2026-05-18
dropped that machinery; there is now exactly one DB schema and no
per-tenant routing.
"""

from __future__ import annotations

import os
import urllib.parse
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Load .env from the project root if present. `override=False` means
# environment variables already set by the shell, systemd, Docker, or CI
# always win — `.env` is a dev convenience, never a prod source of truth.
load_dotenv(BASE_DIR / ".env", override=False)

# Import-side effect: pull the typed env loader from core.security so all
# settings go through a single, audited path instead of scattered
# os.environ.get(...) calls. core/security is mypy --strict.
from core.security.env import env  # noqa: E402

# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

SECRET_KEY = env("DJANGO_SECRET_KEY", default="dev-only-secret-must-be-overridden")
DEBUG = False  # dev.py flips this; prod.py asserts it stays False.

ALLOWED_HOSTS: list[str] = [
    h.strip() for h in env("DJANGO_ALLOWED_HOSTS", "").split(",") if h.strip()
]

ROOT_URLCONF = "config.urls"

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"  # Overridden per-model with UUIDv7.

# ---------------------------------------------------------------------------
# Apps — single instance, no tenancy split.
# ---------------------------------------------------------------------------

INSTALLED_APPS: list[str] = [
    # First-party
    "apps.accounts",
    "apps.webauthn_auth",
    "apps.audit",
    "apps.approvals",
    "apps.vendors",
    # Retired (migration stub only; tables dropped in engagements/0002).
    "apps.engagements",
    "apps.findings",
    "apps.attachments",
    "apps.reports",
    # Django built-ins
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.admin",
    # Third-party
    "rest_framework",
]

# Custom passwordless User model; see apps.accounts.models.User.
AUTH_USER_MODEL = "accounts.User"

# WebAuthn is the only authentication path. The backend's authenticate()
# returns None (no password / token-pair flow); login() is invoked by the
# ceremony view layer with the resolved user.
AUTHENTICATION_BACKENDS: tuple[str, ...] = ("apps.accounts.backends.WebAuthnAuthBackend",)

LOGIN_URL = "/super/login/"
LOGIN_REDIRECT_URL = "/super/dashboard/"

# WebAuthn relying-party configuration. Defaults are dev-only; prod must
# set WEBAUTHN_RP_ID to the registered hostname (no scheme/port) and
# WEBAUTHN_RP_ORIGINS to a comma-separated list of full HTTPS origins.
WEBAUTHN_RP_ID = env("WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_RP_NAME = env("WEBAUTHN_RP_NAME", "ZTOps (dev)")
WEBAUTHN_RP_ORIGINS: tuple[str, ...] = tuple(
    origin.strip()
    for origin in env("WEBAUTHN_RP_ORIGINS", "http://localhost:8000").split(",")
    if origin.strip()
)

MIDDLEWARE: list[str] = [
    # Emits CSP (with per-request nonce), COEP, Permissions-Policy.
    "core.security.headers.SecurityHeadersMiddleware",
    # Emits HSTS, Referrer-Policy, COOP, X-Content-Type-Options.
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    # AuthenticationMiddleware populates request.user from the session.
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # MessageMiddleware enables one-shot flash messages on the request.
    "django.contrib.messages.middleware.MessageMiddleware",
    # Emits X-Frame-Options (reads X_FRAME_OPTIONS below).
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # Maps django-ratelimit's Ratelimited exception to HTTP 429 (Retry-After).
    # Last so its process_exception runs first for view-raised Ratelimited.
    "core.security.ratelimit_middleware.RatelimitTo429Middleware",
]

# ---------------------------------------------------------------------------
# Database — plain Postgres (single schema).
# ---------------------------------------------------------------------------

if _database_url := os.environ.get("DATABASE_URL"):
    _parsed = urllib.parse.urlparse(_database_url)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": _parsed.path.lstrip("/") or "ztops",
            "USER": _parsed.username or "ztops",
            "PASSWORD": _parsed.password or "",
            "HOST": _parsed.hostname or "127.0.0.1",
            "PORT": str(_parsed.port or 5432),
            "CONN_MAX_AGE": 60,
            "OPTIONS": {"sslmode": "prefer"},
        },
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": env("POSTGRES_DB", "ztops"),
            "USER": env("POSTGRES_USER", "ztops"),
            "PASSWORD": env("POSTGRES_PASSWORD", default=""),
            "HOST": env("POSTGRES_HOST", "127.0.0.1"),
            "PORT": env("POSTGRES_PORT", "5432"),
            "CONN_MAX_AGE": 60,
            "OPTIONS": {"sslmode": "prefer"},
        },
    }

# ---------------------------------------------------------------------------
# i18n / tz — UI is English-only (per project decision); timestamps in UTC.
# ---------------------------------------------------------------------------

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

# ---------------------------------------------------------------------------
# Static files — served by Caddy in prod; collected to STATIC_ROOT.
# ---------------------------------------------------------------------------

STATIC_URL = "/static/"
STATIC_ROOT = Path(env("STATIC_ROOT", str(BASE_DIR / "staticfiles")))
STATICFILES_DIRS = [BASE_DIR / "static"]

# ---------------------------------------------------------------------------
# Attachments — finding artifacts (PoC scripts, screenshots, recordings).
# Stored OUTSIDE Django's MEDIA_ROOT per hardening requirement #8 so
# they can never be served as static assets. Bytes are streamed by an
# authenticated Django view that forces application/octet-stream +
# Content-Disposition: attachment regardless of the uploaded mime type.
# ---------------------------------------------------------------------------

ATTACHMENTS_ROOT = Path(env("ATTACHMENTS_ROOT", str(BASE_DIR / "var" / "attachments")))
ATTACHMENTS_MAX_SIZE = int(env("ATTACHMENTS_MAX_SIZE", "104857600"))  # 100 MiB

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}

# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ---------------------------------------------------------------------------
# Security headers — split between core.security.headers and Django builtins.
# ---------------------------------------------------------------------------

X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"

TRUSTED_PROXY_IPS: tuple[str, ...] = tuple(
    ip.strip() for ip in env("TRUSTED_PROXY_IPS", "127.0.0.1").split(",") if ip.strip()
)

# ---------------------------------------------------------------------------
# Sessions — Redis-backed cache. 4h cookie TTL, sliding window, Strict SameSite.
# SECURE flag is set in prod.py where TLS is enforced.
# ---------------------------------------------------------------------------

REDIS_URL = env("REDIS_URL", "redis://127.0.0.1:6379/0")

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
    },
}

SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"
SESSION_COOKIE_AGE = 4 * 60 * 60
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_NAME = "ztops_sessionid"

CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Strict"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
    },
    "root": {
        "handlers": ["console"],
        "level": os.environ.get("LOG_LEVEL", "INFO"),
    },
}
