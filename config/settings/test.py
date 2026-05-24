"""Settings used by pytest. Production-shaped strictness, throwaway state."""

from __future__ import annotations

from .base import *  # noqa: F401, F403
from .base import DATABASES  # explicit re-import for mypy on the mutation below

DEBUG = False

SECRET_KEY = "test-only-secret-never-used-in-real-environments"  # noqa: S105

ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]

DATABASES["default"]["TEST"] = {"NAME": "ztops_test"}

SECURE_PROXY_SSL_HEADER = None

# WebAuthn ceremony tests run via the Django test client (Host=testserver).
WEBAUTHN_RP_ID = "testserver"
WEBAUTHN_RP_NAME = "ZTOps (test)"
WEBAUTHN_RP_ORIGINS = ("http://testserver",)

# Rate limiting off by default in the suite — the auth/enroll endpoints are
# exercised far above their production per-minute caps across the run, and the
# Redis counters persist between runs. The dedicated 429 test re-enables it
# locally via @override_settings(RATELIMIT_ENABLE=True) + cache.clear().
RATELIMIT_ENABLE = False
