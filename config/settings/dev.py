"""Local development settings. Never deployed; never used in CI."""

from __future__ import annotations

from .base import *  # noqa: F401, F403

DEBUG = True

# Single-instance app: one host. LAN IP kept for phone testing.
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]", "192.168.0.195"]
INTERNAL_IPS = ["127.0.0.1"]
