"""Typed environment-variable loader.

Centralizes how settings read from the process environment so the
`os.environ.get(...)` pattern stays out of feature code. Two entry points:

- ``env(name, default)`` — returns the env var or the default; raises only
  when neither exists. Used during Django settings construction where a
  reasonable default keeps `manage.py check` runnable without a live env.

- ``env_required(name)`` — refuses to fall through; raises immediately when
  the variable is missing or empty. Used in prod settings to make
  misconfigured deploys fail at import time rather than at first request.
"""

from __future__ import annotations

import os


class MissingEnvError(RuntimeError):
    """Raised when a required environment variable is not set."""


def env(name: str, default: str | None = None) -> str:
    """Return ``$name`` from the environment, falling back to ``default``.

    Raises :class:`MissingEnvError` only when both the variable is unset
    AND no default is supplied. Empty-string env values are returned as-is
    (they are explicit, while "unset" is implicit).
    """
    value = os.environ.get(name)
    if value is not None:
        return value
    if default is not None:
        return default
    raise MissingEnvError(f"Required environment variable {name} is not set.")


def env_required(name: str) -> str:
    """Return ``$name`` from the environment; raise if missing or empty.

    Prod settings should use this for any value whose absence would silently
    weaken security (e.g. ``DJANGO_SECRET_KEY``, ``POSTGRES_PASSWORD``).
    """
    value = os.environ.get(name)
    if not value:
        raise MissingEnvError(
            f"Production environment requires {name} to be set to a non-empty value.",
        )
    return value
