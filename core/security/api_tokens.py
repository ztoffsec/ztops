"""Bearer API token format: generation, strict parsing, hashing.

Wire format::

    ztops_<prefix>_<secret>

- ``prefix``: 12 lowercase hex chars (48 bits). Public, non-secret DB lookup
  key — shown in the UI so users can tell their tokens apart. It never
  authenticates anything on its own.
- ``secret``: ``secrets.token_urlsafe(32)`` — 32 bytes (256 bits) from the OS
  CSPRNG, base64url without padding (43 chars).

The full raw token (prefix included) is hashed with argon2id via
``core.security.crypto`` so the stored hash also binds the prefix. The raw
token is returned once by :func:`generate` and must never be persisted or
logged.

Parsing is strict (anchored regex, exact lengths) and happens before any DB
or argon2 work, so malformed input costs nothing.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from functools import lru_cache
from typing import Final

from core.security.crypto import hash_token, verify_token

# Public, documented namespace (not a secret); bandit/ruff flag the name only.
TOKEN_NAMESPACE: Final[str] = "ztops"  # noqa: S105  # nosec B105
PREFIX_HEX_CHARS: Final[int] = 12
SECRET_BYTES: Final[int] = 32  # 256 bits of entropy
_SECRET_B64_CHARS: Final[int] = 43  # len(token_urlsafe(32))

_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    rf"\A{TOKEN_NAMESPACE}_(?P<prefix>[0-9a-f]{{{PREFIX_HEX_CHARS}}})"
    rf"_(?P<secret>[A-Za-z0-9_-]{{{_SECRET_B64_CHARS}}})\Z",
)

# Upper bound on what we are willing to look at in an Authorization header.
MAX_TOKEN_LEN: Final[int] = len(TOKEN_NAMESPACE) + 1 + PREFIX_HEX_CHARS + 1 + _SECRET_B64_CHARS


@dataclass(frozen=True, slots=True)
class GeneratedToken:
    """A freshly minted token. ``raw`` is shown to the user exactly once."""

    prefix: str
    raw: str
    hashed: str

    def __repr__(self) -> str:  # never leak the secret through repr()/logging
        return f"GeneratedToken(prefix={self.prefix!r}, raw=<redacted>)"


def new_prefix() -> str:
    """Return a fresh random lookup prefix (callers retry on collision)."""
    return secrets.token_hex(PREFIX_HEX_CHARS // 2)


def generate(prefix: str | None = None) -> GeneratedToken:
    """Mint a new token. ``prefix`` may be supplied to retry on collision."""
    pfx = prefix if prefix is not None else new_prefix()
    secret = secrets.token_urlsafe(SECRET_BYTES)
    raw = f"{TOKEN_NAMESPACE}_{pfx}_{secret}"
    if _TOKEN_RE.match(raw) is None:  # pragma: no cover - defensive
        msg = "generated token does not match the wire format"
        raise RuntimeError(msg)
    return GeneratedToken(prefix=pfx, raw=raw, hashed=hash_token(raw))


def parse_prefix(raw: str) -> str | None:
    """Return the lookup prefix of a well-formed token, else ``None``."""
    if len(raw) != MAX_TOKEN_LEN:
        return None
    match = _TOKEN_RE.match(raw)
    if match is None:
        return None
    return match.group("prefix")


def verify(raw: str, encoded: str) -> bool:
    """Constant-time argon2id verification of ``raw`` against ``encoded``."""
    return verify_token(raw, encoded)


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return hash_token(f"{TOKEN_NAMESPACE}_{'0' * PREFIX_HEX_CHARS}_{secrets.token_urlsafe(32)}")


def burn_verify(raw: str) -> None:
    """Run one argon2id verification that always fails.

    Used when the prefix is unknown so the response time matches the
    "known prefix, wrong secret" path: no timing oracle on prefix existence.
    """
    verify_token(raw, _dummy_hash())
