"""Argon2id wrappers for hashing short-lived tokens at rest.

The project hardening spec mandates that secret-like material (API
tokens, enrollment tokens, recovery codes) be hashed before storage.
Use this module's
helpers rather than importing argon2 directly, so the parameter set
stays consistent across the codebase and rotates from one place.

The default ``PasswordHasher`` parameters from argon2-cffi are
deliberate: roughly 100ms per hash on modern hardware, which is
overkill for short-lived 32-byte tokens but cheap enough to apply
uniformly. If profiling shows it as a hot path later we can drop to
a lower-cost preset; until then, no tuning.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher: PasswordHasher = PasswordHasher()


def hash_token(raw: str) -> str:
    """Return the argon2id PHC-encoded hash of ``raw``."""
    return _hasher.hash(raw)


def verify_token(raw: str, encoded: str) -> bool:
    """Constant-time verification: True iff ``raw`` matches ``encoded``."""
    try:
        return _hasher.verify(encoded, raw)
    except VerifyMismatchError:
        return False
