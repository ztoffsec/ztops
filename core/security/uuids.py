"""UUIDv7 generator per RFC 9562.

UUIDv7 is the right primary-key choice for ZTOps tables: the leading
48 bits are a millisecond Unix timestamp, so rows sort by creation time
naturally and B-tree inserts stay roughly sequential (good cache
behavior). Unlike UUIDv4, the URL form is not a foothold for
enumeration attacks either, since 74 bits of entropy follow the
timestamp.

Layout (bits, leftmost = MSB):
    0  -  47   unix_ts_ms     (48 bits)
    48 -  51   version (=7)   ( 4 bits)
    52 -  63   rand_a         (12 bits)
    64 -  65   variant (=10)  ( 2 bits)
    66 - 127   rand_b         (62 bits)
"""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Final

_VERSION: Final[int] = 0x7
_VARIANT_RFC4122: Final[int] = 0b10  # variant bits per RFC 9562 §4
_TIMESTAMP_MASK: Final[int] = (1 << 48) - 1
_RAND_A_BITS: Final[int] = 12
_RAND_B_BITS: Final[int] = 62


def uuid7() -> uuid.UUID:
    """Return a new RFC-9562 UUIDv7.

    Time source: ``time.time_ns()`` truncated to milliseconds. Random
    fields come from ``secrets`` (cryptographically strong PRNG).
    """
    ms = (time.time_ns() // 1_000_000) & _TIMESTAMP_MASK
    rand_a = secrets.randbits(_RAND_A_BITS)
    rand_b = secrets.randbits(_RAND_B_BITS)

    value = (ms << 80) | (_VERSION << 76) | (rand_a << 64) | (_VARIANT_RFC4122 << 62) | rand_b
    return uuid.UUID(int=value)
