"""Tests for the UUIDv7 generator."""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable

from core.security.uuids import uuid7

_VERSION_FIELD_MASK = 0xF000
_VERSION_FIELD_SHIFT = 12

_VARIANT_FIELD_MASK = 0xC0000000_00000000
_VARIANT_FIELD_SHIFT = 62


def test_version_bits_are_7() -> None:
    value = uuid7()
    # The four version bits live at integer bits 76-79 in a 128-bit UUID.
    version = (value.int >> 76) & 0xF
    assert version == 7


def test_variant_bits_are_rfc4122_10() -> None:
    value = uuid7()
    # The two variant bits live at integer bits 62-63.
    variant = (value.int >> 62) & 0b11
    assert variant == 0b10


def test_timestamp_encoded_matches_current_time() -> None:
    before_ms = time.time_ns() // 1_000_000
    value = uuid7()
    after_ms = time.time_ns() // 1_000_000

    # Top 48 bits are the unix-ms timestamp.
    ts_ms = value.int >> 80
    # Clock skew between calls in a fast test should be at most a few ms.
    assert before_ms - 5 <= ts_ms <= after_ms + 5


def test_two_uuids_generated_in_sequence_are_sortable() -> None:
    a = uuid7()
    time.sleep(0.002)  # ensure distinct millisecond
    b = uuid7()
    assert a.int < b.int
    # And string form preserves the order too — important for IN clauses
    # and DB-side ORDER BY id.
    assert str(a) < str(b)


def test_bulk_generation_has_no_collisions() -> None:
    seen: set[uuid.UUID] = set()
    for _ in range(10_000):
        seen.add(uuid7())
    assert len(seen) == 10_000


def test_returns_python_uuid_object() -> None:
    value = uuid7()
    assert isinstance(value, uuid.UUID)
    # Verify it's a usable UUID via standard repr / version interrogation.
    # Note: uuid.UUID.version returns the version field as parsed; ours
    # is 7 even though Python's uuid module historically only generated
    # 1/3/4/5.
    assert value.version == 7


def _is_strictly_increasing(values: Iterable[uuid.UUID]) -> bool:
    seq = list(values)
    return all(seq[i].int < seq[i + 1].int for i in range(len(seq) - 1))


def test_many_uuids_with_sleep_are_monotonic() -> None:
    # 5 ms gap each — guarantees distinct ms timestamps, so the ordering
    # is purely from the timestamp prefix, not random tail collisions.
    batch = []
    for _ in range(5):
        batch.append(uuid7())
        time.sleep(0.005)
    assert _is_strictly_increasing(batch)
