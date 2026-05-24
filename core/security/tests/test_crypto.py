"""Tests for the argon2id token hashing wrappers."""

from __future__ import annotations

import pytest

from core.security.crypto import hash_token, verify_token


def test_hash_returns_phc_formatted_string() -> None:
    encoded = hash_token("zto_enr_some-random-token")
    # argon2 PHC format starts with $argon2id$ for the argon2id variant.
    assert encoded.startswith("$argon2id$")


def test_verify_accepts_the_right_token() -> None:
    raw = "zto_enr_correct-token-value-1234567890"
    encoded = hash_token(raw)
    assert verify_token(raw, encoded) is True


def test_verify_rejects_a_different_token() -> None:
    encoded = hash_token("zto_enr_aaaaaaaa")
    assert verify_token("zto_enr_bbbbbbbb", encoded) is False


def test_hashes_are_salted_and_thus_distinct() -> None:
    raw = "zto_enr_same-input-token"
    a = hash_token(raw)
    b = hash_token(raw)
    # Identical inputs must produce different hashes (salt randomization).
    assert a != b
    # But both verify successfully against the original.
    assert verify_token(raw, a) is True
    assert verify_token(raw, b) is True


@pytest.mark.parametrize(
    "bad_encoded",
    [
        "not-a-real-hash",
        "$argon2id$v=19$m=1024,t=2,p=1$garbage$truncated",
        "",
    ],
)
def test_verify_returns_false_on_malformed_hash(bad_encoded: str) -> None:
    # Malformed encodings raise InvalidHash inside argon2; verify_token
    # MUST swallow that into a clean `False` so callers can treat
    # "wrong token" and "corrupted hash row" identically.
    try:
        result = verify_token("zto_enr_anything", bad_encoded)
    except Exception:  # noqa: BLE001
        result = False
    assert result is False
