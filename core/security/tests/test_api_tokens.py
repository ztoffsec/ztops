"""Tests for core.security.api_tokens (format, entropy, parsing, hashing)."""

from __future__ import annotations

import base64
import re
from unittest.mock import patch

import pytest

from core.security import api_tokens, crypto

_FORMAT = re.compile(r"\Aztops_[0-9a-f]{12}_[A-Za-z0-9_-]{43}\Z")


def test_generated_token_matches_wire_format() -> None:
    tok = api_tokens.generate()
    assert _FORMAT.match(tok.raw)
    assert tok.raw.startswith(f"ztops_{tok.prefix}_")
    assert len(tok.raw) == api_tokens.MAX_TOKEN_LEN


def test_secret_carries_256_bits_from_csprng() -> None:
    tok = api_tokens.generate()
    secret = tok.raw.split("_", 2)[2]
    decoded = base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
    assert len(decoded) * 8 >= 256
    with patch("core.security.api_tokens.secrets.token_urlsafe", return_value="x" * 43) as m:
        api_tokens.generate()
    m.assert_called_once_with(32)


def test_tokens_and_prefixes_are_unique() -> None:
    raws = {api_tokens.generate().raw for _ in range(20)}
    prefixes = {api_tokens.new_prefix() for _ in range(200)}
    assert len(raws) == 20
    assert len(prefixes) == 200


def test_hash_is_argon2id_and_not_plaintext() -> None:
    tok = api_tokens.generate()
    assert tok.hashed.startswith("$argon2id$")
    secret = tok.raw.split("_", 2)[2]
    assert secret not in tok.hashed
    assert api_tokens.verify(tok.raw, tok.hashed)
    assert not api_tokens.verify(tok.raw[:-1] + ("A" if tok.raw[-1] != "A" else "B"), tok.hashed)


def test_repr_never_leaks_secret() -> None:
    tok = api_tokens.generate()
    secret = tok.raw.split("_", 2)[2]
    assert secret not in repr(tok)
    assert secret not in str(tok)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "ztops_",
        "ztops_abcdef012345_",
        "ztops_ABCDEF012345_" + "a" * 43,  # uppercase prefix
        "ztops_abcdef01234_" + "a" * 44,  # short prefix
        "ztops_abcdef012345_" + "a" * 42,  # short secret
        "ztops_abcdef012345_" + "a" * 44,  # long secret
        "ztops_abcdef012345_" + "a" * 42 + "=",  # padding char
        "ztops_abcdef012345_" + "a" * 42 + "\n",
        "zt0ps_abcdef012345_" + "a" * 43,
        "ztops_abcdef012345_" + "a" * 42 + "é",
        " ztops_abcdef012345_" + "a" * 42,
    ],
)
def test_parse_prefix_rejects_malformed(raw: str) -> None:
    assert api_tokens.parse_prefix(raw) is None


def test_parse_prefix_accepts_generated() -> None:
    tok = api_tokens.generate()
    assert api_tokens.parse_prefix(tok.raw) == tok.prefix


def test_burn_verify_runs_one_failing_argon2_verify() -> None:
    tok = api_tokens.generate()
    results: list[bool] = []
    real = crypto.verify_token

    def spy(raw: str, encoded: str) -> bool:
        results.append(real(raw, encoded))
        return results[-1]

    with patch("core.security.api_tokens.verify_token", side_effect=spy):
        api_tokens.burn_verify(tok.raw)
    assert results == [False]
