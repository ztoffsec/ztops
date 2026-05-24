"""Tests for the typed env loader."""

from __future__ import annotations

import pytest

from core.security.env import MissingEnvError, env, env_required


def test_env_returns_value_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZTOPS_TEST_VAR", "value-1")
    assert env("ZTOPS_TEST_VAR") == "value-1"


def test_env_returns_default_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZTOPS_TEST_VAR", raising=False)
    assert env("ZTOPS_TEST_VAR", "fallback") == "fallback"


def test_env_raises_when_unset_and_no_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZTOPS_TEST_VAR", raising=False)
    with pytest.raises(MissingEnvError, match="ZTOPS_TEST_VAR"):
        env("ZTOPS_TEST_VAR")


def test_env_returns_empty_string_when_explicitly_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # Empty string is a real value; only "unset" should fall back.
    monkeypatch.setenv("ZTOPS_TEST_VAR", "")
    assert env("ZTOPS_TEST_VAR", "fallback") == ""


def test_env_required_raises_on_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZTOPS_REQUIRED_VAR", raising=False)
    with pytest.raises(MissingEnvError, match="ZTOPS_REQUIRED_VAR"):
        env_required("ZTOPS_REQUIRED_VAR")


def test_env_required_raises_on_empty_string(monkeypatch: pytest.MonkeyPatch) -> None:
    # Unlike `env()`, `env_required()` treats "" as effectively missing —
    # production must never accept a blank secret.
    monkeypatch.setenv("ZTOPS_REQUIRED_VAR", "")
    with pytest.raises(MissingEnvError, match="ZTOPS_REQUIRED_VAR"):
        env_required("ZTOPS_REQUIRED_VAR")


def test_env_required_returns_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZTOPS_REQUIRED_VAR", "set")
    assert env_required("ZTOPS_REQUIRED_VAR") == "set"
