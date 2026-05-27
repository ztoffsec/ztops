"""Shared fixtures for the attachments test suite."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from django.test import override_settings

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def attachments_root(tmp_path: Path) -> Path:
    """Isolate the on-disk attachment store per test."""
    root = tmp_path / "attachments"
    root.mkdir()
    return root


@pytest.fixture
def settings_root(attachments_root: Path) -> Iterator[Path]:
    with override_settings(ATTACHMENTS_ROOT=str(attachments_root)):
        yield attachments_root
