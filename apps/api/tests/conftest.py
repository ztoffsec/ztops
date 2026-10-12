"""Shared fixtures for apps.api tests."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import timedelta

import pytest
from django.core.cache import cache
from django.utils import timezone

from apps.accounts.models import Role, User
from apps.api.models import ApiToken
from core.security import api_tokens

MakeToken = Callable[..., tuple[ApiToken, str]]


@pytest.fixture(autouse=True)
def _clear_cache() -> Iterator[None]:
    # Throttle / rate-limit counters live in the shared cache.
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def alice(db: None) -> User:
    return User.objects.create_user(email="alice@example.com", display_name="Alice")


@pytest.fixture
def bob(db: None) -> User:
    return User.objects.create_user(email="bob@example.com", display_name="Bob")


@pytest.fixture
def root(db: None) -> User:
    return User.objects.create_user(
        email="root@example.com",
        display_name="Root",
        role=Role.SUPERADMIN,
    )


@pytest.fixture
def make_token(db: None) -> MakeToken:
    """Insert a token row directly (bypassing step-up/UI) for auth tests."""

    def _make(
        user: User,
        *,
        scopes: list[str] | None = None,
        lifetime: timedelta = timedelta(days=30),
        name: str = "test agent",
    ) -> tuple[ApiToken, str]:
        generated = api_tokens.generate()
        token = ApiToken.objects.create(
            user=user,
            name=name,
            prefix=generated.prefix,
            token_hash=generated.hashed,
            scopes=scopes if scopes is not None else ["findings:read"],
            expires_at=timezone.now() + lifetime,
        )
        return token, generated.raw

    return _make
