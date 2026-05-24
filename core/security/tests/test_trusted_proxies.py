"""Tests for trusted-proxy aware client-IP extraction."""

from __future__ import annotations

from django.test import RequestFactory, override_settings

from core.security.trusted_proxies import get_real_client_ip


@override_settings(TRUSTED_PROXY_IPS=("127.0.0.1",))
def test_direct_connection_returns_remote_addr(rf: RequestFactory) -> None:
    # Connecting client is NOT a trusted proxy; XFF must be ignored entirely
    # even when the attacker tries to set it.
    request = rf.get(
        "/",
        REMOTE_ADDR="203.0.113.7",
        HTTP_X_FORWARDED_FOR="10.0.0.1, 192.0.2.99",
    )
    assert get_real_client_ip(request) == "203.0.113.7"


@override_settings(TRUSTED_PROXY_IPS=("127.0.0.1",))
def test_behind_trusted_proxy_returns_xff_leftmost_untrusted(rf: RequestFactory) -> None:
    request = rf.get(
        "/",
        REMOTE_ADDR="127.0.0.1",
        HTTP_X_FORWARDED_FOR="198.51.100.5",
    )
    assert get_real_client_ip(request) == "198.51.100.5"


@override_settings(TRUSTED_PROXY_IPS=("127.0.0.1", "10.0.0.1"))
def test_walks_xff_right_to_left_skipping_trusted(rf: RequestFactory) -> None:
    # The right-most untrusted hop is the real client even when the chain
    # contains multiple trusted proxies on the inside.
    request = rf.get(
        "/",
        REMOTE_ADDR="127.0.0.1",
        HTTP_X_FORWARDED_FOR="198.51.100.5, 10.0.0.1",
    )
    assert get_real_client_ip(request) == "198.51.100.5"


@override_settings(TRUSTED_PROXY_IPS=("127.0.0.1",))
def test_spoofed_xff_is_ignored_when_remote_addr_is_not_trusted(rf: RequestFactory) -> None:
    # Classic attempt: attacker connects directly and sets XFF themselves.
    # We must NOT honor it.
    request = rf.get(
        "/",
        REMOTE_ADDR="203.0.113.7",
        HTTP_X_FORWARDED_FOR="127.0.0.1",
    )
    assert get_real_client_ip(request) == "203.0.113.7"


@override_settings(TRUSTED_PROXY_IPS=("127.0.0.1",))
def test_missing_xff_behind_trusted_proxy_falls_back_to_proxy_addr(rf: RequestFactory) -> None:
    request = rf.get("/", REMOTE_ADDR="127.0.0.1")
    assert get_real_client_ip(request) == "127.0.0.1"


@override_settings(TRUSTED_PROXY_IPS=("127.0.0.1",))
def test_missing_remote_addr_returns_none(rf: RequestFactory) -> None:
    request = rf.get("/")
    # RequestFactory injects REMOTE_ADDR by default; strip it explicitly.
    request.META.pop("REMOTE_ADDR", None)
    assert get_real_client_ip(request) is None
