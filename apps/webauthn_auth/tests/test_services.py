"""Tests for the WebAuthn service layer.

The actual cryptographic verification is owned by the `webauthn`
library — these tests mock its verify helpers and focus on what THIS
codebase is responsible for: session-state handling, model creation,
error mapping, and the anti-leak invariants (no-such-user behaves like
no-credentials).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from django.test import RequestFactory

from apps.accounts.models import User
from apps.webauthn_auth.models import WebAuthnCredential
from apps.webauthn_auth.services import (
    WebAuthnError,
    finish_authentication,
    finish_registration,
    start_authentication,
    start_registration,
)


def _request_with_session(rf: RequestFactory) -> Any:
    """Build a request that has a writable session dict (for ceremony state)."""
    request = rf.post("/")
    request.session = {}  # type: ignore[attr-defined]
    return request


# ---- start_registration ----


@pytest.mark.django_db
def test_start_registration_stores_challenge_in_session(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="reg@example.com", display_name="Reg")
    request = _request_with_session(rf)

    options = start_registration(user, request)

    assert "challenge" in options
    assert request.session["webauthn_reg_user"] == str(user.id)
    assert request.session["webauthn_reg_challenge"]


@pytest.mark.django_db
def test_start_registration_excludes_existing_credentials(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="ex@example.com", display_name="Ex")
    WebAuthnCredential.objects.create(user=user, credential_id=b"already-here", public_key=b"x")
    request = _request_with_session(rf)

    options = start_registration(user, request)

    # The lib serializes excludeCredentials with id as base64url. We just
    # assert the field is present and non-empty when credentials exist.
    assert options.get("excludeCredentials")


# ---- finish_registration ----


@pytest.mark.django_db
def test_finish_registration_persists_a_credential(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="fin@example.com", display_name="Fin")
    request = _request_with_session(rf)
    # Seed session as if start_registration had run.
    request.session["webauthn_reg_user"] = str(user.id)
    request.session["webauthn_reg_challenge"] = "Y2hhbGxlbmdl"  # b"challenge"

    fake_verified = MagicMock()
    fake_verified.credential_id = b"new-cred-id"
    fake_verified.credential_public_key = b"new-pub"
    fake_verified.sign_count = 0
    fake_verified.aaguid = "12345678-1234-1234-1234-123456789012"

    with patch(
        "apps.webauthn_auth.services.verify_registration_response",
        return_value=fake_verified,
    ):
        cred = finish_registration(request, {"response": {"transports": ["internal"]}})

    assert cred.user_id == user.id
    assert bytes(cred.credential_id) == b"new-cred-id"
    assert cred.transports == ["internal"]
    assert "webauthn_reg_challenge" not in request.session  # consumed


@pytest.mark.django_db
def test_finish_registration_without_challenge_in_session_raises(rf: RequestFactory) -> None:
    request = _request_with_session(rf)
    with pytest.raises(WebAuthnError, match="no registration"):
        finish_registration(request, {})


@pytest.mark.django_db
def test_finish_registration_with_lib_failure_raises_clean_error(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="bad@example.com", display_name="Bad")
    request = _request_with_session(rf)
    request.session["webauthn_reg_user"] = str(user.id)
    request.session["webauthn_reg_challenge"] = "Y2hhbGxlbmdl"

    with (
        patch(
            "apps.webauthn_auth.services.verify_registration_response",
            side_effect=ValueError("bad attestation"),
        ),
        pytest.raises(WebAuthnError, match="verification failed"),
    ):
        finish_registration(request, {})


# ---- start_authentication ----


@pytest.mark.django_db
def test_start_authentication_for_unknown_user_raises(rf: RequestFactory) -> None:
    request = _request_with_session(rf)
    with pytest.raises(WebAuthnError, match="no credentials"):
        start_authentication("ghost@example.com", request)


@pytest.mark.django_db
def test_start_authentication_for_user_without_credentials_raises(rf: RequestFactory) -> None:
    User.objects.create_user(email="empty@example.com", display_name="Empty")
    request = _request_with_session(rf)
    with pytest.raises(WebAuthnError, match="no credentials"):
        start_authentication("empty@example.com", request)


@pytest.mark.django_db
def test_start_authentication_for_user_with_creds_stores_challenge(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="auth@example.com", display_name="Auth")
    WebAuthnCredential.objects.create(user=user, credential_id=b"k", public_key=b"p")
    request = _request_with_session(rf)

    options = start_authentication("auth@example.com", request)

    assert "challenge" in options
    assert request.session["webauthn_auth_user"] == str(user.id)


# ---- finish_authentication ----


@pytest.mark.django_db
def test_finish_authentication_updates_sign_count_and_returns_user(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="ok@example.com", display_name="OK")
    cred = WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"valid-id",
        public_key=b"pk",
        sign_count=5,
    )
    request = _request_with_session(rf)
    request.session["webauthn_auth_user"] = str(user.id)
    request.session["webauthn_auth_challenge"] = "Y2hhbGxlbmdl"

    fake_verified = MagicMock()
    fake_verified.new_sign_count = 6

    # `id` field of the response is base64url('valid-id') = "dmFsaWQtaWQ"
    with patch(
        "apps.webauthn_auth.services.verify_authentication_response",
        return_value=fake_verified,
    ):
        result_user = finish_authentication(request, {"id": "dmFsaWQtaWQ"})

    assert result_user.id == user.id
    cred.refresh_from_db()
    assert cred.sign_count == 6
    assert cred.last_used_at is not None


@pytest.mark.django_db
def test_finish_authentication_detects_sign_count_regression(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="clone@example.com", display_name="Clone")
    WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"cl",
        public_key=b"pk",
        sign_count=10,
    )
    request = _request_with_session(rf)
    request.session["webauthn_auth_user"] = str(user.id)
    request.session["webauthn_auth_challenge"] = "Y2hhbGxlbmdl"

    fake_verified = MagicMock()
    fake_verified.new_sign_count = 9  # regressed!

    with (
        patch(
            "apps.webauthn_auth.services.verify_authentication_response",
            return_value=fake_verified,
        ),
        pytest.raises(WebAuthnError, match="clone"),
    ):
        finish_authentication(request, {"id": "Y2w"})  # base64url('cl')


@pytest.mark.django_db
def test_finish_authentication_without_session_state_raises(rf: RequestFactory) -> None:
    request = _request_with_session(rf)
    with pytest.raises(WebAuthnError, match="no authentication"):
        finish_authentication(request, {"id": "anything"})


@pytest.mark.django_db
def test_finish_authentication_with_unknown_credential_raises(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="nocred@example.com", display_name="NC")
    request = _request_with_session(rf)
    request.session["webauthn_auth_user"] = str(user.id)
    request.session["webauthn_auth_challenge"] = "Y2hhbGxlbmdl"

    with pytest.raises(WebAuthnError, match="not registered"):
        finish_authentication(request, {"id": "dW5rbm93bg"})  # b'unknown'
