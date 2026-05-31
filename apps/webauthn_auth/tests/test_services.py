"""Tests for the WebAuthn service layer.

The actual cryptographic verification is owned by the `webauthn`
library — these tests mock its verify helpers and focus on what THIS
codebase is responsible for: session-state handling, model creation,
error mapping, and the anti-leak invariants (no-such-user behaves like
no-credentials).
"""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from django.test import RequestFactory

from apps.accounts.models import User
from apps.webauthn_auth.models import WebAuthnCredential
from apps.webauthn_auth.services import (
    WebAuthnError,
    finish_authentication,
    finish_authentication_usernameless,
    finish_registration,
    start_authentication,
    start_authentication_usernameless,
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


# ---- usernameless flow ----------------------------------------------------


def _b64u(s: str | bytes) -> str:
    data = s.encode("utf-8") if isinstance(s, str) else s
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.mark.django_db
def test_start_authentication_usernameless_clears_user_session_key(rf: RequestFactory) -> None:
    """An email-keyed ceremony in flight must not bleed into the usernameless
    start. The user-key is cleared so finish_authentication_usernameless
    cannot accidentally pick up a stale identity.
    """
    request = _request_with_session(rf)
    request.session["webauthn_auth_user"] = "stale-id"  # pretend prior flow

    options = start_authentication_usernameless(request)

    assert "challenge" in options
    # No allow-credentials list: discoverable-credential discovery on the client.
    assert options.get("allowCredentials") in (None, [])
    assert request.session["webauthn_auth_challenge"]
    assert "webauthn_auth_user" not in request.session


@pytest.mark.django_db
def test_finish_authentication_usernameless_happy_path(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="ul@example.com", display_name="UL")
    cred = WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"ul-cred",
        public_key=b"pk",
        sign_count=2,
    )
    request = _request_with_session(rf)
    request.session["webauthn_auth_challenge"] = _b64u(b"challenge")
    # no webauthn_auth_user => usernameless

    fake = MagicMock()
    fake.new_sign_count = 3
    with patch(
        "apps.webauthn_auth.services.verify_authentication_response",
        return_value=fake,
    ):
        result = finish_authentication_usernameless(
            request,
            {
                "id": _b64u(b"ul-cred"),
                "response": {"userHandle": _b64u(str(user.id))},
            },
        )

    assert result.id == user.id
    cred.refresh_from_db()
    assert cred.sign_count == 3


@pytest.mark.django_db
def test_finish_usernameless_rejects_mode_mismatch_session(rf: RequestFactory) -> None:
    """If both webauthn_auth_user AND webauthn_auth_challenge are present,
    refuse. That state means an email-keyed ceremony started, and finishing
    it via the usernameless path would skip the per-user binding."""
    user = User.objects.create_user(email="mm@example.com", display_name="MM")
    WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"mm-cred",
        public_key=b"pk",
        sign_count=0,
    )
    request = _request_with_session(rf)
    request.session["webauthn_auth_challenge"] = _b64u(b"ch")
    request.session["webauthn_auth_user"] = str(user.id)  # email-keyed start

    with pytest.raises(WebAuthnError, match="mode mismatch"):
        finish_authentication_usernameless(
            request,
            {
                "id": _b64u(b"mm-cred"),
                "response": {"userHandle": _b64u(str(user.id))},
            },
        )


@pytest.mark.django_db
def test_finish_usernameless_rejects_tampered_user_handle(rf: RequestFactory) -> None:
    """The assertion's userHandle must match the credential's user id.
    Even if signature verification would somehow succeed, a mismatched
    handle is refused so the data layer never drifts under the crypto.
    """
    alice = User.objects.create_user(email="a@example.com", display_name="A")
    bob = User.objects.create_user(email="b@example.com", display_name="B")
    WebAuthnCredential.objects.create(
        user=alice,
        credential_id=b"alice-cred",
        public_key=b"pk",
        sign_count=0,
    )
    request = _request_with_session(rf)
    request.session["webauthn_auth_challenge"] = _b64u(b"ch")

    # Authenticator (or attacker) returns BOB's id while presenting ALICE's
    # credential. Must refuse before signature verification even runs.
    with patch(
        "apps.webauthn_auth.services.verify_authentication_response",
    ) as verify:
        with pytest.raises(WebAuthnError, match="userHandle does not match"):
            finish_authentication_usernameless(
                request,
                {
                    "id": _b64u(b"alice-cred"),
                    "response": {"userHandle": _b64u(str(bob.id))},
                },
            )
        verify.assert_not_called()


@pytest.mark.django_db
def test_finish_usernameless_rejects_missing_user_handle(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="nu@example.com", display_name="NU")
    WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"nu-cred",
        public_key=b"pk",
        sign_count=0,
    )
    request = _request_with_session(rf)
    request.session["webauthn_auth_challenge"] = _b64u(b"ch")

    with pytest.raises(WebAuthnError, match="missing userHandle"):
        finish_authentication_usernameless(
            request,
            {"id": _b64u(b"nu-cred"), "response": {}},
        )


@pytest.mark.django_db
def test_finish_usernameless_rejects_malformed_user_handle(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="mh@example.com", display_name="MH")
    WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"mh-cred",
        public_key=b"pk",
        sign_count=0,
    )
    request = _request_with_session(rf)
    request.session["webauthn_auth_challenge"] = _b64u(b"ch")

    # Non-UTF8 bytes inside the userHandle base64 payload.
    bad = _b64u(b"\xff\xfe\xff\xfe")
    with pytest.raises(WebAuthnError, match="malformed userHandle"):
        finish_authentication_usernameless(
            request,
            {"id": _b64u(b"mh-cred"), "response": {"userHandle": bad}},
        )


@pytest.mark.django_db
def test_finish_usernameless_rejects_inactive_owner(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="ina@example.com", display_name="I")
    user.is_active = False
    user.save(update_fields=["is_active"])
    WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"ina-cred",
        public_key=b"pk",
        sign_count=0,
    )
    request = _request_with_session(rf)
    request.session["webauthn_auth_challenge"] = _b64u(b"ch")

    with pytest.raises(WebAuthnError, match="inactive"):
        finish_authentication_usernameless(
            request,
            {
                "id": _b64u(b"ina-cred"),
                "response": {"userHandle": _b64u(str(user.id))},
            },
        )


@pytest.mark.django_db
def test_finish_usernameless_without_session_state_raises(rf: RequestFactory) -> None:
    request = _request_with_session(rf)
    with pytest.raises(WebAuthnError, match="no authentication"):
        finish_authentication_usernameless(
            request,
            {"id": "x", "response": {"userHandle": "x"}},
        )


@pytest.mark.django_db
def test_finish_usernameless_replay_invalidates_challenge(rf: RequestFactory) -> None:
    """Challenge is single-use: after a finish call, the session no longer
    carries it, so a second attempt with the same body must fail closed."""
    user = User.objects.create_user(email="rp@example.com", display_name="R")
    WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"rp-cred",
        public_key=b"pk",
        sign_count=0,
    )
    request = _request_with_session(rf)
    request.session["webauthn_auth_challenge"] = _b64u(b"ch")

    payload = {
        "id": _b64u(b"rp-cred"),
        "response": {"userHandle": _b64u(str(user.id))},
    }
    fake = MagicMock()
    fake.new_sign_count = 1
    with patch(
        "apps.webauthn_auth.services.verify_authentication_response",
        return_value=fake,
    ):
        finish_authentication_usernameless(request, payload)

    with pytest.raises(WebAuthnError, match="no authentication"):
        finish_authentication_usernameless(request, payload)


@pytest.mark.django_db
def test_finish_usernameless_credential_not_in_db_raises(rf: RequestFactory) -> None:
    request = _request_with_session(rf)
    request.session["webauthn_auth_challenge"] = _b64u(b"ch")
    with pytest.raises(WebAuthnError, match="not registered"):
        finish_authentication_usernameless(
            request,
            {
                "id": _b64u(b"never-registered"),
                "response": {"userHandle": _b64u("anything")},
            },
        )


@pytest.mark.django_db
def test_finish_usernameless_clone_detection(rf: RequestFactory) -> None:
    user = User.objects.create_user(email="cl@example.com", display_name="C")
    WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"cl-cred",
        public_key=b"pk",
        sign_count=10,
    )
    request = _request_with_session(rf)
    request.session["webauthn_auth_challenge"] = _b64u(b"ch")

    fake = MagicMock()
    fake.new_sign_count = 5  # regressed
    with (
        patch(
            "apps.webauthn_auth.services.verify_authentication_response",
            return_value=fake,
        ),
        pytest.raises(WebAuthnError, match="clone"),
    ):
        finish_authentication_usernameless(
            request,
            {
                "id": _b64u(b"cl-cred"),
                "response": {"userHandle": _b64u(str(user.id))},
            },
        )
