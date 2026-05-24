"""Tests for WebAuthnCredential and EnrollmentToken."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.db import IntegrityError
from django.utils import timezone

from apps.accounts.models import Role, User
from apps.webauthn_auth.models import EnrollmentToken, WebAuthnCredential
from core.security.crypto import hash_token


@pytest.mark.django_db
def test_webauthn_credential_stores_binary_blobs() -> None:
    user = User.objects.create_user(email="cred@example.com", display_name="C")
    cred = WebAuthnCredential.objects.create(
        user=user,
        credential_id=b"\x00\x01\x02\x03",
        public_key=b"\xaa\xbb\xcc",
        sign_count=0,
    )
    assert bytes(cred.credential_id) == b"\x00\x01\x02\x03"
    assert bytes(cred.public_key) == b"\xaa\xbb\xcc"


@pytest.mark.django_db
def test_credential_id_is_unique_across_users() -> None:
    user_a = User.objects.create_user(email="a@example.com", display_name="A")
    user_b = User.objects.create_user(email="b@example.com", display_name="B")
    WebAuthnCredential.objects.create(user=user_a, credential_id=b"shared", public_key=b"x")
    with pytest.raises(IntegrityError):
        WebAuthnCredential.objects.create(user=user_b, credential_id=b"shared", public_key=b"y")


@pytest.mark.django_db
def test_user_can_have_multiple_credentials() -> None:
    user = User.objects.create_user(email="multi@example.com", display_name="M")
    WebAuthnCredential.objects.create(user=user, credential_id=b"k1", public_key=b"p1")
    WebAuthnCredential.objects.create(user=user, credential_id=b"k2", public_key=b"p2")
    WebAuthnCredential.objects.create(user=user, credential_id=b"k3", public_key=b"p3")
    assert user.credentials.count() == 3


# ---- EnrollmentToken ----


@pytest.mark.django_db
def test_enrollment_token_issue_returns_raw_value() -> None:
    user = User.objects.create_user(email="e@example.com", display_name="E")
    token, raw = EnrollmentToken.issue(user)
    assert raw.startswith("zto_enr_")
    assert token.token_prefix == raw[:16]
    # The hash on the row must not equal the raw token.
    assert token.token_hash != raw
    assert token.token_hash.startswith("$argon2id$")


@pytest.mark.django_db
def test_enrollment_token_consume_marks_used_and_returns_row() -> None:
    user = User.objects.create_user(email="c@example.com", display_name="C")
    _, raw = EnrollmentToken.issue(user)

    consumed = EnrollmentToken.consume(raw)
    assert consumed is not None
    assert consumed.used_at is not None
    assert consumed.user_id == user.id


@pytest.mark.django_db
def test_enrollment_token_consume_is_single_use() -> None:
    user = User.objects.create_user(email="s@example.com", display_name="S")
    _, raw = EnrollmentToken.issue(user)

    first = EnrollmentToken.consume(raw)
    second = EnrollmentToken.consume(raw)
    assert first is not None
    assert second is None


@pytest.mark.django_db
def test_enrollment_token_consume_rejects_expired() -> None:
    user = User.objects.create_user(email="exp@example.com", display_name="X")
    token, raw = EnrollmentToken.issue(user)
    # Force-expire.
    token.expires_at = timezone.now() - timedelta(seconds=1)
    token.save(update_fields=["expires_at"])

    assert EnrollmentToken.consume(raw) is None


@pytest.mark.django_db
def test_enrollment_token_consume_rejects_garbage() -> None:
    assert EnrollmentToken.consume("not-a-real-token") is None
    assert EnrollmentToken.consume("zto_enr_thisdoesntexist") is None


@pytest.mark.django_db
def test_enrollment_token_consume_rejects_wrong_secret_same_prefix() -> None:
    # Issue one token; replace its hash with the hash of a different
    # token so the prefix still matches but the secret does not.
    user = User.objects.create_user(email="prefix@example.com", display_name="P")
    real_raw = "zto_enr_AAAAAAAAAA-secretAAA"
    fake_raw = "zto_enr_AAAAAAAAAA-secretBBB"
    EnrollmentToken.objects.create(
        user=user,
        token_prefix=real_raw[:16],
        token_hash=hash_token(real_raw),
        expires_at=timezone.now() + timedelta(hours=1),
    )

    assert EnrollmentToken.consume(fake_raw) is None
    # And the real token still works.
    assert EnrollmentToken.consume(real_raw) is not None


@pytest.mark.django_db
def test_enrollment_token_bound_to_user_role() -> None:
    user = User.objects.create_user(
        email="role@example.com",
        display_name="Role",
        role=Role.SUPERADMIN,
    )
    token, _ = EnrollmentToken.issue(user)
    assert token.user.is_superadmin is True
