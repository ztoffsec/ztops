"""Basic model behavior for AuditLogEntry."""

from __future__ import annotations

import uuid

import pytest

from apps.accounts.models import User
from apps.audit.models import AuditAction, AuditLogEntry


@pytest.mark.django_db
def test_entry_pk_is_uuidv7() -> None:
    entry = AuditLogEntry.objects.create(action=AuditAction.USER_SIGNED_IN)
    assert isinstance(entry.id, uuid.UUID)
    assert (entry.id.int >> 76) & 0xF == 7


@pytest.mark.django_db
def test_entry_persists_actor_snapshot() -> None:
    user = User.objects.create_user(email="actor@example.com", display_name="A")
    entry = AuditLogEntry.objects.create(
        action=AuditAction.USER_SIGNED_IN,
        actor_user=user,
        actor_email=user.email,
    )
    assert entry.actor_user_id == user.id
    assert entry.actor_email == "actor@example.com"


@pytest.mark.django_db
def test_entry_survives_actor_deletion() -> None:
    # `actor_user` is db_constraint=False on_delete=DO_NOTHING so the
    # User deletion does NOT touch this row (UPDATE would be rejected
    # by the immutability trigger). The actor_email snapshot is what
    # forensic readers rely on.
    user = User.objects.create_user(email="del@example.com", display_name="D")
    entry = AuditLogEntry.objects.create(
        action=AuditAction.USER_SIGNED_IN,
        actor_user=user,
        actor_email=user.email,
    )
    user.delete()

    entry.refresh_from_db()
    assert entry.actor_email == "del@example.com"  # snapshot preserved


@pytest.mark.django_db
def test_entry_str_includes_action_and_actor() -> None:
    entry = AuditLogEntry.objects.create(
        action=AuditAction.USER_SIGNED_IN,
        actor_email="x@example.com",
    )
    s = str(entry)
    assert "user_signed_in" in s
    assert "x@example.com" in s


@pytest.mark.django_db
def test_entry_with_no_actor_records_as_system() -> None:
    entry = AuditLogEntry.objects.create(action=AuditAction.USER_SIGNED_IN)
    assert "system" in str(entry)


@pytest.mark.django_db
def test_default_ordering_is_most_recent_first() -> None:
    a = AuditLogEntry.objects.create(action=AuditAction.USER_SIGNED_IN)
    b = AuditLogEntry.objects.create(action=AuditAction.USER_SIGNED_OUT)
    rows = list(AuditLogEntry.objects.all()[:2])
    # Newest first
    assert rows[0].id == b.id
    assert rows[1].id == a.id
