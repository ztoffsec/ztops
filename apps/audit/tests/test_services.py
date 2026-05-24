"""Tests for the audit() helper."""

from __future__ import annotations

import pytest
from django.test import RequestFactory, override_settings

from apps.accounts.models import User
from apps.audit.models import AuditAction
from apps.audit.services import audit


@pytest.mark.django_db
def test_audit_creates_a_row_with_string_action() -> None:
    entry = audit(action="user_signed_in", target_kind="user", target_id="abc")
    assert entry.action == "user_signed_in"
    assert entry.target_kind == "user"
    assert entry.target_id == "abc"


@pytest.mark.django_db
def test_audit_accepts_textchoices_action() -> None:
    entry = audit(action=AuditAction.USER_SIGNED_IN)
    assert entry.action == AuditAction.USER_SIGNED_IN.value


@pytest.mark.django_db
def test_audit_captures_actor_email_snapshot() -> None:
    user = User.objects.create_user(email="cap@example.com", display_name="C")
    entry = audit(action=AuditAction.USER_SIGNED_IN, actor=user)
    assert entry.actor_user_id == user.id
    assert entry.actor_email == "cap@example.com"


@pytest.mark.django_db
@override_settings(TRUSTED_PROXY_IPS=())
def test_audit_with_request_captures_ip_and_truncated_ua(rf: RequestFactory) -> None:
    long_ua = "Mozilla/" + "x" * 1000
    request = rf.get("/", REMOTE_ADDR="203.0.113.7", HTTP_USER_AGENT=long_ua)
    entry = audit(action=AuditAction.USER_SIGNED_IN, request=request)
    assert entry.actor_ip == "203.0.113.7"
    assert len(entry.actor_user_agent) <= 500
    assert entry.actor_user_agent.startswith("Mozilla/")


@pytest.mark.django_db
def test_audit_without_actor_or_request_still_persists() -> None:
    # System-initiated event (e.g. management command without user context).
    entry = audit(action=AuditAction.USER_SIGNED_IN, target_label="abc")
    assert entry.actor_user is None
    assert entry.actor_email == ""
    assert entry.actor_ip is None
    assert entry.target_label == "abc"


@pytest.mark.django_db
def test_audit_metadata_round_trips_as_json() -> None:
    entry = audit(
        action=AuditAction.USER_SIGNED_IN,
        metadata={"source": "test", "count": 0},
    )
    entry.refresh_from_db()
    assert entry.metadata == {"source": "test", "count": 0}


@pytest.mark.django_db
def test_target_id_coerced_to_string() -> None:
    entry = audit(action=AuditAction.USER_SIGNED_IN, target_kind="user", target_id=42)
    assert entry.target_id == "42"
