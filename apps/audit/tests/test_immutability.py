"""DB-layer immutability: UPDATE / DELETE / TRUNCATE must fail.

Per hardening requirement #11. These tests connect with the same
DB user the test suite normally uses (typically the DB owner) and verify
that the Postgres triggers reject modifications regardless. In
production, role separation gives an additional layer (REVOKE from the
app role) — see deploy/roles.sql.
"""

from __future__ import annotations

import pytest
from django.db import IntegrityError, connection, transaction

from apps.audit.models import AuditAction, AuditLogEntry


@pytest.mark.django_db
def test_insert_is_allowed() -> None:
    entry = AuditLogEntry.objects.create(action=AuditAction.USER_SIGNED_IN)
    assert entry.pk is not None


@pytest.mark.django_db
def test_update_is_rejected_by_trigger() -> None:
    entry = AuditLogEntry.objects.create(action=AuditAction.USER_SIGNED_IN)
    # Wrap in an inner atomic so the failed query doesn't poison the
    # outer test transaction (pytest-django needs that to roll back).
    with transaction.atomic(), pytest.raises(IntegrityError) as exc:
        entry.action = "tampered"
        entry.save(update_fields=["action"])
    assert "append-only" in str(exc.value).lower()


@pytest.mark.django_db
def test_delete_is_rejected_by_trigger() -> None:
    entry = AuditLogEntry.objects.create(action=AuditAction.USER_SIGNED_IN)
    pk = entry.pk
    with transaction.atomic(), pytest.raises(IntegrityError) as exc:
        AuditLogEntry.objects.filter(pk=pk).delete()
    assert "append-only" in str(exc.value).lower()


@pytest.mark.django_db
def test_all_three_triggers_are_installed_on_the_table() -> None:
    # Belt-and-suspenders coverage of TRUNCATE / raw-SQL UPDATE which
    # are awkward to exercise from inside pytest-django's outer test
    # transaction without breaking the cursor cleanup path. Querying
    # pg_trigger directly confirms the migration installed all three.
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT tgname FROM pg_trigger "
            "WHERE tgrelid = 'audit_auditlogentry'::regclass "
            "AND NOT tgisinternal",
        )
        names = {row[0] for row in cursor.fetchall()}
    assert {"audit_no_update", "audit_no_delete", "audit_no_truncate"} <= names
