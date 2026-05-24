"""Install Postgres triggers that enforce append-only semantics on the audit log.

UPDATE, DELETE, and TRUNCATE all raise an exception from the trigger
function. This works regardless of which DB user is connected — even
postgres / the migration user is blocked. Combined with the future
production role-separation (`ztops_app` granted INSERT only on this
table), it forms the defense-in-depth that hardening requirement #11
prescribes.

`OR REPLACE` on the function is idempotent. The triggers are dropped
before re-creation on the forward direction so a fresh migration of
an existing DB doesn't error.
"""

from __future__ import annotations

from django.db import migrations

_INSTALL_SQL = """
CREATE OR REPLACE FUNCTION ztops_reject_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'audit_auditlogentry is append-only (% rejected)', TG_OP
        USING ERRCODE = 'check_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_no_update ON audit_auditlogentry;
DROP TRIGGER IF EXISTS audit_no_delete ON audit_auditlogentry;
DROP TRIGGER IF EXISTS audit_no_truncate ON audit_auditlogentry;

CREATE TRIGGER audit_no_update
    BEFORE UPDATE ON audit_auditlogentry
    FOR EACH ROW EXECUTE FUNCTION ztops_reject_audit_modification();

CREATE TRIGGER audit_no_delete
    BEFORE DELETE ON audit_auditlogentry
    FOR EACH ROW EXECUTE FUNCTION ztops_reject_audit_modification();

CREATE TRIGGER audit_no_truncate
    BEFORE TRUNCATE ON audit_auditlogentry
    EXECUTE FUNCTION ztops_reject_audit_modification();
"""

_REVERSE_SQL = """
DROP TRIGGER IF EXISTS audit_no_truncate ON audit_auditlogentry;
DROP TRIGGER IF EXISTS audit_no_delete ON audit_auditlogentry;
DROP TRIGGER IF EXISTS audit_no_update ON audit_auditlogentry;
DROP FUNCTION IF EXISTS ztops_reject_audit_modification();
"""


class Migration(migrations.Migration):
    dependencies = (("audit", "0001_initial"),)

    operations = (
        migrations.RunSQL(sql=_INSTALL_SQL, reverse_sql=_REVERSE_SQL),
    )
