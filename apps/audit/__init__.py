"""Append-only audit log for privileged + security-relevant actions.

This app's table is the forensic-grade ledger the project spec
(hardening requirement #11) prescribes: immutable in the database via
Postgres triggers that reject UPDATE / DELETE / TRUNCATE on the audit
table. Application code can only INSERT.

Production deploys layer Postgres role separation on top
(`ztops_audit_reader` for forensic SELECT, `ztops_app` with INSERT-only
on the audit table) — handled in `deploy/roles.sql` at Phase 5. The
trigger here defends even when those roles aren't in place yet (dev,
test, migration-time).

Audit emission is via the `audit()` helper in `services.py`. Allowlist
discipline (hardening requirement #12 — no finding bodies, no tokens,
no attachments) is enforced by the call site, not by the helper.
"""
