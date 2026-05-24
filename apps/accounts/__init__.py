"""Custom User model.

ZTOps users do not have passwords — there is no `password` column on the
User model and `set_password` / `check_password` raise. Authentication
is exclusively via WebAuthn credentials registered in `apps.webauthn_auth`.
Recovery is out-of-band, gated by the superadmin 2-person rule.

Single-instance team app: any active user can access everyday team
features (findings, engagements). Only superadmins reach `/super/`.
"""
