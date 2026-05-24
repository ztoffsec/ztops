"""WebAuthn ceremony — registration + authentication of passkeys.

This app owns the WebAuthn protocol surface: per-credential records, the
ceremony challenge/verify flow, the enrollment-token grant used for
initial superadmin bootstrap and (later) invited collaborator onboarding,
and the management command that produces an enrollment URL.

There are no passwords here — by design, by spec, by hard-requirement #1.
"""
