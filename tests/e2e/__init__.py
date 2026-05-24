"""End-to-end tests that exercise the full WebAuthn ceremony round-trip.

Unlike `apps/webauthn_auth/tests/test_services.py`, these tests do NOT
mock `verify_registration_response` / `verify_authentication_response`.
Instead, a tiny in-process virtual authenticator (`_virtual_authenticator.py`)
produces cryptographically valid registration + authentication payloads
that the lib's verifiers accept on the round-trip.

If these tests pass, we know:
- The ceremony JSON shape we emit/expect is wire-compatible with the
  `webauthn` library.
- The session-state machine survives a multi-request flow.
- The session created by a successful sign-in is recognized by
  `@login_required` views on the next request.

These are the closest thing in Phase 1 to a "would a browser succeed?"
test without spinning up a browser.
"""
