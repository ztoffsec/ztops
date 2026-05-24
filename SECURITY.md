# Security Policy

ZTOps is a security platform built by security researchers. We take reports seriously and we will work with reporters in good faith.

## Reporting a vulnerability

Email: **security@zerotrustoffsec.com**

Include:

- Affected component (UI / API / deployment / dependency).
- Reproduction steps. PoC code/script if applicable.
- Impact (what an attacker gains).
- Your preferred disclosure timeline if it differs from the default.

Do **not** open a public GitHub issue for security reports. The issue tracker is for non-security bugs.

Expect an initial acknowledgement within **72 hours**.

## Supported versions

Only the `main` branch is supported. There is no LTS branch. Production deployments should pin to a recent tagged release and upgrade promptly.

| Version       | Supported          |
| ------------- | ------------------ |
| `main` (HEAD) | :white_check_mark: |
| Anything else | :x:                |

## Disclosure timeline

Default: **90 days** from initial acknowledgement to public disclosure, or sooner if a fix ships and is deployed.

We will negotiate longer windows when the underlying issue is in a transitive dependency we do not control, or when a coordinated disclosure with another vendor is in progress.

## Scope

In scope:

- Code in this repository.
- The production deployment at `https://ztops.zerotrustoffsec.com`.

Out of scope (report upstream):

- Third-party dependencies (Django, Postgres, etc.). Report to upstream first; we will track and patch downstream.
- Findings that require operator-side misconfiguration not produced by this repo's defaults.
- Self-XSS, social-engineering, physical attacks, denial-of-service against the public site by traffic flooding.

## Safe harbor

Good-faith research is welcomed. Do not access data that is not yours, do not pivot, do not exfiltrate. If you make a mistake in good faith and report it promptly, we will not pursue.

## Hardening commitments built into this codebase

These are enforced by code, not policy:

- WebAuthn-only authentication. No password path exists.
- Two-person rule on superadmin-destructive actions.
- Append-only audit log enforced at the Postgres role layer.
- Per-object access control (`can_user_view` / `can_user_edit`) on every finding, note, and attachment — no cross-user data exposure via a missing filter.
- Rate limiting on the unauthenticated login / enrollment endpoints.
- CSP, HSTS, COOP, COEP, X-Frame-Options on every response.
- API tokens hashed at rest (argon2id), scoped, rotate-on-use for write scopes, idle-expire at 90 days.
