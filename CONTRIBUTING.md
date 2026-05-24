# Contributing to ZTOps

Thanks for looking. ZTOps is **source-available but proprietary** (see
[`LICENSE`](./LICENSE)) — the code is public for transparency and security
review, not for open redistribution or reuse.

## Reporting a security vulnerability

**Do not open a public issue for security problems.** Follow the process in
[`SECURITY.md`](./SECURITY.md) — email **security@zerotrustoffsec.com** with
the details. We acknowledge within 72 hours.

## Reporting a non-security bug

Open a GitHub issue using the bug-report template. Include:

- What you did, what you expected, what happened.
- Version / commit, and environment if relevant.
- Logs or screenshots that don't contain sensitive data.

## Pull requests

Because the license does not grant redistribution or derivative-work
rights, we generally do not accept external code contributions. If you have
a fix you'd like to propose:

1. Open an issue first to discuss it.
2. Keep changes focused and small.
3. By opening a PR you agree your contribution may be incorporated under the
   project's proprietary license, with copyright assigned to Zero Trust
   Offsec.

PRs must pass CI (ruff, mypy on `core/security`, bandit, pip-audit, semgrep,
gitleaks, pytest) before review.

## Code of conduct

Be professional and respectful. Harassment, spam, and bad-faith activity get
you blocked. Security research is welcome under the safe-harbor terms in
[`SECURITY.md`](./SECURITY.md).
