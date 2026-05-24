# ZTOps

**Zero Trust Offsec** — collaborative offensive-security reporting and disclosure-tracking platform.

Single-instance, internal-team app. WebAuthn-only auth. Append-only audit. Self-hosted.

Production: <https://ztops.zerotrustoffsec.com>

## What this is

A Plextrac-style tool for tracking vulnerability research engagements — findings, advisory drafts, disclosure status across channels (HackerOne, GHSA, MITRE, vendor-direct, Patchstack, etc.), per-engagement collaboration, immutable audit history.

## Quickstart (dev)

Prerequisites: `uv`, Docker + Docker Compose.

```bash
# 1. dependencies
uv sync --all-groups

# 2. local env
cp .env.example .env          # edit; .env is gitignored
$EDITOR .env

# 3. data services
docker compose -f docker-compose.dev.yml up -d

# 4. database
uv run manage.py migrate
uv run manage.py register_superadmin_passkey   # hands-on WebAuthn ceremony

# 5. dev server
uv run manage.py runserver 127.0.0.1:8000
```

Production deployment (Caddy + systemd + role-separated Postgres + Celery + backups) is documented in the operator's private runbook.

## Tooling

| Tool                | Purpose                                         |
| ------------------- | ----------------------------------------------- |
| `uv`                | Dependency management, lockfile, virtualenv     |
| `ruff`              | Lint + format                                   |
| `mypy --strict`     | Type-checking on `core/security/`               |
| `bandit`            | Static security analysis                        |
| `pip-audit`         | Dependency CVE scanning                         |
| `semgrep`           | Django / Python / security-audit rule packs     |
| `gitleaks`          | Secret detection (pre-commit + CI)              |
| `pre-commit`        | Run all of the above on staged changes          |
| `pytest`            | Test runner                                     |

Install pre-commit hooks once after clone:

```bash
uv run pre-commit install
```

## Security

See [`SECURITY.md`](./SECURITY.md) for the disclosure policy and how to report a vulnerability.

## License

Proprietary — all rights reserved. Not open source. Contact `jrivas@zerotrustoffsec.com` for licensing inquiries.
