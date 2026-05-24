"""Bootstrap command: create a superadmin User and issue an enrollment token.

Usage:

    uv run python manage.py register_superadmin_passkey \\
        --email admin@example.com \\
        --display-name "Admin Name"

The command does NOT perform a WebAuthn ceremony itself — that would
require a browser. Instead it:

1. Creates the User (role=superadmin) if missing. Refuses to elevate an
   existing non-superadmin without explicit ``--allow-elevate``.
2. Issues a single-use, 24h-TTL EnrollmentToken bound to that user.
3. Prints the enrollment URL the operator opens in a browser, where the
   actual WebAuthn ceremony runs against the in-page JS.

Subsequent passkey registrations (additional devices for an existing
superadmin, second superadmin for the 2-person rule) reuse the same
command — it's idempotent on the User creation, fresh on the token.
"""

from __future__ import annotations

import argparse
from typing import Any
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import Role
from apps.audit.models import AuditAction
from apps.audit.services import audit
from apps.webauthn_auth.models import EnrollmentToken


class Command(BaseCommand):
    help = "Create a superadmin user (if missing) and print an enrollment URL."

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--email",
            required=True,
            help="Superadmin email. Used as the login identifier.",
        )
        parser.add_argument(
            "--display-name",
            required=True,
            dest="display_name",
            help="Human-readable name shown in UI surfaces.",
        )
        parser.add_argument(
            "--allow-elevate",
            action="store_true",
            help=(
                "Promote an existing regular user to superadmin. "
                "Without this flag the command refuses to change the role."
            ),
        )
        parser.add_argument(
            "--base-url",
            default=None,
            help=(
                "Base URL for the enrollment link. Defaults to the first entry "
                "in WEBAUTHN_RP_ORIGINS."
            ),
        )

    def handle(self, *_args: Any, **options: Any) -> None:
        user_model = get_user_model()
        email: str = options["email"].strip().lower()
        display_name: str = options["display_name"]
        allow_elevate: bool = bool(options.get("allow_elevate"))
        base_url: str | None = options.get("base_url")

        # --- find or create the user, with explicit role handling ----------

        try:
            user = user_model.objects.get(email__iexact=email)
            created = False
        except user_model.DoesNotExist:
            user = user_model.objects.create_user(
                email=email,
                display_name=display_name,
                role=Role.SUPERADMIN,
            )
            created = True

        elevated = False
        if not created:
            if user.role != Role.SUPERADMIN and not allow_elevate:
                msg = (
                    f"User {email!r} exists with role={user.role!r}; refusing to "
                    "promote without --allow-elevate."
                )
                raise CommandError(msg)
            if user.role != Role.SUPERADMIN and allow_elevate:
                user.role = Role.SUPERADMIN
                user.save(update_fields=["role"])
                elevated = True

        if elevated:
            audit(
                action=AuditAction.SUPERADMIN_ROLE_GRANTED,
                target_kind="user",
                target_id=str(user.id),
                target_label=user.email,
                metadata={"command": "register_superadmin_passkey", "elevated": True},
            )

        # --- issue an enrollment token and print the URL -------------------

        _, raw_token = EnrollmentToken.issue(user)
        audit(
            action=AuditAction.SUPERADMIN_TOKEN_ISSUED,
            target_kind="user",
            target_id=str(user.id),
            target_label=user.email,
            metadata={
                "command": "register_superadmin_passkey",
                "created_user": created,
            },
        )

        url_base = base_url or self._default_base_url()
        enroll_url = f"{url_base.rstrip('/')}/webauthn/enroll/{raw_token}/"

        verb = "Created" if created else "Found"
        self.stdout.write(self.style.SUCCESS(f"{verb} superadmin user: {email}"))
        self.stdout.write("Open this URL in a browser to register a passkey:")
        self.stdout.write(self.style.NOTICE(f"  {enroll_url}"))
        self.stdout.write("(Token is single-use and expires in 24h.)")

    @staticmethod
    def _default_base_url() -> str:
        origins: tuple[str, ...] = tuple(getattr(settings, "WEBAUTHN_RP_ORIGINS", ()))
        if not origins:
            return "http://localhost:8000"
        first = origins[0]
        # Strip any path/query — we only want scheme+host[:port].
        parts = urlsplit(first)
        netloc = parts.netloc or parts.path  # tolerate "localhost:8000" w/o scheme
        scheme = parts.scheme or "http"
        return f"{scheme}://{netloc}"
