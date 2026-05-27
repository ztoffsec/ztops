"""Reassign legacy/manual finding internal_ids to the canonical
``ZT-{year}-{7 digits}`` format.

Internal ids are system-assigned now (the form no longer exposes the field
and the model marks it ``editable=False``). This backfills findings created
before that change. **Safe to run on the live server:**

- default is a **DRY RUN** — prints the planned ``old -> new`` mapping and
  changes nothing;
- pass ``--apply`` to commit, inside a single transaction;
- **idempotent** — findings already in ``ZT-YYYY-NNNNNNN`` form are skipped,
  so re-running is a no-op.

``internal_id`` is a display label only (findings are addressed by their
UUID ``id``), so reassigning it does not break URLs, sessions, attachments,
or the audit log (which snapshots the label at write time).

Usage:
    uv run python manage.py reassign_internal_ids            # dry run
    uv run python manage.py reassign_internal_ids --apply    # commit
"""

from __future__ import annotations

import re
import secrets
from typing import TYPE_CHECKING

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.findings.models import Finding

if TYPE_CHECKING:
    import argparse

_CANONICAL = re.compile(r"^ZT-\d{4}-\d{7}$")


def _allocate(year: int, used: set[str]) -> str:
    """Pick a ``ZT-{year}-{7 digits}`` id not present in ``used``."""
    for _ in range(100):
        candidate = f"ZT-{year}-{secrets.randbelow(10_000_000):07d}"
        if candidate not in used:
            return candidate
    msg = f"Could not allocate a unique internal_id for year {year} after 100 tries."
    raise CommandError(msg)


class Command(BaseCommand):
    help = "Reassign finding internal_ids to the canonical ZT-{year}-{7 digits} format."

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Commit the changes. Without this flag the command is a dry run.",
        )

    def handle(self, *args: object, **options: object) -> None:
        apply = bool(options["apply"])

        # Seed the in-use set with ids we will NOT touch (already canonical), so
        # newly generated ids collide neither with them nor with each other.
        used: set[str] = set(
            Finding.objects.filter(internal_id__regex=r"^ZT-\d{4}-\d{7}$").values_list(
                "internal_id",
                flat=True,
            ),
        )

        to_change: list[tuple[str, str, str]] = []  # (pk, old, new)
        for finding in Finding.objects.all().order_by("created_at"):
            current = finding.internal_id or ""
            if _CANONICAL.match(current):
                continue
            year = (finding.created_at or timezone.now()).year
            new_id = _allocate(year, used)
            used.add(new_id)
            to_change.append((str(finding.pk), current or "(blank)", new_id))

        if not to_change:
            self.stdout.write(
                self.style.SUCCESS("All findings already use the canonical format. Nothing to do."),
            )
            return

        for _pk, old, new in to_change:
            self.stdout.write(f"  {old:>20}  ->  {new}")

        if not apply:
            self.stdout.write(
                self.style.WARNING(
                    f"DRY RUN: {len(to_change)} finding(s) would be reassigned. "
                    "Re-run with --apply to commit.",
                ),
            )
            return

        with transaction.atomic():
            for pk, _old, new in to_change:
                # .update() bypasses save() — surgical field change, no severity
                # re-derivation and no updated_at bump for a maintenance backfill.
                Finding.objects.filter(pk=pk).update(internal_id=new)

        self.stdout.write(
            self.style.SUCCESS(f"Applied: {len(to_change)} internal_id(s) reassigned."),
        )
