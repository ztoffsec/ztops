"""Drop any reference whose scheme is not http or https.

Defense in depth for the stored XSS fix. The form validator already
rejects bad schemes on save, but existing rows may carry a legacy
`javascript:` / `data:` / etc. entry from before the validator landed.
This migration walks every Finding and prunes such entries.

Idempotent. Re-running is a no-op once the data is clean. Backward
migration is a no-op (we never re-introduce the removed entries).
"""

from __future__ import annotations

from urllib.parse import urlparse

from django.db import migrations

_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _safe(entry: object) -> bool:
    if not isinstance(entry, str):
        return False
    value = entry.strip()
    if not value:
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme.lower() in _ALLOWED_SCHEMES and bool(parsed.netloc)


def scrub_references(apps, schema_editor):
    Finding = apps.get_model("findings", "Finding")
    touched = 0
    for f in Finding.objects.all():
        if not isinstance(f.references, list):
            continue
        cleaned = [r for r in f.references if _safe(r)]
        if cleaned != f.references:
            f.references = cleaned
            f.save(update_fields=["references"])
            touched += 1
    if touched:
        # Surface the count in the migrate output so the operator notices.
        print(f"  scrubbed unsafe references on {touched} finding(s)")  # noqa: T201


class Migration(migrations.Migration):
    dependencies = [
        ("findings", "0007_remove_finding_engagement"),
    ]

    operations = [
        migrations.RunPython(scrub_references, migrations.RunPython.noop),
    ]
