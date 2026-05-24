"""Signals wired to Finding lifecycle events."""

from __future__ import annotations

from typing import Any

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .models import Finding


@receiver(post_save, sender=Finding)
def ensure_reporter_assigned(
    sender: type[Finding],  # noqa: ARG001
    instance: Finding,
    created: bool,
    **kwargs: Any,
) -> None:
    """When a Finding is created, ensure reported_by is in assigned_researchers.

    Only fires on creation so updates that legitimately remove the
    reporter from the assignment list (rare, but possible if ownership
    is being transferred) are not stomped on.
    """
    if not created or instance.reported_by_id is None:
        return
    instance.assigned_researchers.add(instance.reported_by_id)


@receiver(post_delete, sender=Finding)
def purge_attachment_bucket(
    sender: type[Finding],  # noqa: ARG001
    instance: Finding,
    **kwargs: Any,
) -> None:
    """Drop on-disk artifact files when their Finding is deleted.

    The Attachment rows themselves cascade-delete via the FK; this signal
    cleans up the bytes that the cascade leaves on disk.
    """
    from apps.attachments.storage import purge_finding_bucket  # noqa: PLC0415

    purge_finding_bucket(str(instance.id))
