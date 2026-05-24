"""Attachment metadata.

Phase 3 stores only the metadata — no file bytes pass through here yet.
Storage path is opaque; the signed-URL serving endpoint and ClamAV
scanner pipeline land in a later milestone of this same app.
"""

from __future__ import annotations

from typing import ClassVar

from django.db import models

from core.security.uuids import uuid7


class ScanStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    CLEAN = "clean", "Clean"
    INFECTED = "infected", "Infected"
    ERROR = "error", "Scan Error"
    SKIPPED = "skipped", "Skipped"


class Attachment(models.Model):
    """A file attached to a Finding — metadata-only in Phase 3."""

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    finding = models.ForeignKey(
        "findings.Finding",
        on_delete=models.CASCADE,
        related_name="attachments",
    )

    filename = models.CharField(max_length=255)
    content_type = models.CharField(max_length=120)
    size_bytes = models.PositiveBigIntegerField(default=0)
    sha256_hash = models.CharField(max_length=64, db_index=True)
    # Storage path is opaque — the signed-URL endpoint serves the bytes.
    # NEVER under Django's MEDIA_ROOT (hardening requirement #8).
    storage_path = models.CharField(max_length=500, blank=True)

    uploaded_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        related_name="uploaded_attachments",
        null=True,
        blank=True,
    )
    uploaded_by_email = models.CharField(max_length=255, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    scan_status = models.CharField(
        max_length=20,
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        db_index=True,
    )
    scan_completed_at = models.DateTimeField(null=True, blank=True)
    scan_notes = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("-uploaded_at",)
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["finding", "-uploaded_at"], name="attachment_finding_ts_idx"),
            models.Index(fields=["scan_status"], name="attachment_scan_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.filename} ({self.size_bytes}B)"
