"""Vendor — the party a Finding is reported against."""

from __future__ import annotations

from typing import ClassVar

from django.db import models

from core.security.uuids import uuid7


class Vendor(models.Model):
    """A vendor / project / program a Finding is reported against."""

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    slug = models.SlugField(max_length=80, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    website = models.URLField(max_length=300, blank=True)

    created_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        related_name="vendors_created",
        null=True,
        blank=True,
    )
    created_by_email = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("name",)
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["name"], name="vendor_name_idx"),
        ]

    def __str__(self) -> str:
        return self.name
