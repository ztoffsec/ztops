"""Engagement, Asset, ScopeRule — engagement scope of work.

Single-instance app: one shared engagements table for the whole team.
Findings (apps.findings) link to Engagement via FK.
"""

from __future__ import annotations

from typing import ClassVar

from django.db import models

from core.security.uuids import uuid7


class EngagementType(models.TextChoices):
    BUG_BOUNTY = "bug_bounty", "Bug Bounty"
    DISCLOSURE = "disclosure", "Disclosure"
    PENTEST = "pentest", "Pentest"
    RESEARCH = "research", "Research"


class EngagementStatus(models.TextChoices):
    ACTIVE = "active", "Active"
    PAUSED = "paused", "Paused"
    ARCHIVED = "archived", "Archived"


class Engagement(models.Model):
    """A disclosure cycle / bug-bounty project / pentest engagement."""

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    slug = models.SlugField(max_length=80, unique=True)
    name = models.CharField(max_length=200)
    engagement_type = models.CharField(
        max_length=20,
        choices=EngagementType.choices,
        default=EngagementType.DISCLOSURE,
    )
    status = models.CharField(
        max_length=20,
        choices=EngagementStatus.choices,
        default=EngagementStatus.ACTIVE,
    )
    target_vendor = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)
    started_at = models.DateField(null=True, blank=True)
    completed_at = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["status", "-created_at"], name="engagement_status_ts_idx"),
            models.Index(fields=["target_vendor"], name="engagement_vendor_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.slug})"


class AssetKind(models.TextChoices):
    URL = "url", "URL"
    REPO = "repo", "Code Repository"
    BINARY = "binary", "Binary"
    CONTAINER = "container", "Container Image"
    PACKAGE = "package", "Package"
    NETWORK_HOST = "network_host", "Network Host"
    OTHER = "other", "Other"


class Asset(models.Model):
    """A concrete thing under test in an engagement."""

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    engagement = models.ForeignKey(
        Engagement,
        on_delete=models.CASCADE,
        related_name="assets",
    )
    kind = models.CharField(max_length=20, choices=AssetKind.choices)
    identifier = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    in_scope = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("engagement", "kind", "identifier")
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["engagement", "kind"], name="asset_eng_kind_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.kind}:{self.identifier}"


class ScopeRuleType(models.TextChoices):
    IN_SCOPE = "in_scope", "In Scope"
    OUT_OF_SCOPE = "out_of_scope", "Out of Scope"


class ScopeRule(models.Model):
    """A pattern-based in/out-of-scope rule for an engagement.

    Unlike Asset (which names specific concrete targets), a ScopeRule
    captures program-policy text like "*.example.com is in scope" or
    "auth/sso endpoints are out of scope".
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    engagement = models.ForeignKey(
        Engagement,
        on_delete=models.CASCADE,
        related_name="scope_rules",
    )
    rule_type = models.CharField(max_length=20, choices=ScopeRuleType.choices)
    pattern = models.CharField(max_length=500)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("engagement", "rule_type", "pattern")

    def __str__(self) -> str:
        return f"{self.rule_type}: {self.pattern}"
