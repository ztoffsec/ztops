"""Client-facing engagement reports.

A Report is the deliverable a researcher builds for a client (vendor): the
engagement metadata, an executive summary, the included findings, a
conclusion, and ordered annexes. It replaces the old Engagement model — the
engagement scope/dates/people now live here.

Findings included in a report are the same `findings.Finding` rows (so they
count once, globally) and are vendor-scoped to the report's client to avoid
cross-client leakage.
"""

from __future__ import annotations

from typing import ClassVar

from django.db import models

from core.security.uuids import uuid7


class ScopeCategory(models.Model):
    """Engagement scope/type (Web App, Kernel Exploitation, …).

    Seeded with defaults; editable by a superadmin via the UI in a later
    phase. The selected categories drive how the report template is built.
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True)
    order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("order", "name")
        verbose_name_plural = "scope categories"

    def __str__(self) -> str:
        return self.name


class ReportStatus(models.TextChoices):
    """Review lifecycle (mirrors the finding review gate).

    A report is built in DRAFT, submitted for review (IN_REVIEW), then
    APPROVED or REJECTED by a reviewer. Only APPROVED reports are publicly
    visible and exportable; everything else is involved-parties only.
    """

    DRAFT = "draft", "Draft"
    IN_REVIEW = "in_review", "In Review"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected"


class Report(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    name = models.CharField(max_length=300)
    client = models.ForeignKey(
        "vendors.Vendor",
        on_delete=models.PROTECT,
        related_name="reports",
    )
    researchers = models.ManyToManyField(
        "accounts.User",
        related_name="reports_as_researcher",
        blank=True,
    )
    engagement_manager = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        related_name="reports_as_manager",
        null=True,
        blank=True,
    )
    scope_categories = models.ManyToManyField(
        ScopeCategory,
        related_name="reports",
        blank=True,
    )
    findings = models.ManyToManyField(
        "findings.Finding",
        related_name="reports",
        blank=True,
    )

    engagement_start = models.DateField(null=True, blank=True)
    engagement_end = models.DateField(null=True, blank=True)
    classification = models.CharField(max_length=40, default="CONFIDENTIAL")
    status = models.CharField(
        max_length=20,
        choices=ReportStatus.choices,
        default=ReportStatus.DRAFT,
        db_index=True,
    )

    executive_summary = models.TextField(blank=True)
    conclusion = models.TextField(blank=True)

    reviewed_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        related_name="reports_reviewed",
        null=True,
        blank=True,
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)

    created_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        related_name="reports_created",
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)

    def __str__(self) -> str:
        return self.name

    @property
    def is_approved(self) -> bool:
        return self.status == ReportStatus.APPROVED.value

    def _is_involved(self, user: object) -> bool:
        """Directly involved parties: creator, engagement manager, researchers."""
        if user.pk in {self.created_by_id, self.engagement_manager_id}:
            return True
        return self.researchers.filter(pk=user.pk).exists()

    def can_user_edit(self, user: object) -> bool:
        """Involved parties (creator / researchers / engagement manager) and
        superadmins may edit a report."""
        if not getattr(user, "is_authenticated", False):
            return False
        if getattr(user, "is_superadmin", False):
            return True
        return self._is_involved(user)

    def can_user_view(self, user: object) -> bool:
        """Approved reports are visible to anyone authenticated. Non-approved
        reports (draft / in_review / rejected) are visible only to the involved
        parties and to review authorities (so they can review them)."""
        if not getattr(user, "is_authenticated", False):
            return False
        if self.is_approved:
            return True
        if getattr(user, "is_review_authority", False):
            return True
        return self._is_involved(user)

    def can_user_export(self, user: object) -> bool:
        """Export is allowed only once APPROVED, to anyone who can view it."""
        return self.is_approved and self.can_user_view(user)

    def can_user_review(self, user: object) -> bool:
        """Reviewers + superadmins move the review state. A reviewer cannot
        approve a report they created (2-person flavour); superadmin override."""
        if not getattr(user, "is_authenticated", False):
            return False
        if not getattr(user, "is_review_authority", False):
            return False
        return self.created_by_id != user.pk or getattr(user, "is_superadmin", False)

    def can_user_view_review_notes(self, user: object) -> bool:
        """Private review thread: involved parties + reviewers/superadmins."""
        if not getattr(user, "is_authenticated", False):
            return False
        if getattr(user, "is_review_authority", False):
            return True
        return self._is_involved(user)


class PointOfContactRole(models.TextChoices):
    SECURITY = "security", "Security"
    MANAGER = "manager", "Manager"
    ADMINISTRATION = "administration", "Administration"
    TECHNICAL = "technical", "Technical"
    OTHER = "other", "Other"


class PointOfContact(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    report = models.ForeignKey(
        Report,
        on_delete=models.CASCADE,
        related_name="contacts",
    )
    name = models.CharField(max_length=200)
    role = models.CharField(
        max_length=20,
        choices=PointOfContactRole.choices,
        default=PointOfContactRole.SECURITY,
    )
    email = models.EmailField(blank=True)
    phone = models.CharField(max_length=40, blank=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("name",)

    def __str__(self) -> str:
        return f"{self.name} ({self.get_role_display()})"


class Annex(models.Model):
    """Appendix section, presented in order as Annex A, B, C…

    Defined here; the builder UI to add/reorder annexes arrives in a later
    sub-phase.
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    report = models.ForeignKey(
        Report,
        on_delete=models.CASCADE,
        related_name="annexes",
    )
    title = models.CharField(max_length=200)
    body = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("order",)

    def __str__(self) -> str:
        return self.title


class ReportReviewNote(models.Model):
    """Private review-thread note on a report — visible to involved parties +
    reviewers + superadmins. Distinct from the report content."""

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    report = models.ForeignKey(
        Report,
        on_delete=models.CASCADE,
        related_name="review_notes",
    )
    author = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        related_name="report_review_notes",
        null=True,
        blank=True,
    )
    author_email = models.CharField(max_length=255, blank=True)
    author_is_reviewer = models.BooleanField(default=False)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("created_at",)

    def __str__(self) -> str:
        return f"ReviewNote on {self.report_id} by {self.author_email or 'unknown'}"
