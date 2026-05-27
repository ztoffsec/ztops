"""Finding and FindingNote — the disclosure-tracking core.

Single-instance app: one shared set of findings for the whole team.
Finding captures the columns a vulnerability tracker needs: internal_id,
vendor, channel, title, CVE id, CVSS score+vector, status. FindingNote is
append-only journal entries on the finding.

The `severity` field is derived from CVSS 3.1 (or 4.0 if present) on
save() — callers never set it directly. Bands per the standard:

    0.0      = None
    0.1-3.9  = Low
    4.0-6.9  = Medium
    7.0-8.9  = High
    9.0-10.0 = Critical
"""

from __future__ import annotations

import secrets
from decimal import Decimal
from typing import ClassVar

from django.db import models
from django.utils import timezone

from core.security.uuids import uuid7


class Channel(models.TextChoices):
    """Where a vulnerability was (or will be) reported.

    `channel_program` carries the specific program name (e.g. "acme",
    "globex", "initech") where Channel only carries the platform.
    """

    HACKERONE = "hackerone", "HackerOne"
    GHSA = "ghsa", "GitHub Security Advisory"
    MITRE = "mitre", "MITRE / CNA"
    PATCHSTACK = "patchstack", "Patchstack"
    ASF_SECURITY = "asf_security", "Apache Security"
    EMAIL_VENDOR = "email_vendor", "Vendor Email"
    OTHER = "other", "Other"


class Status(models.TextChoices):
    """Disclosure-lifecycle status, with underscored codes.

    Labels are kept short so the pills don't overflow table cells or
    get cut off on mobile. Long-form names live in the documentation.
    """

    DRAFTED = "drafted", "Drafted"
    IN_TRIAGE = "in_triage", "In Triage"
    VENDOR_ACK = "vendor_ack", "Vendor Ack"
    PATCHED = "patched", "Patched"
    AWAITING_CVE = "awaiting_cve", "Awaiting CVE"
    DUPLICATE = "duplicate", "Duplicate"
    REJECTED = "rejected", "Rejected"
    WONTFIX = "wontfix", "Won't Fix"
    WAD = "wad", "WAD"


class Severity(models.TextChoices):
    """CVSS qualitative band. Derived from score; do not set by hand."""

    NONE = "none", "None"
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


class ReviewState(models.TextChoices):
    """Quality-gate state machine for new findings.

    Reports filed by a non-superadmin reporter start in `PENDING` and
    must be vetted by a reviewer before they're visible to the team at
    large. Superadmin reports are born `APPROVED` (they are reviewers
    by definition).

    Visibility rules (enforced in views.Finding.can_user_view_finding):
    - PENDING / UNDER_REVIEW / REJECTED → reporter, reviewers,
      superadmins only.
    - APPROVED → everyone (and rendered with the "Approved" pill).
    """

    PENDING = "pending", "Pending"
    UNDER_REVIEW = "under_review", "Reviewing"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected"


_SEVERITY_BANDS: tuple[tuple[Decimal, str], ...] = (
    (Decimal("9.0"), Severity.CRITICAL.value),
    (Decimal("7.0"), Severity.HIGH.value),
    (Decimal("4.0"), Severity.MEDIUM.value),
    (Decimal("0.1"), Severity.LOW.value),
)


def severity_from_score(score: Decimal | None) -> str:
    """Return the qualitative band for a CVSS score (or NONE if missing/0)."""
    if score is None or score <= Decimal("0.0"):
        return Severity.NONE.value
    for floor, band in _SEVERITY_BANDS:
        if score >= floor:
            return band
    return Severity.NONE.value


class Finding(models.Model):
    """A vulnerability report tracked from drafting through disclosure.

    `internal_id` is the human-facing tracker identifier (e.g. "ACME-001");
    unique across the table.
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    # System-assigned (ZT-{year}-{7 digits}); never set by hand. editable=False
    # keeps it out of every ModelForm and the admin.
    internal_id = models.CharField(max_length=40, editable=False)
    title = models.CharField(max_length=300)
    vendor = models.ForeignKey(
        "vendors.Vendor",
        on_delete=models.PROTECT,
        related_name="findings",
    )
    channel = models.CharField(max_length=20, choices=Channel.choices)
    channel_program = models.CharField(max_length=100, blank=True)
    cve_id = models.CharField(max_length=30, blank=True)

    # Owner — the user who created this finding. They can edit + manage
    # the collaborator list. Required on create.
    reported_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.PROTECT,
        related_name="findings_reported",
    )
    reported_by_email = models.CharField(max_length=255, blank=True)

    # Collaboration set — researchers (including the reporter) who can
    # edit the finding and add notes. The reporter is added automatically
    # on save(); additional members can only be added by reporter or
    # superadmin.
    assigned_researchers = models.ManyToManyField(
        "accounts.User",
        related_name="findings_assigned",
        blank=True,
    )

    cvss_31_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    cvss_31_vector = models.CharField(max_length=200, blank=True)
    cvss_4_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    cvss_4_vector = models.CharField(max_length=200, blank=True)
    severity = models.CharField(
        max_length=10,
        choices=Severity.choices,
        default=Severity.NONE,
        editable=False,
        db_index=True,
    )

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFTED,
        db_index=True,
    )

    # Quality gate. Findings filed by a non-superadmin reporter start
    # PENDING and need a reviewer to move them to APPROVED before they
    # surface in the global feed / dashboard. The view layer fills
    # this in based on the reporter's role at finding_new() time;
    # default APPROVED keeps the column tractable for legacy rows that
    # predate this feature (set in the data migration).
    review_state = models.CharField(
        max_length=20,
        choices=ReviewState.choices,
        default=ReviewState.APPROVED,
        db_index=True,
    )
    reviewed_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        related_name="findings_reviewed",
        null=True,
        blank=True,
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)

    engagement = models.ForeignKey(
        "engagements.Engagement",
        on_delete=models.PROTECT,
        related_name="findings",
        null=True,
        blank=True,
    )

    # Structured finding body. narrative = what/impact, poc = reproduction,
    # remediation = fix guidance. All markdown, rendered via render_markdown.
    narrative = models.TextField(blank=True)
    poc = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    # Hosts/URLs/assets this finding affects. Vendor-scoped (see AffectedHost);
    # choices are restricted to the finding's vendor in the form/view.
    affected_hosts = models.ManyToManyField(
        "AffectedHost",
        related_name="findings",
        blank=True,
    )
    cwe_ids = models.JSONField(default=list, blank=True)
    references = models.JSONField(default=list, blank=True)

    disclosed_at = models.DateField(null=True, blank=True)
    acknowledged_at = models.DateField(null=True, blank=True)
    patched_at = models.DateField(null=True, blank=True)
    published_at = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=["internal_id"], name="finding_internal_id_unique"),
        ]
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["status", "-created_at"], name="finding_status_ts_idx"),
            models.Index(fields=["vendor"], name="finding_vendor_idx"),
            models.Index(fields=["channel"], name="finding_channel_idx"),
            models.Index(fields=["severity", "-created_at"], name="finding_sev_ts_idx"),
            models.Index(fields=["reported_by"], name="finding_reporter_idx"),
            models.Index(fields=["review_state", "-created_at"], name="finding_review_ts_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.internal_id}: {self.title}"

    def save(self, *args: object, **kwargs: object) -> None:
        # Auto-assign the human-facing id on first save when none was set.
        # Findings are no longer numbered by hand; the form omits the field.
        if not self.internal_id:
            self.internal_id = self.generate_internal_id()
        # Derive severity from the highest CVSS score present. When both
        # 3.1 and 4.0 are set they often disagree (different formulas for
        # the same vuln); user-facing severity should reflect the worst
        # measured impact, not arbitrarily prefer one standard.
        scores = [s for s in (self.cvss_31_score, self.cvss_4_score) if s is not None]
        score = max(scores) if scores else None
        self.severity = severity_from_score(score)
        # Snapshot reporter email at create time so the row remains
        # readable even if the User row is later deleted.
        if self.reported_by_id and not self.reported_by_email:
            self.reported_by_email = self.reported_by.email
        super().save(*args, **kwargs)

    @staticmethod
    def generate_internal_id() -> str:
        """Allocate a unique human-facing id of the form ``ZT-{year}-{7 digits}``.

        Retries on the rare random collision against the unique constraint.
        """
        year = timezone.now().year
        for _ in range(50):
            candidate = f"ZT-{year}-{secrets.randbelow(10_000_000):07d}"
            if not Finding.objects.filter(internal_id=candidate).exists():
                return candidate
        msg = "Could not allocate a unique internal_id after 50 attempts."
        raise RuntimeError(msg)

    def can_user_edit(self, user: object) -> bool:
        """Return True if `user` can edit this finding's content or add notes.

        Permission rule: assigned researchers + superadmins. The reporter
        is always in `assigned_researchers` (added in save()).
        """
        if not getattr(user, "is_authenticated", False):
            return False
        if getattr(user, "is_superadmin", False):
            return True
        return self.assigned_researchers.filter(pk=user.pk).exists()

    def can_user_manage_collaborators(self, user: object) -> bool:
        """Return True if `user` can add/remove assigned_researchers.

        Permission rule: reporter (owner) + superadmins only. Assigned
        collaborators who are NOT the reporter cannot invite others.
        """
        if not getattr(user, "is_authenticated", False):
            return False
        if getattr(user, "is_superadmin", False):
            return True
        return self.reported_by_id == user.pk

    @property
    def is_publicly_visible(self) -> bool:
        """Approved findings show up everywhere; everything else is
        review-thread-only."""
        return self.review_state == ReviewState.APPROVED.value

    def can_user_view(self, user: object) -> bool:
        """Visibility gate that wraps the review state.

        Approved findings are visible to anyone authenticated. Findings
        in any non-approved state (pending, under_review, rejected) are
        only visible to the reporter, reviewers, and superadmins."""
        if not getattr(user, "is_authenticated", False):
            return False
        if self.is_publicly_visible:
            return True
        if getattr(user, "is_review_authority", False):
            return True
        return self.reported_by_id == user.pk

    def can_user_review(self, user: object) -> bool:
        """Reviewers + superadmins can transition review_state and post
        private review notes. The reporter cannot review their own."""
        if not getattr(user, "is_authenticated", False):
            return False
        if not getattr(user, "is_review_authority", False):
            return False
        # A reviewer cannot self-approve their own report (mirrors the
        # 2-person rule pattern). Superadmin override stays for emergency
        # use — they could revoke an abusive reviewer's submissions if
        # the reviewer themselves is also the reporter.
        return self.reported_by_id != user.pk or getattr(user, "is_superadmin", False)

    def can_user_view_private_notes(self, user: object) -> bool:
        """Private review notes: reporter + reviewers + superadmins.
        Other assigned collaborators do NOT see them."""
        if not getattr(user, "is_authenticated", False):
            return False
        if getattr(user, "is_review_authority", False):
            return True
        return self.reported_by_id == user.pk


class FindingNote(models.Model):
    """Append-only journal entry attached to a Finding.

    Edits are not supported through the ORM contract; the audit log
    captures who said what when. UPDATE is not blocked at the DB layer
    here (unlike audit_auditlogentry) — the discipline is application-
    level for now and can be hardened with a trigger if it becomes a
    forensic requirement.
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    finding = models.ForeignKey(
        Finding,
        on_delete=models.CASCADE,
        related_name="notes",
    )
    author = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        related_name="finding_notes",
        null=True,
        blank=True,
    )
    author_email = models.CharField(max_length=255, blank=True)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("created_at",)

    def __str__(self) -> str:
        return f"Note on {self.finding.internal_id} by {self.author_email or 'unknown'}"


class FindingReviewNote(models.Model):
    """Private review-thread note — visible to reporter + reviewers + superadmins.

    Distinct from `FindingNote` (the public collaboration journal) so the
    audience can differ: a reviewer can leave critique that the wider team
    doesn't need to see, and the reporter can respond.

    Append-only by application convention; the audit log captures the
    state-transition events that frame the discussion.
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    finding = models.ForeignKey(
        Finding,
        on_delete=models.CASCADE,
        related_name="review_notes",
    )
    author = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        related_name="finding_review_notes",
        null=True,
        blank=True,
    )
    author_email = models.CharField(max_length=255, blank=True)
    author_is_reviewer = models.BooleanField(
        default=False,
        help_text="Snapshot of whether the author was a reviewer/superadmin "
        "at write time. Used to render reporter-vs-reviewer attribution "
        "without re-checking the User row.",
    )
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("created_at",)

    def __str__(self) -> str:
        return f"ReviewNote on {self.finding.internal_id} by {self.author_email or 'unknown'}"


class AffectedHost(models.Model):
    """A host / URL / asset affected by one or more findings, scoped to a vendor.

    Stored against the vendor so it can be reused across that vendor's
    findings via a dropdown without re-typing. **Never shared across
    vendors** — the form and view restrict the selectable set to the
    finding's own vendor, so a finding can't reference another client's
    hosts (cross-vendor isolation).
    """

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    vendor = models.ForeignKey(
        "vendors.Vendor",
        on_delete=models.CASCADE,
        related_name="affected_hosts",
    )
    value = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering: ClassVar[tuple[str, ...]] = ("value",)
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["vendor", "value"],
                name="affectedhost_vendor_value_unique",
            ),
        ]

    def __str__(self) -> str:
        return self.value
