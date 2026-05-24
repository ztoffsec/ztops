"""User — passwordless auth principal.

Per hardening requirement #1 the User has no `password` column,
and the inherited `set_password` / `check_password` methods are
overridden to raise. The only auth path is a WebAuthn ceremony in
`apps.webauthn_auth`.

Roles are the only authorization signal: `superadmin` reaches /super/
(admin, approvals, audit); `regular` is everyone else on the team.
"""

from __future__ import annotations

from typing import ClassVar

from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.utils.crypto import salted_hmac

from core.security.uuids import uuid7

from .managers import UserManager


class Role(models.TextChoices):
    """Platform-level role for a User.

    `superadmin` carries administrative authority (user management,
    two-person-rule approvals, Django admin access).
    `regular` is a regular team member: read/write findings, read
    audit log, can't approve other superadmins' actions.
    """

    SUPERADMIN = "superadmin", "Superadmin"
    REGULAR = "regular", "Regular"


class User(AbstractBaseUser):
    """A passwordless ZTOps user."""

    # Removes the inherited `password` field from the model schema.
    password = None  # type: ignore[assignment]

    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    display_name = models.CharField(max_length=200)
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.REGULAR,
    )
    is_active = models.BooleanField(default=True)
    # Reviewer capability — can move findings through the review state
    # machine (pending → under_review → approved/rejected) and post
    # private review notes. Superadmins are reviewers implicitly
    # regardless of this flag; this column lets us delegate review
    # authority to a regular without granting full superadmin.
    is_reviewer = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = []

    class Meta:
        ordering = ("email",)
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["role"], name="accounts_user_role_idx"),
        ]

    def __str__(self) -> str:
        return self.email

    # --- password-path barriers --------------------------------------------

    def set_password(self, raw_password: str | None) -> None:  # pragma: no cover
        msg = (
            "ZTOps does not use passwords. Register a WebAuthn credential via "
            "apps.webauthn_auth instead."
        )
        raise RuntimeError(msg)

    def check_password(self, raw_password: str) -> bool:
        return False

    def has_usable_password(self) -> bool:
        return False

    def get_session_auth_hash(self) -> str:
        key_salt = "apps.accounts.models.User.get_session_auth_hash"
        return salted_hmac(key_salt, str(self.id)).hexdigest()

    # --- helpers -----------------------------------------------------------

    @property
    def is_superadmin(self) -> bool:
        return self.role == Role.SUPERADMIN

    @property
    def is_review_authority(self) -> bool:
        """Combines the explicit reviewer flag with implicit superadmin
        review authority. Use this in permission checks — `is_reviewer`
        alone misses the superadmins-are-reviewers-too rule."""
        return self.is_superadmin or self.is_reviewer

    @property
    def is_staff(self) -> bool:
        return self.is_superadmin

    @property
    def is_superuser(self) -> bool:
        return self.is_superadmin

    def has_perm(self, _perm: str, _obj: object | None = None) -> bool:
        return self.is_superadmin

    def has_perms(self, perm_list: list[str], obj: object | None = None) -> bool:
        return all(self.has_perm(p, obj) for p in perm_list)

    def has_module_perms(self, _app_label: str) -> bool:
        return self.is_superadmin
