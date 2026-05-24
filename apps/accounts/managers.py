"""User manager that refuses every password-based account-creation path.

Django's default ``BaseUserManager`` exposes both ``create_user`` and
``create_superuser``, both of which set passwords. We override the
former to skip the password step entirely and we DO NOT implement
``create_superuser`` — Django's ``createsuperuser`` management command
will fail loudly if anyone tries to use it, which is the intent.

Superadmins are created exclusively by the
``register_superadmin_passkey`` command in Paso 5, which performs a
hands-on WebAuthn ceremony rather than accepting a password.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.contrib.auth.base_user import BaseUserManager

if TYPE_CHECKING:
    from .models import User


class UserManager(BaseUserManager["User"]):
    use_in_migrations = True

    def create_user(
        self,
        email: str,
        display_name: str,
        role: str = "regular",
        **extra_fields: Any,
    ) -> User:
        """Create a passwordless User row.

        The returned user cannot log in until at least one WebAuthn
        credential is registered for them via `apps.webauthn_auth`.
        """
        if not email:
            msg = "email is required"
            raise ValueError(msg)
        email = self.normalize_email(email)
        user: User = self.model(
            email=email,
            display_name=display_name,
            role=role,
            **extra_fields,
        )
        # Intentionally no `user.set_password()` call — the User model
        # has no password column, and overriding set_password to raise
        # ensures third-party code can't accidentally restore a password
        # auth path.
        user.save(using=self._db)
        return user
