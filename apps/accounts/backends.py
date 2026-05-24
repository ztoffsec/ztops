"""Authentication backend for WebAuthn-authenticated users.

Django's session login requires an ``AUTHENTICATION_BACKENDS`` entry that
knows how to (a) authenticate a user from credentials and (b) restore a
user from a session.

For ZTOps, (a) is a no-op — we never authenticate via username/password.
The only valid auth path is a successful WebAuthn ceremony in
``apps.webauthn_auth``, which sets ``user.backend`` to this class before
calling ``django.contrib.auth.login(request, user)``. The login function
then skips the authenticate() loop and writes the user ID into the
session directly.

Method (b) is the live use: AuthenticationMiddleware calls ``get_user``
on every request to populate ``request.user`` from the session.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import User

if TYPE_CHECKING:
    from django.http import HttpRequest


class WebAuthnAuthBackend:
    """Session-restorer for users authenticated via WebAuthn."""

    def authenticate(
        self,
        request: HttpRequest | None,  # noqa: ARG002 — required by the protocol
        **_kwargs: Any,
    ) -> None:
        # No password / token-pair auth path. Return None so Django's
        # authenticate() loop walks to the next backend (we configure
        # only this one, so the loop produces None — which is correct,
        # the only way to log in is the WebAuthn ceremony).
        return None

    def get_user(self, user_id: str) -> User | None:
        try:
            return User.objects.get(pk=user_id, is_active=True)
        except User.DoesNotExist:
            return None
