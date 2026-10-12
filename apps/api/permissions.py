"""Scope-based authorization for API views (deny by default).

Every API view must declare ``required_scopes``:

- a ``Mapping[str, frozenset[str]]`` of HTTP method -> scopes (preferred), or
- a ``frozenset[str]`` applied to every method.

A view that declares nothing, or a method missing from the mapping, is
denied. An empty frozenset means "any valid token" (e.g. ``/me/``). HEAD
falls back to the GET entry, matching DRF's handler mapping.

Scopes only gate *which API operations* a token may call. Per-object access
(``can_user_view`` / ``can_user_edit``) is still enforced by each endpoint on
top of this, using the token owner as the subject.
"""

from __future__ import annotations

from collections.abc import Mapping, Set
from typing import TYPE_CHECKING

from rest_framework.permissions import BasePermission

from .models import ApiToken

if TYPE_CHECKING:
    from rest_framework.request import Request
    from rest_framework.views import APIView


def required_scopes_for(view: APIView, method: str) -> frozenset[str] | None:
    declared = getattr(view, "required_scopes", None)
    if isinstance(declared, Mapping):
        entry = declared.get(method)
        if entry is None and method == "HEAD":
            entry = declared.get("GET")
        return frozenset(entry) if isinstance(entry, Set) else None
    if isinstance(declared, Set):
        return frozenset(declared)
    return None


class HasTokenScopes(BasePermission):
    message = "Token is not authorized for this operation."

    def has_permission(self, request: Request, view: APIView) -> bool:
        token = request.auth
        if not isinstance(token, ApiToken):
            return False
        required = required_scopes_for(view, request.method or "")
        if required is None:
            return False
        return token.has_scopes(required)
