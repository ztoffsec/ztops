"""API v1 views.

All API views subclass ``ApiView`` so they inherit the hardened defaults from
``settings.REST_FRAMEWORK`` (bearer auth only, JSON only, IsAuthenticated +
HasTokenScopes, per-token throttle) and ``Cache-Control: no-store``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rest_framework.response import Response
from rest_framework.views import APIView

if TYPE_CHECKING:
    from rest_framework.request import Request


class ApiView(APIView):
    def finalize_response(
        self,
        request: Request,
        response: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        response = super().finalize_response(request, response, *args, **kwargs)
        # Responses carry user data; never let a shared or browser cache keep them.
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
        return response


class MeView(ApiView):
    """Identity + token introspection. Any valid token may call it."""

    required_scopes = {"GET": frozenset()}

    def get(self, request: Request) -> Response:
        token = request.auth
        user = request.user
        return Response(
            {
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "display_name": user.display_name,
                },
                "token": {
                    "id": str(token.id),
                    "name": token.name,
                    "prefix": token.prefix,
                    "scopes": list(token.scopes),
                    "created_at": token.created_at.isoformat(),
                    "expires_at": token.expires_at.isoformat(),
                },
            },
        )
