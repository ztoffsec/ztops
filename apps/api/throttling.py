"""Per-token request throttle.

Keyed on the token id (not the user), so one runaway agent cannot starve a
user's other tokens, and a revoked-and-reissued token starts clean. The rate
is read from settings at call time so it is tunable per environment.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from rest_framework.throttling import SimpleRateThrottle

from .models import ApiToken

if TYPE_CHECKING:
    from rest_framework.request import Request
    from rest_framework.views import APIView


class TokenRateThrottle(SimpleRateThrottle):
    scope = "api_token"

    def get_rate(self) -> str:
        return str(settings.API_TOKEN_THROTTLE_RATE)

    def get_cache_key(self, request: Request, view: APIView) -> str | None:
        token = request.auth
        if not isinstance(token, ApiToken):
            return None
        return self.cache_format % {"scope": self.scope, "ident": token.pk}
