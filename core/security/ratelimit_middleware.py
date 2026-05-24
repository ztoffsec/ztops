"""Map django-ratelimit's ``Ratelimited`` to an HTTP 429.

`@ratelimit(block=True)` raises ``Ratelimited`` (a ``PermissionDenied`` subclass),
which Django would otherwise render as 403. For throttling we want 429 Too Many
Requests with a ``Retry-After`` hint so clients (and the WebAuthn fetch() flow)
back off correctly. This middleware only intercepts that one exception type.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.http import HttpResponse
from django_ratelimit.exceptions import Ratelimited  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest


class RatelimitTo429Middleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        return self.get_response(request)

    def process_exception(self, request: HttpRequest, exception: Exception) -> HttpResponse | None:
        if isinstance(exception, Ratelimited):
            response = HttpResponse("Too Many Requests", status=429, content_type="text/plain")
            response["Retry-After"] = "60"
            return response
        return None
