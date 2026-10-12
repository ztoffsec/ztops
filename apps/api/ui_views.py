"""HTML views for managing API tokens.

- ``tokens_page`` (GET/POST): the signed-in user's own tokens + create form.
  Creation requires a fresh, one-shot step-up grant
  (``apps.webauthn_auth.services.consume_step_up``) for purpose
  ``api_token_create``. The raw token is rendered once in the POST response
  (``Cache-Control: no-store``); it is never put in a URL, session, message
  or log.
- ``token_revoke`` (POST): owners revoke their own tokens; superadmins may
  revoke any token. Anything else is a 404 (no existence oracle).
- ``admin_tokens_list`` (GET, superadmin): every user's tokens.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods, require_POST, require_safe
from django_ratelimit.decorators import ratelimit

from apps.accounts.decorators import superadmin_required
from apps.webauthn_auth.services import STEP_UP_PURPOSE_API_TOKEN_CREATE, consume_step_up
from core.security.ratelimit_keys import session_user

from .forms import ApiTokenCreateForm
from .models import ApiToken
from .services import TokenError, create_token, revoke_token

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse

    from apps.accounts.models import User

_LOGIN_URL = "/super/login/"


def _rows(tokens: list[ApiToken]) -> list[dict[str, object]]:
    now = timezone.now()
    return [{"token": t, "status": t.status_label(now)} for t in tokens]


def _own_tokens(user: User) -> list[ApiToken]:
    return list(ApiToken.objects.filter(user=user).select_related("user", "revoked_by"))


def _render_page(
    request: HttpRequest,
    form: ApiTokenCreateForm,
    *,
    issued: tuple[ApiToken, str] | None = None,
    status: int = 200,
) -> HttpResponse:
    response = render(
        request,
        "tenant/api_tokens/list.html",
        {
            "form": form,
            "rows": _rows(_own_tokens(request.user)),
            "issued_token": issued[0] if issued else None,
            "issued_raw": issued[1] if issued else None,
        },
        status=status,
    )
    # The create response contains the raw token; never cache any variant.
    response["Cache-Control"] = "no-store"
    return response


@login_required(login_url=_LOGIN_URL)
@csrf_protect
@require_http_methods(["GET", "HEAD", "POST"])
@ratelimit(key=session_user, rate="10/h", method="POST", block=True)
def tokens_page(request: HttpRequest) -> HttpResponse:
    if request.method != "POST":
        return _render_page(request, ApiTokenCreateForm())

    form = ApiTokenCreateForm(request.POST)
    if not form.is_valid():
        return _render_page(request, form, status=400)

    # Step-up is checked AFTER form validation so a typo does not burn the
    # grant, and BEFORE any state change. consume_step_up is one-shot.
    if not consume_step_up(request.user, request, STEP_UP_PURPOSE_API_TOKEN_CREATE):
        form.add_error(None, "Confirm with your passkey to create a token.")
        return _render_page(request, form, status=403)

    try:
        issued = create_token(
            user=request.user,
            name=form.cleaned_data["name"],
            scopes=form.cleaned_data["scopes"],
            lifetime_days=form.cleaned_data["lifetime_days"],
            request=request,
        )
    except TokenError as exc:
        form.add_error(None, str(exc))
        return _render_page(request, form, status=400)

    return _render_page(request, ApiTokenCreateForm(), issued=issued)


@login_required(login_url=_LOGIN_URL)
@csrf_protect
@require_POST
def token_revoke(request: HttpRequest, token_id: str) -> HttpResponse:
    user = request.user
    qs = ApiToken.objects.select_related("user")
    if not user.is_superadmin:
        qs = qs.filter(user=user)
    token = qs.filter(pk=token_id).first()
    if token is None:
        raise Http404

    if revoke_token(token=token, actor=user, request=request):
        messages.success(request, f"Token {token.prefix} revoked.")
    else:
        messages.info(request, f"Token {token.prefix} was already revoked.")

    if token.user_id != user.pk:
        return HttpResponseRedirect(reverse("api_tokens_admin:list"))
    return HttpResponseRedirect(reverse("api_tokens:list"))


@superadmin_required
@require_safe
def admin_tokens_list(request: HttpRequest) -> HttpResponse:
    tokens = list(ApiToken.objects.select_related("user", "revoked_by"))
    return render(request, "tenant/api_tokens/admin_list.html", {"rows": _rows(tokens)})
