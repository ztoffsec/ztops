"""End-to-end: passkey sign-in -> step-up -> mint API token -> call /api/v1/me/.

Real WebAuthn signatures from the in-process virtual authenticator; no
mocks of the verifier. Proves the step-up gate is cryptographically wired
and the minted token authenticates the bearer API.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

import pytest
from django.core.cache import cache

from apps.api.models import ApiToken

from ._virtual_authenticator import VirtualAuthenticator
from .test_passkey_flow import _b64u_decode, _login, _register

if TYPE_CHECKING:
    from django.test import Client

_ORIGIN = "http://testserver"
_TOKEN_RE = re.compile(r"ztops_[0-9a-f]{12}_[A-Za-z0-9_-]{43}")


@pytest.mark.e2e
@pytest.mark.django_db
def test_step_up_mint_and_use_token(client: Client) -> None:
    cache.clear()
    authenticator = VirtualAuthenticator()
    user, _ = _register(
        client,
        user_email="agent-owner@example.com",
        user_display_name="Agent Owner",
        authenticator=authenticator,
    )
    _login(client, authenticator=authenticator)

    # Without step-up: refused.
    form = {"name": "e2e agent", "scopes": ["findings:read"], "lifetime_days": "7"}
    assert client.post("/super/profile/api-tokens/", form).status_code == 403

    # Real step-up ceremony.
    start = client.post(
        "/webauthn/step-up/start/",
        data=json.dumps({"purpose": "api_token_create"}),
        content_type="application/json",
    )
    assert start.status_code == 200
    options = start.json()
    assertion = authenticator.get(
        rp_id=options["rpId"],
        challenge=_b64u_decode(options["challenge"]),
        origin=_ORIGIN,
    )
    finish = client.post(
        "/webauthn/step-up/finish/",
        data=json.dumps(assertion),
        content_type="application/json",
    )
    assert finish.status_code == 200, finish.content

    created = client.post("/super/profile/api-tokens/", form)
    assert created.status_code == 200
    match = _TOKEN_RE.search(created.content.decode())
    assert match is not None
    raw = match.group(0)

    token = ApiToken.objects.get(user=user)
    assert raw.startswith(f"ztops_{token.prefix}_")

    me = client.get("/api/v1/me/", HTTP_AUTHORIZATION=f"Bearer {raw}")
    assert me.status_code == 200
    assert me.json()["user"]["id"] == str(user.id)
    assert me.json()["token"]["scopes"] == ["findings:read"]

    # Revoke from the UI; the token stops working immediately.
    assert client.post(f"/super/profile/api-tokens/{token.id}/revoke/").status_code == 302
    assert client.get("/api/v1/me/", HTTP_AUTHORIZATION=f"Bearer {raw}").status_code == 401
    cache.clear()
