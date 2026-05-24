"""Tests for the Engagements UI."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from apps.accounts.models import Role, User
from apps.engagements.models import Asset, AssetKind, Engagement, ScopeRule, ScopeRuleType

if TYPE_CHECKING:
    from django.test import Client


def _make_member(email: str) -> User:
    return User.objects.create_user(email=email, display_name=email[:6], role=Role.REGULAR)


# ---- access control ------------------------------------------------------


@pytest.mark.django_db
def test_engagements_anon_redirected(client: Client) -> None:
    response = client.get("/engagements/")
    assert response.status_code == 302
    assert "/super/login/" in response["Location"]


# ---- engagement CRUD ----------------------------------------------------


@pytest.mark.django_db
def test_list_renders_engagements(client: Client) -> None:
    user = _make_member("li@example.com")
    Engagement.objects.create(slug="acme-disc", name="Acme Disclosure")
    client.force_login(user)
    response = client.get("/engagements/")
    assert response.status_code == 200
    assert b"acme-disc" in response.content


@pytest.mark.django_db
def test_new_post_creates_engagement(client: Client) -> None:
    user = _make_member("nw@example.com")
    client.force_login(user)
    response = client.post(
        "/engagements/new/",
        data={
            "slug": "new-eng",
            "name": "New Engagement",
            "engagement_type": "disclosure",
            "status": "active",
            "target_vendor": "Vendor X",
            "description": "",
            "started_at": "",
            "completed_at": "",
        },
    )
    assert response.status_code == 302
    assert Engagement.objects.filter(slug="new-eng").exists()


@pytest.mark.django_db
def test_detail_renders_with_children(client: Client) -> None:
    user = _make_member("dt@example.com")
    e = Engagement.objects.create(slug="det-eng", name="Detail")
    Asset.objects.create(engagement=e, kind=AssetKind.URL, identifier="https://x.test")
    ScopeRule.objects.create(
        engagement=e,
        rule_type=ScopeRuleType.IN_SCOPE,
        pattern="*.x.test",
    )
    client.force_login(user)
    response = client.get(f"/engagements/{e.id}/")
    assert response.status_code == 200
    body = response.content.decode()
    assert "det-eng" in body
    assert "https://x.test" in body
    assert "*.x.test" in body


@pytest.mark.django_db
def test_edit_post_updates_engagement(client: Client) -> None:
    user = _make_member("ed@example.com")
    e = Engagement.objects.create(slug="ed-eng", name="Before")
    client.force_login(user)
    response = client.post(
        f"/engagements/{e.id}/edit/",
        data={
            "slug": "ed-eng",
            "name": "After",
            "engagement_type": "disclosure",
            "status": "paused",
            "target_vendor": "V",
            "description": "",
            "started_at": "",
            "completed_at": "",
        },
    )
    assert response.status_code == 302
    e.refresh_from_db()
    assert e.name == "After"
    assert e.status == "paused"


# ---- nested Asset / ScopeRule actions -----------------------------------


@pytest.mark.django_db
def test_asset_add_appends(client: Client) -> None:
    user = _make_member("aa@example.com")
    e = Engagement.objects.create(slug="aa-eng", name="AA")
    client.force_login(user)
    response = client.post(
        f"/engagements/{e.id}/assets/add/",
        data={
            "kind": "url",
            "identifier": "https://test.example",
            "description": "",
            "in_scope": "on",
        },
    )
    assert response.status_code == 302
    assert e.assets.filter(identifier="https://test.example").exists()


@pytest.mark.django_db
def test_asset_delete_removes(client: Client) -> None:
    user = _make_member("ad@example.com")
    e = Engagement.objects.create(slug="ad-eng", name="AD")
    a = Asset.objects.create(engagement=e, kind=AssetKind.URL, identifier="x")
    client.force_login(user)
    response = client.post(f"/engagements/{e.id}/assets/{a.id}/delete/")
    assert response.status_code == 302
    assert not Asset.objects.filter(pk=a.id).exists()


@pytest.mark.django_db
def test_scope_rule_add_appends(client: Client) -> None:
    user = _make_member("sa@example.com")
    e = Engagement.objects.create(slug="sa-eng", name="SA")
    client.force_login(user)
    response = client.post(
        f"/engagements/{e.id}/scope-rules/add/",
        data={
            "rule_type": "in_scope",
            "pattern": "*.target.example",
            "notes": "primary domain",
        },
    )
    assert response.status_code == 302
    assert e.scope_rules.filter(pattern="*.target.example").exists()


@pytest.mark.django_db
def test_scope_rule_delete_removes(client: Client) -> None:
    user = _make_member("sd@example.com")
    e = Engagement.objects.create(slug="sd-eng", name="SD")
    r = ScopeRule.objects.create(
        engagement=e,
        rule_type=ScopeRuleType.IN_SCOPE,
        pattern="x",
    )
    client.force_login(user)
    response = client.post(f"/engagements/{e.id}/scope-rules/{r.id}/delete/")
    assert response.status_code == 302
    assert not ScopeRule.objects.filter(pk=r.id).exists()
