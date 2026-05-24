"""Tests for Engagement, Asset, ScopeRule."""

from __future__ import annotations

import pytest
from django.db import IntegrityError

from apps.engagements.models import (
    Asset,
    AssetKind,
    Engagement,
    EngagementStatus,
    EngagementType,
    ScopeRule,
    ScopeRuleType,
)


@pytest.mark.django_db
def test_engagement_creation() -> None:
    e = Engagement.objects.create(
        slug="acme-2026",
        name="Acme 2026 Disclosure",
        target_vendor="Acme",
        engagement_type=EngagementType.DISCLOSURE,
    )
    assert e.status == EngagementStatus.ACTIVE  # default
    assert e.created_at is not None


@pytest.mark.django_db
def test_engagement_slug_is_unique() -> None:
    Engagement.objects.create(slug="dup", name="First")
    with pytest.raises(IntegrityError):
        Engagement.objects.create(slug="dup", name="Second")


@pytest.mark.django_db
def test_asset_links_to_engagement_via_fk() -> None:
    e = Engagement.objects.create(slug="ke", name="K8s Engagement")
    asset = Asset.objects.create(
        engagement=e,
        kind=AssetKind.REPO,
        identifier="github.com/kubernetes/python-client",
        in_scope=True,
    )
    assert asset.engagement_id == e.id
    assert list(e.assets.all()) == [asset]


@pytest.mark.django_db
def test_cascade_delete_removes_assets_and_scope_rules() -> None:
    e = Engagement.objects.create(slug="cas", name="Cascade")
    Asset.objects.create(engagement=e, kind=AssetKind.URL, identifier="x.com")
    ScopeRule.objects.create(
        engagement=e,
        rule_type=ScopeRuleType.IN_SCOPE,
        pattern="*.example.com",
    )
    e_id = e.id
    e.delete()
    assert Asset.objects.filter(engagement_id=e_id).count() == 0
    assert ScopeRule.objects.filter(engagement_id=e_id).count() == 0


@pytest.mark.django_db
def test_scope_rule_two_polarities() -> None:
    e = Engagement.objects.create(slug="sr", name="Scope Rules")
    ScopeRule.objects.create(
        engagement=e,
        rule_type=ScopeRuleType.IN_SCOPE,
        pattern="*.target.com",
    )
    ScopeRule.objects.create(
        engagement=e,
        rule_type=ScopeRuleType.OUT_OF_SCOPE,
        pattern="login.target.com",
    )
    assert e.scope_rules.count() == 2
    assert e.scope_rules.filter(rule_type=ScopeRuleType.IN_SCOPE).count() == 1
    assert e.scope_rules.filter(rule_type=ScopeRuleType.OUT_OF_SCOPE).count() == 1
