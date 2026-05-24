"""Tests for the markdown renderer + preview endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from apps.accounts.models import Role, User
from apps.findings.markdown import render_markdown

if TYPE_CHECKING:
    from django.test import Client


def _user(email: str = "md@example.com") -> User:
    return User.objects.create_user(email=email, display_name="MD", role=Role.REGULAR)


# ---- render_markdown unit tests ------------------------------------------


def test_render_empty_returns_empty_string() -> None:
    assert render_markdown("") == ""
    assert render_markdown("   ") == ""


def test_render_basic_paragraph() -> None:
    out = render_markdown("hello **world**")
    assert "<p>" in out
    assert "<strong>world</strong>" in out


def test_render_code_fence_with_language_gets_highlighted() -> None:
    out = render_markdown("```python\nprint('hi')\n```")
    assert '<pre class="hl">' in out
    assert 'class="hl language-python"' in out
    # The string literal becomes a Pygments token span.
    assert 'class="s1"' in out  # single-quoted string token
    # Built-in `print` is tagged as a name-builtin.
    assert 'class="nb">print</span>' in out


def test_render_code_fence_without_language_falls_back_to_plain() -> None:
    out = render_markdown("```\nplain text\n```")
    # markdown-it default rendering, not Pygments-decorated.
    assert "<pre>" in out
    assert "plain text" in out
    assert 'class="hl"' not in out


def test_render_code_fence_unknown_language_falls_back_to_plain() -> None:
    out = render_markdown("```not-a-real-lang\nfoo\n```")
    assert "<pre>" in out
    assert 'class="hl"' not in out


def test_render_table_supported() -> None:
    out = render_markdown("| a | b |\n|---|---|\n| 1 | 2 |\n")
    assert "<table>" in out
    assert "<th>a</th>" in out
    assert "<td>1</td>" in out


def test_render_strips_inline_html() -> None:
    """markdown-it with html=False escapes raw tags."""
    out = render_markdown("<script>alert(1)</script>\n\nfoo")
    assert "<script>" not in out
    assert "alert(1)" in out  # text survives, the tag does not


def test_render_strips_javascript_url() -> None:
    """A js: scheme must not survive as an anchor href.

    markdown-it refuses to emit a link element for unsafe schemes; the
    raw text falls through and is rendered as a paragraph. Either way,
    no live link is produced.
    """
    out = render_markdown("[click](javascript:alert(1))")
    assert 'href="javascript:' not in out
    assert "<a " not in out


def test_render_strips_event_handler_attr() -> None:
    """Raw HTML in source is escaped to text (html=False) — the <a>
    never becomes a real element, so the onclick is harmless."""
    out = render_markdown('<a href="https://x" onclick="x()">click</a>')
    # No live <a> rendered; escaped to text.
    assert "<a " not in out
    assert "&lt;a " in out


def test_render_preserves_safe_link() -> None:
    out = render_markdown("[advisory](https://example.com/advisory/1)")
    assert 'href="https://example.com/advisory/1"' in out


# ---- preview endpoint -----------------------------------------------------


@pytest.mark.django_db
def test_preview_endpoint_requires_auth(client: Client) -> None:
    response = client.post("/findings/preview-markdown/", data={"body": "hi"})
    assert response.status_code == 302
    assert "/super/login/" in response["Location"]


@pytest.mark.django_db
def test_preview_endpoint_returns_rendered_html(client: Client) -> None:
    user = _user()
    client.force_login(user)
    response = client.post(
        "/findings/preview-markdown/",
        data={"body": "# hello\n\nworld"},
    )
    assert response.status_code == 200
    body = response.content.decode()
    assert "<h1>hello</h1>" in body
    assert "<p>world</p>" in body


@pytest.mark.django_db
def test_preview_endpoint_strips_xss(client: Client) -> None:
    user = _user("xss@example.com")
    client.force_login(user)
    response = client.post(
        "/findings/preview-markdown/",
        data={"body": '<img src=x onerror="alert(1)">\n\n[js](javascript:alert(1))'},
    )
    assert response.status_code == 200
    body = response.content.decode()
    # No live img element; no live anchor with a JS-scheme href.
    assert "<img" not in body
    assert "<a " not in body
    assert 'href="javascript:' not in body


@pytest.mark.django_db
def test_preview_endpoint_get_is_not_allowed(client: Client) -> None:
    user = _user("get@example.com")
    client.force_login(user)
    response = client.get("/findings/preview-markdown/")
    assert response.status_code == 405


@pytest.mark.django_db
def test_preview_endpoint_caps_payload(client: Client) -> None:
    user = _user("big@example.com")
    client.force_login(user)
    body = "a" * 200_000  # 200KB; view caps at 100KB
    response = client.post("/findings/preview-markdown/", data={"body": body})
    assert response.status_code == 200
    # The cap means at most the first 100K chars get rendered; the
    # output is bounded.
    assert len(response.content) < len(body)
