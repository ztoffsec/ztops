"""Markdown rendering for Finding.description and FindingNote.body.

Three-layer pipeline:
1. markdown-it-py parses with `html=False` so raw HTML inside the
   markdown source is treated as text, never injected.
2. Pygments highlights fenced code blocks server-side (no JS shipped
   to the page). Unknown languages fall back to plain monospace.
3. bleach.clean() with an explicit tag + attribute + protocol allowlist
   strips anything we don't want, including the rare cases where the
   markdown engine or highlighter could emit unsafe output.

The allowlist covers everything CommonMark + GFM tables + Pygments
token spans can emit. New markup categories require an explicit grant
here.
"""

from __future__ import annotations

import html as _html

import bleach
from markdown_it import MarkdownIt
from pygments import highlight as _pyg_highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name
from pygments.util import ClassNotFound

_FORMATTER = HtmlFormatter(nowrap=True)


def _highlight_code(code: str, lang: str, _attrs: str) -> str:
    """markdown-it-py highlight callback.

    Returns the complete <pre><code> block when we recognise the lang;
    returns "" to let markdown-it use its default plain rendering when
    the language is unknown or unspecified.
    """
    if not lang:
        return ""
    try:
        lexer = get_lexer_by_name(lang, stripall=False)
    except ClassNotFound:
        return ""
    tokens = _pyg_highlight(code, lexer, _FORMATTER)
    return f'<pre class="hl"><code class="hl language-{_html.escape(lang)}">{tokens}</code></pre>'


_MD = MarkdownIt(
    "commonmark",
    {
        "html": False,  # disallow inline HTML in source
        "linkify": True,  # auto-link bare URLs
        "typographer": False,  # avoid smart-quote surprises in findings
        "highlight": _highlight_code,
    },
)
_MD.enable("table")
_MD.enable("strikethrough")

ALLOWED_TAGS: frozenset[str] = frozenset(
    {
        "p",
        "br",
        "hr",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "strong",
        "em",
        "s",
        "del",
        "code",
        "pre",
        "span",  # Pygments token spans
        "blockquote",
        "ul",
        "ol",
        "li",
        "a",
        "table",
        "thead",
        "tbody",
        "tr",
        "th",
        "td",
    },
)

ALLOWED_ATTRIBUTES: dict[str, list[str]] = {
    "a": ["href", "title", "rel"],
    "code": ["class"],
    "pre": ["class"],
    # Pygments token spans only need `class`; nothing else gets through.
    "span": ["class"],
    "th": ["align"],
    "td": ["align"],
}

ALLOWED_PROTOCOLS: frozenset[str] = frozenset({"http", "https", "mailto"})


def render_markdown(text: str) -> str:
    """Render `text` to sanitized HTML. Empty input → empty string."""
    if not text:
        return ""
    rendered = _MD.render(text)
    return bleach.clean(
        rendered,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
    )
