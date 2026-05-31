"""Template filters that gate user-supplied URLs against a scheme whitelist.

`safe_external_url` is the render-time half of the references defense. The
form-level validator already rejects bad schemes on save, but if a bad
URL ever lands in the DB by another path (raw SQL, restored backup from a
vulnerable era, a future bug), the template still refuses to render it as
an href. The filter returns an empty string for anything outside the
whitelist, so the surrounding markup falls back to plain text.
"""

from __future__ import annotations

from urllib.parse import urlparse

from django import template

register = template.Library()

_ALLOWED_SCHEMES = frozenset({"http", "https"})


@register.filter(name="safe_external_url")
def safe_external_url(value: object) -> str:
    """Return value if it parses as an http/https URL with a host, else ''.

    Empty / None / non-strings collapse to ''. javascript:, data:, file:,
    vbscript:, and other URI schemes are stripped to '' so a template
    rendering ``<a href="{{ ref|safe_external_url }}">`` never produces a
    clickable javascript: link.
    """
    if not isinstance(value, str):
        return ""
    stripped = value.strip()
    if not stripped:
        return ""
    try:
        parsed = urlparse(stripped)
    except ValueError:
        return ""
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return ""
    if not parsed.netloc:
        return ""
    return stripped
