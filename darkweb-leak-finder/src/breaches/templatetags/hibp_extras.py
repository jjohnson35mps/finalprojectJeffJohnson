# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# breaches/templatetags/hibp_extras.py
#
# Template helpers for the breaches app.
#
# OWASP notes:
#   - A03/A05/A06 (Injection/XSS/Insecure design):
#       sanitize_hibp applies a tiny allow-list HTML sanitizer
#       to HIBP descriptions, then marks them safe.
#       Never call |safe directly on raw HIBP data.

from __future__ import annotations

from html import escape
from html.parser import HTMLParser

from django import template
from django.utils.safestring import mark_safe

# Django template Library instance – all filters/tags must be registered on this.
register = template.Library()

# ---------------------------------------------------------------------------
# HIBP description sanitizer
# ---------------------------------------------------------------------------

# Tags and attributes we allow from HIBP’s HTML descriptions
_ALLOWED_TAGS = {"a", "strong", "b", "em", "i", "br", "p", "ul", "ol", "li"}
_ALLOWED_ATTRS = {
    "a": {"href", "target", "rel"},
}


class HibpSanitizer(HTMLParser):
    """
    Very small HTML sanitizer for HIBP descriptions.

    - Keeps only a small set of tags (see _ALLOWED_TAGS).
    - For <a>, keeps href/target/rel and enforces:
        * http/https only
        * rel="noopener noreferrer" to prevent reverse tabnabbing.
    - All text content is HTML-escaped.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        tag = tag.lower()
        if tag not in _ALLOWED_TAGS:
            return

        # <br> is self-closing in our output
        if tag == "br":
            self.chunks.append("<br>")
            return

        allowed_names = _ALLOWED_ATTRS.get(tag, set())
        safe_attrs: list[str] = []

        for name, value in attrs:
            name = name.lower()
            if name not in allowed_names:
                continue

            if name == "href":
                # Only allow http/https hrefs
                if not (value.startswith("http://") or value.startswith("https://")):
                    continue

            safe_attrs.append(f'{name}="{escape(value, quote=True)}"')

        # Enforce safe defaults for links
        if tag == "a":
            if not any(a.startswith("target=") for a in safe_attrs):
                safe_attrs.append('target="_blank"')
            if not any(a.startswith("rel=") for a in safe_attrs):
                safe_attrs.append('rel="noopener noreferrer"')

        attr_str = f" {' '.join(safe_attrs)}" if safe_attrs else ""
        self.chunks.append(f"<{tag}{attr_str}>")

    def handle_endtag(self, tag) -> None:
        tag = tag.lower()
        if tag not in _ALLOWED_TAGS or tag == "br":
            return
        self.chunks.append(f"</{tag}>")

    def handle_data(self, data) -> None:
        self.chunks.append(escape(data))

    def get_html(self) -> str:
        return "".join(self.chunks)


def _sanitize_hibp_html(value: str | None) -> str:
    """Internal helper: return sanitized HTML string from a raw HIBP description."""
    if not value:
        return ""
    parser = HibpSanitizer()
    parser.feed(str(value))
    return parser.get_html()


@register.filter(name="sanitize_hibp")
def sanitize_hibp(value: str | None) -> str:
    """
    Sanitize a HIBP description for safe rendering:

      - Whitelists a small tag set (a, strong, em, p, ul/ol/li, br).
      - Strips all other tags and attributes.
      - Ensures links use http/https and have rel="noopener noreferrer".

    Usage in templates:
        {{ h.description|sanitize_hibp }}
    """
    return mark_safe(_sanitize_hibp_html(value))
