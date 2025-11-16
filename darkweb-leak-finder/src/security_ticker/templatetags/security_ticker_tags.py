# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# src/security_ticker/templatetags/security_ticker_tags.py
#
# Purpose:
#   Expose a reusable `{% security_ticker %}` inclusion tag that renders
#   the ticker container markup. The JavaScript front-end is responsible
#   for fetching KEV / vulnerability data from the backend API.
#
# OWASP Top 10 touchpoints:
#   - A01: Broken Access Control
#       * The tag itself does not enforce auth; views/templates that include
#         it should gate display (e.g., `if user.is_authenticated` in base.html).
#   - A02: Cryptographic Failures / A04: Insecure Design
#       * This tag does not handle any secrets or crypto; all secret handling
#         (e.g. API tokens for upstream feeds) is done on the server side in
#         the ticker view/service, not passed through the template layer.
#   - A03/A05/A06: Injection / Security Misconfig / XSS
#       * The tag returns an empty context and renders a static partial. All
#         dynamic content is pulled via JS and should be escaped on the
#         backend or in DOM construction (not via `innerHTML` with raw data
#         from untrusted sources).
#   - A09: Security Logging & Monitoring
#       * Any logging of external API failures or errors is handled in the
#         view/service layer, not in the template tag.

from __future__ import annotations

from django import template

# Django template Library instance used to register custom template tags.
register = template.Library()


@register.inclusion_tag("security_ticker/_ticker.html", takes_context=True)
def security_ticker(context: dict) -> dict:
    """
    Render the security ticker container markup.

    The returned context is intentionally empty:
      - The visual structure lives in `security_ticker/_ticker.html`.
      - Data items (e.g., KEV entries) are fetched by front-end JS from
        `/api/ticker/` and rendered client-side.

    Security notes (OWASP A01/A03):
      - Access control: templates that include this tag should decide whether
        the current user is allowed to see the ticker (e.g., only when
        authenticated).
      - XSS: the template itself doesn’t output feed data; the API that backs
        `/api/ticker/` must ensure values are sanitized/escaped before sending
        them to the browser, and the JS should avoid inserting untrusted HTML.
    """
    # We purposely do *not* pass the full `context` into the partial to avoid
    # accidentally leaking sensitive variables into the ticker template.
    return {}
