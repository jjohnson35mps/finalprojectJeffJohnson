# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# src/security_ticker/views.py
#
# Purpose:
#   Provide a JSON feed of high-priority vulnerabilities (e.g., CISA KEV)
#   for the scrolling security ticker in the UI.

from __future__ import annotations

import logging

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from .services.sources import fetch_kev_items


# ------------------------------
# Module-level logger
# ------------------------------
logger = logging.getLogger("security_ticker")


# ------------------------------
# Ticker feed view (JSON)
# ------------------------------
@login_required(login_url="login")
@require_GET
def ticker_feed(request):
    """
    Return the ticker feed as JSON for authenticated users.

    Response shape:
      {
        "items": [
          {"title": "...", "date": "YYYY-MM-DD", "link": "https://..."},
          ...
        ],
        "source": "cisa_json" | "nvd_hasKev" | "fallback" | "error"
      }

    OWASP Top 10 touchpoints:
      - A01: Broken Access Control
          * Protected by @login_required so only authenticated users
            can see the feed in this implementation.
      - A04: Insecure Design / A05: Security Misconfiguration
          * Only GET is allowed via @require_GET to prevent misuse of the endpoint.
      - A06: Vulnerable & Outdated Components
          * Uses a small helper to fetch remote JSON; network/parse errors are
            handled gracefully so we don’t expose stack traces.
      - A09: Security Logging & Monitoring Failures
          * Failures are logged with warning level for troubleshooting.
    """
    try:
        # Fetch up to 10 items from the configured vulnerability sources
        items, source = fetch_kev_items(limit=10)

    except Exception as exc:
        # Log but return a generic, non-sensitive error payload
        logger.warning("Ticker feed failed: %s", exc)

        items = [
            {
                "title": "Security feed unavailable",
                "date": "",
                "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }
        ]
        source = "error"

    # Build JSON response
    resp = JsonResponse(
        {
            "items": items,
            "source": source,
        }
    )

    # Helpful debug header for browsers / tools, no sensitive info
    resp["X-Ticker-Source"] = source

    # Conservative caching: don’t let intermediaries store potentially
    # time-sensitive security information.
    resp["Cache-Control"] = "no-store"

    return resp
