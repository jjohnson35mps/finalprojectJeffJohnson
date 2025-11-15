# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# src/security_ticker/templatetags/to_list.py (or similar)
#
# Purpose:
#   Provide a safe, reusable Django template filter that normalizes different
#   input shapes (lists, tuples, JSON, CSV strings) into a clean list[str]
#   for display (e.g., badges/chips in templates).
#
# OWASP Top 10 touchpoints:
#   - A01: Broken Access Control
#       * This filter does not perform any auth checks; it just transforms
#         data already selected by the view. Access control must be enforced
#         in views / query layers (not here).
#   - A03: Injection / A05: Security Misconfiguration
#       * This helper only returns plain strings; it does not mark anything
#         as safe HTML. Templates using it should rely on Django’s default
#         auto-escaping to avoid XSS.
#   - A06: Vulnerable & Outdated Components
#       * Uses Python stdlib (json, str). No external parsing libs involved.
#   - A09: Security Logging & Monitoring
#       * No logging here: failures fall back gracefully instead of raising
#         unhandled exceptions that could leak data to end users.
#
#   IMPORTANT:
#     - Do NOT pipe untrusted values from here through "|safe" in templates
#       unless they have been explicitly sanitized elsewhere.

from __future__ import annotations

import json
from typing import Iterable, List

from django import template

# Django template Library instance used to register custom filters/tags.
register = template.Library()


@register.filter
def to_list(value: object) -> List[str]:
    """
    Normalize an arbitrary value into a list of non-empty strings.

    Accepted inputs:
      - None              -> []
      - list/tuple        -> coerces each element to str, strips whitespace
      - JSON string       -> if it parses as list/tuple, normalize that
      - CSV string        -> split on comma, strip each field
      - other types       -> stringified, split on commas, stripped

    Security notes (OWASP A03/A05):
      - This function never returns HTML or marks content safe.
      - Output is intended to be rendered with Django's auto-escaping ON,
        which prevents XSS when values originate from untrusted sources
        (e.g., external APIs).
    """
    # None → empty list, avoids "None" text showing up in the UI.
    if value is None:
        return []

    # If already a list/tuple, normalize to list[str].
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()]

    # If it's a string, first try to interpret as JSON, then fall back to CSV.
    if isinstance(value, str):
        # Try JSON first: e.g., '["Email addresses", "Passwords"]'
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed = None

        if isinstance(parsed, (list, tuple)):
            return [str(x).strip() for x in parsed if str(x).strip()]

        # Fallback: treat as comma-separated string.
        return [s.strip() for s in value.split(",") if s.strip()]

    # Last resort for any other type:
    # stringify and split on commas, e.g. for objects that define __str__.
    return [s.strip() for s in str(value).split(",") if s.strip()]
