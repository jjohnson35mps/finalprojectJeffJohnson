# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# Reusable utilities (validators, parsing helpers, etc.).
#
# OWASP Top 10 considerations:
#   - A03/A05 (Injection / Input Validation):
#       * This module provides basic, explicit validation helpers so that
#         user input is checked before use.
#       * Email validation here is intentionally simple; it is meant for
#         UX and basic sanity checks, not as a security boundary.
#   - A06 (Sensitive Data Exposure):
#       * Email values are PII. Validators should not log raw email
#         addresses; callers are responsible for careful logging.
#   - A06/A08 (Insecure Design / Data Integrity):
#       * Do not rely solely on this function to enforce auth, access
#         control, or business rules—treat it as a helper only.

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Email validation
# ---------------------------------------------------------------------------

# Simple, non-catastrophic regex for "something@something.tld".
# This is NOT a full RFC-compliant validator, but good enough for
# basic form checks.
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(value: str | None) -> bool:
    """
    Return True if `value` looks like a syntactically valid email address.

    - Trims surrounding whitespace.
    - Returns False for None or empty/whitespace-only strings.
    - Uses a simple regex suitable for basic validation, not a full RFC parser.

    OWASP notes:
      - Do NOT use this alone to decide authorization or account ownership.
      - Always treat the email as untrusted input elsewhere in the system.
    """
    if value is None:
        return False

    candidate = value.strip()
    if not candidate:
        return False

    return bool(EMAIL_REGEX.match(candidate))
