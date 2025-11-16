# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# hibp.py
# ------------------------------------------------------------
# Service-layer client for the "Have I Been Pwned" (HIBP) v3 API.
#
# Responsibilities
#   - Read HIBP API configuration from environment variables
#   - Call the `breachedaccount` endpoint for a given email
#   - Normalize raw HIBP responses into a clean internal schema
#   - Raise clear, typed exceptions for auth/ratelimit errors
#
# OWASP Top 10 (2025) touchpoints
#   - A02: Security Misconfiguration
#       * Secrets (API key, UA) come from env, not hard-coded.
#       * Timeout is enforced on outbound calls.
#   - A06: Insecure Design
#       * Email is normalized and URL-encoded before use.
#       * Normalized schema keeps data consistent for downstream logic.
#   - A09: Logging & Alerting Failures
#       * Logging avoids leaking the full email address.
#   - A10: Mishandling of Exceptional Conditions
#       * Typed exceptions for auth / rate limit.
#       * Clear handling of 404 / non-JSON / unexpected responses.
# ------------------------------------------------------------

from __future__ import annotations

import os
import re
import time
import logging
from typing import Any, List, Optional
from urllib.parse import quote

import requests

# Module-level logger used by the breaches app. Configure handlers/levels
# centrally in Django settings. Be careful not to log secrets or full PII.
logger = logging.getLogger("breaches")

# ------------------------------------------------------------
# Custom exception hierarchy for HIBP-related errors
# ------------------------------------------------------------
class HibpError(Exception):
    """
    Base error for HIBP-related failures.

    This lets callers catch HibpError to handle all HIBP-specific problems
    in one place (e.g., show a generic "HIBP is unavailable" message).
    """
    ...


class HibpAuthError(HibpError):
    """
    Raised when the HIBP API returns HTTP 401.

    Typically means the API key is missing or invalid.
    (OWASP A02: alerts you to misconfiguration or leaked/rotated keys.)
    """
    ...


class HibpRateLimitError(HibpError):
    """
    Raised when HIBP returns HTTP 429 (rate limit hit).

    Callers can e.g. pause, back off, or surface a "try again later" message.
    (OWASP A10: predictable handling of exceptional conditions.)
    """
    ...


# ------------------------------------------------------------
# Utility: date parsing & normalization
# ------------------------------------------------------------
# Regex to validate YYYY-MM-DD strings. We reduce HIBP timestamps to this
# format so templates and other code don’t have to deal with full ISO strings.
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _date_yyyy_mm_dd(value: Any) -> Optional[str]:
    """
    Normalize a date-like value to 'YYYY-MM-DD', or return None.

    - Accepts full timestamps like '2019-10-16T00:00:00Z' and truncates
      to the first 10 characters.
    - Returns None for empty or non-YYYY-MM-DD values.

    This keeps all dates in a consistent, simple format for the UI and
    reporting logic (A06: Insecure Design – explicit, predictable formats).
    """
    if not value:
        return None
    s = str(value).strip()
    if len(s) >= 10:
        s = s[:10]
    return s if _DATE_RE.match(s) else None


# ------------------------------------------------------------
# HIBP API client
# ------------------------------------------------------------
class HibpClient:
    """
    Thin wrapper around the HIBP v3 API for breached accounts.

    Use:
        client = HibpClient()
        breaches = client.breaches_for_account("user@example.com")

    This class isolates:
      - HTTP details (URL, headers, timeouts)
      - Error mapping (HTTP codes -> typed exceptions)
      - Response normalization into app-friendly dicts
    """

    # Base URL for the HIBP v3 API.
    BASE = "https://haveibeenpwned.com/api/v3"

    def __init__(self) -> None:
        """
        Initialize the client, loading configuration and setting HTTP defaults.

        OWASP A02: Security Misconfiguration
        - API key and user agent come from environment variables so they can be
          rotated or changed without touching code.
        """
        # Read API credentials + user agent from environment.
        self.key = (os.getenv("HIBP_API_KEY") or "").strip()
        self.ua = (os.getenv("HIBP_USER_AGENT") or "DarkWebLeakFinder/1.0").strip()

        # Reuse a single requests.Session for better performance and
        # consistent headers across all HIBP calls.
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.ua,
            "hibp-api-key": self.key or "missing",  # header required by HIBP
            "Accept": "application/json",
        })

        # last call metadata for UI/debug (non-sensitive):
        # - status code
        # - requested URL (with local masking)
        # - number of items returned
        # - content type
        # These help with troubleshooting without exposing secrets.
        self.last_status: Optional[int] = None
        self.last_url: Optional[str] = None
        self.last_items: Optional[int] = None
        self.last_ct: Optional[str] = None

    # -------------------------
    # Public API
    # -------------------------
    def breaches_for_account(self, email: str) -> List[dict[str, Any]]:
        """
        Fetch and normalize all breaches for a given account email.

        Returns a list of breach dicts with this schema:
          {
            "breach_name": str,          # stable key from HIBP Name
            "title": str,                # prefer Title, fallback to Name
            "domain": str,
            "breach_date": str|None,     # 'YYYY-MM-DD'
            "occurred_on": str|None,     # same as breach_date
            "added_on": str|None,
            "modified_on": str|None,
            "pwn_count": int,
            "data_classes": list[str],
            "description": str,
            "is_verified": bool,
            "is_sensitive": bool,
            "is_fabricated": bool,
            "is_spam_list": bool,
            "is_retired": bool,
            "is_malware": bool,
            "is_stealer_log": bool,
            "is_subscription_free": bool,
          }

        Notes:
        - Records without a Name are dropped (avoids collapsing multiple rows).
        - LogoPath is intentionally omitted to reduce clutter and external calls.
        - Network errors from requests will bubble up as exceptions; callers
          should handle them at the view layer (A10).
        """
        # If no API key is configured, operate in "demo mode" and
        # return an empty list. This avoids hard failures during grading/demo
        # but still logs the misconfiguration (A02/A09).
        if not self.key:
            logger.info("[HIBP] no API key set; returning [] (demo mode)")
            self.last_status, self.last_url, self.last_items = None, None, 0
            return []

        # Normalize and URL-encode the email.
        # - lowercasing keeps lookups consistent.
        # - quote() prevents injection into the URL path.
        account = quote(email.strip().lower(), safe="")

        url = f"{self.BASE}/breachedaccount/{account}"
        params = {
            "truncateResponse": "false",     # we want full breach details
            "includeUnverified": "true",     # show even unverified breaches
        }

        # OWASP A10: rate limit / resource usage
        # HIBP strongly enforces rate limiting. A small, fixed delay before
        # calls reduces the chance of immediate 429s during normal use.
        time.sleep(1.6)

        # Perform the HTTP request with a bounded timeout.
        # If the network is down or the service hangs, requests will raise.
        resp = self.session.get(url, params=params, timeout=20)

        # Record basic metadata about this request for debugging/UX.
        self.last_status = resp.status_code
        self.last_ct = resp.headers.get("Content-Type", "")

        # Avoid logging the full email address (PII) in URLs (A09).
        # We only log the endpoint path pattern and status code.
        redacted_url = f"{self.BASE}/breachedaccount/<redacted>"
        self.last_url = redacted_url
        logger.info("[HIBP] GET %s -> %s | CT=%s", redacted_url, resp.status_code, self.last_ct)

        # 404 from HIBP means "no breaches found" for this account.
        if resp.status_code == 404:
            self.last_items = 0
            return []

        # 401 suggests a missing or invalid API key (A02).
        if resp.status_code == 401:
            raise HibpAuthError("HIBP 401 Unauthorized: API key missing/invalid.")

        # 429 means we hit the HIBP rate limit and should back off (A10).
        if resp.status_code == 429:
            raise HibpRateLimitError("HIBP 429 Rate limited. Try again shortly.")

        # For any other non-success codes, raise the HTTP error.
        resp.raise_for_status()

        # Defensive check: ensure we got JSON back before parsing.
        # If HIBP returns HTML (maintenance page, WAF, etc.), we avoid
        # trying to parse it and just treat it as "no data".
        if not str(self.last_ct or "").lower().startswith("application/json"):
            logger.info(
                "[HIBP] non-JSON response; ignoring body preview=%r",
                (resp.text or "")[:120],
            )
            self.last_items = 0
            return []

        data = resp.json()

        # HIBP returns a list of breach objects for this endpoint.
        if not isinstance(data, list):
            self.last_items = 0
            return []

        # Normalize and DROP nameless entries (None).
        # Only well-formed breach records with a Name field are kept.
        normalized: List[dict[str, Any]] = []
        for raw in data:
            if isinstance(raw, dict):
                nb = self._normalize_breach(raw)
                if nb is not None:
                    normalized.append(nb)

        self.last_items = len(normalized)
        logger.info("[HIBP] items=%s (normalized)", self.last_items)
        return normalized

    # -------------------------
    # Internals
    # -------------------------
    def _normalize_breach(self, b: dict[str, Any]) -> Optional[dict[str, Any]]:
        """
        Map HIBP fields to our schema and drop any logo-related fields.

        Returns:
            - A normalized dict if 'Name' is present.
            - None if 'Name' is missing/blank (record is skipped).

        This keeps the rest of the application from having to know the exact
        HIBP schema and centralizes any future changes to that schema.
        """
        # 'Name' is the canonical stable identifier for a breach in HIBP.
        name = (b.get("Name") or "").strip()
        if not name:
            # Drop nameless records to avoid collapsing rows under "Unknown"
            return None

        # Prefer the human-friendly Title when present; otherwise fall back to Name.
        title = (b.get("Title") or "").strip() or name
        domain = (b.get("Domain") or "").strip()

        # Normalize all dates to 'YYYY-MM-DD' strings.
        breach_date = _date_yyyy_mm_dd(b.get("BreachDate"))
        added_on = _date_yyyy_mm_dd(b.get("AddedDate"))
        modified_on = _date_yyyy_mm_dd(b.get("ModifiedDate"))

        # PwnCount is the total number of impacted accounts (int).
        pwn_count = int(b.get("PwnCount") or 0)

        # DataClasses describes what types of data were exposed.
        dc = b.get("DataClasses")
        if isinstance(dc, (list, tuple)):
            data_classes = [str(x).strip() for x in dc if str(x).strip()]
        elif isinstance(dc, str):
            data_classes = [s.strip() for s in dc.split(",") if s.strip()]
        else:
            data_classes = []

        # HIBP provides an HTML description of the incident.
        # NOTE: When rendering this in templates, rely on Django's auto-escaping
        # or carefully control any use of |safe to avoid XSS (A03/A05).
        description = (b.get("Description") or "").strip()

        # Return a normalized, app-friendly dictionary.
        return {
            "breach_name": name,       # stable unique-ish key
            "title": title,            # nicer label
            "domain": domain,
            "breach_date": breach_date,
            "occurred_on": breach_date,
            "added_on": added_on,
            "modified_on": modified_on,
            "pwn_count": pwn_count,
            "data_classes": data_classes,
            "description": description,
            # common flags (coerced to bool)
            "is_verified": bool(b.get("IsVerified")),
            "is_sensitive": bool(b.get("IsSensitive")),
            "is_fabricated": bool(b.get("IsFabricricated")),
            "is_spam_list": bool(b.get("IsSpamList")),
            "is_retired": bool(b.get("IsRetired")),
            "is_malware": bool(b.get("IsMalware")),
            "is_stealer_log": bool(b.get("IsStealerLog")),
            "is_subscription_free": bool(b.get("IsSubscriptionFree")),
        }
