# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# security_ticker/kev_feed.py (example module name)
#
# Purpose:
#   Fetch a short list of "known exploited vulnerabilities" (KEV) from
#   public feeds (CISA first, NVD as fallback) for use in the ticker UI.
#
# OWASP Top 10 touchpoints:
#   - A05: Security Misconfiguration / A07: Identification & Auth Failures
#       * No secrets are logged or returned to templates.
#       * External URLs are fixed, HTTPS-only, and not user-controlled.
#   - A03: Injection
#       * We never pass user input into these URLs or into a shell/SQL.
#   - A06: Vulnerable & Outdated Components
#       * Uses 'requests' with explicit timeout; caller should pin versions
#         via requirements to avoid stale libraries.
#   - A09: Security Logging & Monitoring
#       * Errors are logged via a dedicated logger instead of leaking
#         full exception details to the UI.

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Tuple

import requests

# ---------------------------------------------------------------------------
# Logging setup (A09: Security Logging & Monitoring)
# ---------------------------------------------------------------------------
logger = logging.getLogger("security_ticker")

# ---------------------------------------------------------------------------
# Constants / configuration
# ---------------------------------------------------------------------------

#: Primary (preferred) CISA KEV feed – JSON via HTTPS
CISA_KEV_JSONS: List[str] = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
]

#: Fallback API: NVD CVEs with hasKev flag
NVD_KEV_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev"

#: User-agent for outbound HTTP calls (helps API owners identify the client)
UA = os.getenv("SEC_TICKER_USER_AGENT", "DarkWebLeakFinder/1.0 (+ticker)")


def _timeout_from_env(default: int = 8) -> int:
    """
    Derive an HTTP timeout from the environment.

    - Clamps to [1, 30] seconds to avoid pathological values.
    - Logs invalid values instead of raising.

    OWASP:
      - A05 (Security Misconfiguration):
          Avoids crashes or hangs from bad env configuration.
    """
    raw = os.getenv("SEC_TICKER_TIMEOUT_SECONDS", str(default))
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "SEC_TICKER_TIMEOUT_SECONDS=%r is not an integer; using default=%s",
            raw,
            default,
        )
        return default

    # Clamp to a sane range to avoid extreme timeouts
    value = max(1, min(value, 30))
    return value


DEFAULT_TIMEOUT = _timeout_from_env()


def _get_json(url: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Perform a GET request and return parsed JSON.

    Safety notes:
      - Uses HTTPS URLs only (hard-coded).
      - Uses an explicit timeout to avoid hanging the server thread.
      - Raises for non-2xx statuses (except 403/404 which we normalize).

    OWASP:
      - A05 (Security Misconfiguration): timeout + HTTPS-only URLs.
      - A09 (Logging): calling code logs any exceptions instead of exposing
        stack traces directly in the UI.
    """
    response = requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": UA},
    )

    # Normalize some "expected" error statuses into HTTPError so callers
    # can decide how to fall back without exposing details to users.
    if response.status_code in (403, 404):
        raise requests.HTTPError(
            f"{response.status_code} for {url}",
            response=response,
        )

    response.raise_for_status()
    return response.json()


def fetch_kev_items(limit: int = 10) -> Tuple[List[Dict[str, str]], str]:
    """
    Fetch KEV items from CISA (preferred) with NVD as a fallback.

    Returns:
        (items, source_tag)
        - items: list[dict] with keys: "title", "date", "link"
        - source_tag: one of "cisa_json", "nvd_hasKev", or "fallback"

    Args:
        limit: maximum number of items to return (clamped [1, 50])

    OWASP:
      - A05 (Security Misconfiguration):
          * limit is clamped to avoid unbounded processing.
      - A09 (Security Logging & Monitoring):
          * Exceptions are logged; UI only gets a generic "fallback" tag.
      - A03 (Injection):
          * No user input influences URLs or query structure.
    """
    # Clamp limit to a safe, predictable range
    try:
        limit_int = int(limit)
    except (TypeError, ValueError):
        logger.warning("Invalid limit=%r; falling back to 10", limit)
        limit_int = 10

    limit_int = max(1, min(limit_int, 50))

    last_err: Exception | None = None

    # ---------------------------
    # 1) Try CISA KEV JSON feeds
    # ---------------------------
    for url in CISA_KEV_JSONS:
        try:
            data = _get_json(url)
            vulns = (
                data.get("vulnerabilities")
                or data.get("known_exploited_vulnerabilities")
                or []
            )

            items: List[Dict[str, str]] = []
            for v in vulns[:limit_int]:
                cve = v.get("cveID") or v.get("cve_id") or ""
                date = (v.get("dateAdded") or v.get("date_added") or "")[:10]

                items.append(
                    {
                        "title": cve or (v.get("vendorProject") or "CISA KEV"),
                        "date": date,
                        "link": (
                            f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                            f"?search_api_fulltext={cve}"
                            if cve
                            else "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                        ),
                    }
                )

            if items:
                return items, "cisa_json"

        except Exception as ex:  # broad, but we log and fall back gracefully
            last_err = ex
            logger.warning("Failed to fetch CISA KEV from %s: %s", url, ex)
            # brief backoff to avoid hammering upstream if something is wrong
            time.sleep(0.2)

    # ---------------------------
    # 2) Fallback: NVD hasKev API
    # ---------------------------
    try:
        data = _get_json(NVD_KEV_API)
        results = data.get("vulnerabilities", [])

        items: List[Dict[str, str]] = []
        for obj in results[:limit_int]:
            cve_obj = obj.get("cve", {}) or {}
            cve = cve_obj.get("id") or ""
            pub = cve_obj.get("published") or ""

            items.append(
                {
                    "title": cve or "NVD hasKev",
                    "date": pub[:10],
                    "link": (
                        f"https://nvd.nist.gov/vuln/detail/{cve}"
                        if cve
                        else "https://nvd.nist.gov/"
                    ),
                }
            )

        if items:
            return items, "nvd_hasKev"

    except Exception as ex:
        last_err = ex
        logger.warning("Failed to fetch NVD hasKev feed: %s", ex)

    # ---------------------------
    # 3) Final fallback: static item
    # ---------------------------
    if last_err:
        # We log the detailed error but *do not* leak it into the
        # returned source label to avoid information disclosure (A05).
        logger.error("All KEV feeds failed, serving static fallback: %s", last_err)

    return (
        [
            {
                "title": "No KEV feed available",
                "date": "",
                "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }
        ],
        "fallback",
    )
