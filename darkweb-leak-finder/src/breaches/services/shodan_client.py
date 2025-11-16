# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# Shodan client helper
# --------------------
# - Looks up a host in Shodan by IP/hostname.
# - Central place to handle config, retries, and error mapping.
# - OWASP-relevant notes:
#   * Secrets are loaded from env/Django settings (A02: Security Misconfiguration).
#   * Input is validated/normalized to IPs (A06: Insecure Design).
#   * Timeouts & retry/backoff for robustness (A10: Mishandling of Exceptional Conditions).
#   * Logs avoid leaking secrets/PII (A09: Logging & Alerting Failures).

from __future__ import annotations

import os
import time
import socket
import logging
import ipaddress
from typing import Dict, Any, Optional

import requests

# Module-level logger – use "breaches.shodan" so logging config can
# route these messages (A09: centralized logging & monitoring).
logger = logging.getLogger("breaches.shodan")

# ------------------------------------------------------------
# Configuration: obtain SHODAN_API_KEY securely
# ------------------------------------------------------------
# Prefer Django settings (for deployed web app) and fall back to
# environment variables for CLIs/tests. This keeps secrets out of
# source code and under environment/config management.
# (OWASP A02: no hard-coded secrets, secure configuration.)
try:
    from django.conf import settings  # type: ignore
    SHODAN_API_KEY = getattr(settings, "SHODAN_API_KEY", None)
except Exception:
    SHODAN_API_KEY = None

# Fallback to environment if settings not present or key not set there.
if not SHODAN_API_KEY:
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")

# Base URL template for Shodan host lookups
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"


class ShodanError(Exception):
    """Raised for configuration, network, or API errors when calling Shodan."""


# ------------------------------------------------------------
# Helper: IP validation
# ------------------------------------------------------------
def _is_ip(value: str) -> bool:
    """Return True if the value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


# ------------------------------------------------------------
# Helper: hostname -> IP resolution
# ------------------------------------------------------------
def _resolve_to_ip(target: str) -> str:
    """
    Resolve hostname to IP or return the IP unchanged.

    - If `target` is already a valid IP (v4/v6), return it as-is (no DNS call).
    - Otherwise, call DNS (socket.gethostbyname) and return the IPv4 address.
    - Raises socket.gaierror on resolution failure.

    OWASP tie-in (A06 Insecure Design / A10 Errors):
    - Keeps network logic in one place and lets callers map low-level
      errors to user-friendly messages without exposing internals.
    """
    # If target already an IP (v4 or v6), return it (avoids DNS call)
    if _is_ip(target):
        return target

    # Otherwise attempt DNS resolution (returns IPv4 by default)
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        # re-raise so callers can provide user-friendly messages
        raise


# ------------------------------------------------------------
# Public API: fetch host details from Shodan
# ------------------------------------------------------------
def fetch_host(target: str, timeout: int = 10, retries: int = 2) -> Optional[Dict[str, Any]]:
    """
    Query the Shodan Host API for the given domain or IP.

    Args:
        target: IP address or hostname to look up.
        timeout: Per-request timeout in seconds (network safety).
        retries: Number of retry attempts on transient failures.

    Returns:
        - Parsed JSON dict on success.
        - None if Shodan has no host data (404).
        - Raises ShodanError on configuration / network / API errors.

    Usage:
        data = fetch_host("8.8.8.8")
        if data is None:
            # No data found for this host.

    OWASP tie-ins:
        - A02 Security Misconfiguration: requires SHODAN_API_KEY to be configured
          in settings/env; no secrets in code.
        - A10 Mishandling of Exceptional Conditions: clear exception type,
          rate-limit/backoff, and well-defined return values.
        - A09 Logging: logs events/errors without leaking secrets.
    """
    # Ensure we have an API key configured before making external calls.
    if not SHODAN_API_KEY:
        raise ShodanError("SHODAN_API_KEY not configured. Set in settings or environment.")

    # Resolve to an IP (or validate the supplied IP)
    try:
        ip = _resolve_to_ip(target)
    except socket.gaierror as e:
        # Wrap low-level DNS error into domain-specific exception
        raise ShodanError(f"DNS resolution failed for '{target}': {e}") from e
    except Exception as e:
        raise ShodanError(f"Failed to resolve '{target}': {e}") from e

    # Build request URL. We keep the real URL internal and log a redacted
    # version so the API key does not end up in logs.
    url = SHODAN_HOST_URL.format(ip=ip, key=SHODAN_API_KEY)
    safe_url = SHODAN_HOST_URL.format(ip=ip, key="***")  # mask secret in logs

    attempt = 0
    while attempt <= retries:
        try:
            # Debug logging shows which host is queried without exposing API key.
            logger.debug("Shodan request attempt=%s url=%s", attempt, safe_url)

            # Network call to Shodan; timeout prevents hangs (A10).
            resp = requests.get(url, timeout=timeout)

            # 404 -> Shodan has no data for this host; treat as a clean "no result"
            if resp.status_code == 404:
                logger.info("Shodan: no data for %s (404)", ip)
                return None

            # For any other non-2xx status, raise HTTPError for handling below.
            resp.raise_for_status()

            data = resp.json()

            # Add an explicit ip_str if missing, for convenience in templates/UI.
            if "ip_str" not in data and "ip" in data:
                data["ip_str"] = str(data["ip"])

            return data

        except requests.HTTPError as e:
            status = getattr(e.response, "status_code", None)

            # Handle rate limit with simple exponential backoff (A10 / A09).
            if status == 429 and attempt < retries:
                wait = 2 ** attempt
                logger.warning("Shodan rate limited (429) for %s. Retrying in %s s", ip, wait)
                time.sleep(wait)
                attempt += 1
                continue

            # For other HTTP errors, log and wrap in ShodanError.
            logger.error("Shodan HTTP error for %s: %s", ip, e)
            raise ShodanError(f"Shodan API error: {e}") from e

        except requests.RequestException as e:
            # Network error / timeout; we retry a few times, then fail fast.
            if attempt < retries:
                logger.warning(
                    "Shodan network error for %s: %s; retrying (%s/%s)",
                    ip, e, attempt + 1, retries
                )
                time.sleep(1)
                attempt += 1
                continue

            # After max retries, log with traceback and surface a clean error.
            logger.exception("Shodan request failed after retries for %s", ip)
            raise ShodanError(f"Network error when calling Shodan: {e}") from e
