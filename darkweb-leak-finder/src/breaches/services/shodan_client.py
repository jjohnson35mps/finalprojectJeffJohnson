# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/breaches/services/shodan_client.py
from __future__ import annotations
import os
import time
import socket
import logging
import ipaddress
from typing import Dict, Any, Optional

import requests

logger = logging.getLogger("breaches.shodan")

# Prefer Django settings when available (loads from settings.SHODAN_API_KEY)
try:
    from django.conf import settings  # type: ignore
    SHODAN_API_KEY = getattr(settings, "SHODAN_API_KEY", None)
except Exception:
    SHODAN_API_KEY = None

# fallback to environment if settings not present or key not set there
if not SHODAN_API_KEY:
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"


class ShodanError(Exception):
    """Raised for config/errors calling Shodan API."""


def _is_ip(value: str) -> bool:
    """Return True if the value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def _resolve_to_ip(target: str) -> str:
    """
    Resolve hostname to IP or return the IP unchanged.
    Raises socket.gaierror on resolution failure.
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


def fetch_host(target: str, timeout: int = 10, retries: int = 2) -> Optional[Dict[str, Any]]:
    """
    Query Shodan Host API for the given domain or IP.
    Returns the parsed JSON dict on success, None if Shodan has no host data (404),
    or raises ShodanError on configuration / network / API errors.

    Usage:
        data = fetch_host("8.8.8.8")
        if data is None:
            # no data found
    """
    if not SHODAN_API_KEY:
        raise ShodanError("SHODAN_API_KEY not configured. Set in settings or environment.")

    # Resolve to an IP (or validate the supplied IP)
    try:
        ip = _resolve_to_ip(target)
    except socket.gaierror as e:
        raise ShodanError(f"DNS resolution failed for '{target}': {e}") from e
    except Exception as e:
        raise ShodanError(f"Failed to resolve '{target}': {e}") from e

    url = SHODAN_HOST_URL.format(ip=ip, key=SHODAN_API_KEY)
    attempt = 0
    while attempt <= retries:
        try:
            logger.debug("Shodan request attempt=%s url=%s", attempt, url)
            resp = requests.get(url, timeout=timeout)
            # 404 -> Shodan has no data for this host
            if resp.status_code == 404:
                logger.info("Shodan: no data for %s (404)", ip)
                return None
            resp.raise_for_status()
            data = resp.json()
            # add an explicit ip_str if missing, for convenience
            if "ip_str" not in data and "ip" in data:
                data["ip_str"] = str(data["ip"])
            return data

        except requests.HTTPError as e:
            status = getattr(e.response, "status_code", None)
            # handle rate limit with exponential backoff
            if status == 429 and attempt < retries:
                wait = 2 ** attempt
                logger.warning("Shodan rate limited (429). Retrying in %s s", wait)
                time.sleep(wait)
                attempt += 1
                continue
            logger.error("Shodan HTTP error for %s: %s", ip, e)
            raise ShodanError(f"Shodan API error: {e}") from e
        except requests.RequestException as e:
            # network error / timeout
            if attempt < retries:
                logger.warning("Shodan network error: %s; retrying (%s/%s)", e, attempt + 1, retries)
                time.sleep(1)
                attempt += 1
                continue
            logger.exception("Shodan request failed after retries for %s", ip)
            raise ShodanError(f"Network error when calling Shodan: {e}") from eexit
