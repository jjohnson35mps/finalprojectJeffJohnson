# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# ThreatMap configuration helper
#
# Purpose:
#   - Centralize reads of THREATMAP-related settings from Django settings.py
#   - Provide safe defaults when values are not configured
#
# OWASP Top 10 touchpoints:
#   - A05:2021 Security Misconfiguration:
#       * Avoids crashing on missing THREATMAP block by using defaults.
#       * Fails fast with a clear error if an unknown setting key is requested
#         (prevents silent misconfiguration).
#   - Secrets:
#       * This module does NOT expose or manipulate secrets (tokens/keys).
#         Those should remain in settings/.env and never be printed or logged
#         from here.

from django.conf import settings

#: Default ThreatMap configuration.
#: Only non-sensitive values (no API tokens / secrets here).
DEFAULTS = {
    "PROVIDER": "cloudflare",  # which provider implementation to use
    "CACHE_SECONDS": 600,      # server-side cache TTL for point data
    "POINT_LIMIT": 15,         # max number of points returned per fetch
    "AUTO_REFRESH_MS": 0,      # optional client auto-refresh override
}


def conf_get(name: str):
    """
    Fetch a ThreatMap setting from Django settings with sane defaults.

    Usage:
        provider = conf_get("PROVIDER")
        ttl      = conf_get("CACHE_SECONDS")

    Resolution order:
        1. settings.THREATMAP.get(name, <default>)
        2. DEFAULTS[name] if not explicitly provided

    Raises:
        KeyError: if `name` is not defined in DEFAULTS (fail-fast on typos).
    """
    if name not in DEFAULTS:
        # Fail fast instead of silently returning None for unknown keys.
        # This helps avoid subtle misconfigurations in production.
        raise KeyError(f"Unknown THREATMAP setting: {name!r}")

    # Gracefully handle absence of THREATMAP block in settings.py.
    user_cfg = getattr(settings, "THREATMAP", {}) or {}

    # Return user override if present, otherwise the hard-coded default.
    return user_cfg.get(name, DEFAULTS[name])
