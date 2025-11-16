# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# ThreatMap service entry point:
#   - Chooses the active threat data provider (e.g., Cloudflare Radar)
#   - Applies simple caching
#   - Returns normalized point data for the front-end heatmap.
#
# OWASP Top 10 considerations:
#   - A01 (Broken Access Control)
#       This module does NOT perform auth itself; any HTTP views calling
#       get_points() must be protected with @login_required or equivalent.
#   - A05 (Security Misconfiguration)
#       Uses configuration + cache; defensive defaults are applied if config
#       values are missing or malformed.
#   - A09 (Security Logging & Monitoring Failures)
#       Provider-specific logging is handled in the provider modules; this
#       orchestrator avoids leaking sensitive configuration details.

from __future__ import annotations

from typing import Any, List

from django.core.cache import cache

from ..conf import conf_get
from ..providers.cloudflare import CloudflareRadarProvider


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------
# As the project grows, additional providers (e.g., AbuseIPDB, custom feeds)
# can be added here and referenced by config.THREATMAP["PROVIDER"].
PROVIDERS = {
    "cloudflare": CloudflareRadarProvider(),
}


def _safe_limit(raw_limit: Any, default: int = 50, max_limit: int = 200) -> int:
    """
    Defensive helper: coerce configured POINT_LIMIT into a sane integer.

    - Avoids excessively large limits that could stress the provider or server.
    - Applies a hard upper bound to reduce resource abuse risk (A05/A10).
    """
    try:
        value = int(raw_limit)
    except (TypeError, ValueError):
        value = default
    if value < 1:
        value = default
    return min(value, max_limit)


def _safe_ttl(raw_ttl: Any, default: int = 300) -> int:
    """
    Defensive helper: coerce CACHE_SECONDS into a positive integer TTL.

    - If the configured TTL is invalid or <= 0, fall back to a modest default.
    """
    try:
        value = int(raw_ttl)
    except (TypeError, ValueError):
        value = default
    if value <= 0:
        value = default
    return value


def get_points(source: str | None = None) -> List[dict]:
    """
    Resolve the configured provider, fetch points, and apply caching.

    Args:
        source:
            Optional selector that the provider understands
            (e.g., 'layer7_origin', 'layer3_target'). If None, the provider
            uses its own default (typically L7 origin).

    Returns:
        List of point dicts compatible with the front-end heatmap:
          [
            {
              "lat": float,
              "lon": float,
              "intensity": float,
              "country": "US",
              "metric": float,
              "layer": "L7" | "L3",
              "direction": "origin" | "target",
            },
            ...
          ]

    OWASP Top 10 touchpoints:
      - A05/A10:
          * Validates and bounds POINT_LIMIT and CACHE_SECONDS so a bad config
            cannot cause excessive load or disable caching entirely.
      - A09:
          * Any deeper logging is handled in the provider (e.g., Cloudflare
            adapter). This function intentionally does not log configuration
            values like provider keys or cache contents.
    """
    # Read provider key and cache options from the THREATMAP config.
    provider_key = conf_get("PROVIDER")
    ttl_raw = conf_get("CACHE_SECONDS")
    limit_raw = conf_get("POINT_LIMIT")

    # Defensive defaults if config is missing or malformed.
    if not provider_key:
        # Unknown provider: safest behavior is to return no live data.
        return []

    ttl = _safe_ttl(ttl_raw, default=300)
    limit = _safe_limit(limit_raw, default=50, max_limit=200)

    # Cache segmentation: provider + source + limit
    # (prevents cross-contamination between different views/settings)
    cache_source = source or "default"
    cache_key = f"threatmap:{provider_key}:{cache_source}:{limit}"

    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    provider = PROVIDERS.get(provider_key)
    if provider is None:
        # Defensive guard: misconfigured provider name in settings.
        return []

    # Delegate to the provider; provider is responsible for:
    #   - Mapping source -> external API endpoint(s)
    #   - Handling network errors and logging
    #   - Normalizing the shape of the output
    points = provider.fetch_points(limit=limit, source=source)

    # Store in cache (if ttl reasonably positive)
    if ttl > 0:
        cache.set(cache_key, points, ttl)

    return points
