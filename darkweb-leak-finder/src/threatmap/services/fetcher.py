# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/threatmap/services/fetcher.py
"""
Fetcher: thin layer between views and providers.
- Reads config (provider, ttl, limit)
- Accepts an optional `source` (e.g., 'layer7_origin', 'layer7_target', 'layer3_origin', 'layer3_target')
- Caches results PER (provider, source, limit) to avoid cross-pollution
- Delegates the actual retrieval to the selected provider
"""

from __future__ import annotations

from django.core.cache import cache
from ..conf import conf_get
from ..providers.cloudflare import CloudflareRadarProvider

# Registered data providers. Add more here (e.g., AbuseIpdbProvider) as your project grows.
PROVIDERS = {
    "cloudflare": CloudflareRadarProvider(),
}

def get_points(source: str | None = None) -> list:
    """
    Return heatmap points from the configured provider.

    Args:
        source: Optional selector that the provider understands (e.g., 'layer7_origin').
                If None, the provider will use its default (typically L7 origin).

    Returns:
        A list of point objects compatible with your front-end:
          [{ "lat": float, "lon": float, "intensity": float, ...}, ...]
        (If your provider returns tuples, the front-end tolerates that too.)
    """
    provider_key = conf_get("PROVIDER")
    ttl   = conf_get("CACHE_SECONDS")
    limit = conf_get("POINT_LIMIT")

    # Cache is segmented by provider + source + limit to keep results independent.
    cache_key = f"threatmap:{provider_key}:{source or 'default'}:{limit}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    provider = PROVIDERS.get(provider_key)
    if provider is None:
        # Defensive fallback: unknown provider key -> return empty list
        return []

    # Pass source and limit to the provider (provider decides how to map `source` to an API endpoint)
    points = provider.fetch_points(limit=limit, source=source)

    # Store in cache
    cache.set(cache_key, points, ttl)
    return points
