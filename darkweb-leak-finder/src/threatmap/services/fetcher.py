# src/threatmap/services/fetcher.py
from django.core.cache import cache
from ..conf import conf_get
from ..providers.cloudflare import CloudflareRadarProvider

PROVIDERS = {
    "cloudflare": CloudflareRadarProvider(),
}

def get_points() -> list[list[float]]:
    provider_key = conf_get("PROVIDER")
    ttl = conf_get("CACHE_SECONDS")
    limit = conf_get("POINT_LIMIT")

    cache_key = f"threatmap:{provider_key}:{limit}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    provider = PROVIDERS[provider_key]
    points = provider.fetch_points(limit=limit)
    cache.set(cache_key, points, ttl)
    return points
