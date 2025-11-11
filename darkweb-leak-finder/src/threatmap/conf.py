# src/threatmap/conf.py
# Centralized settings for the threatmap app.

from django.conf import settings

DEFAULTS = {
    "PROVIDER": "cloudflare",
    "CACHE_SECONDS": 600,
    "POINT_LIMIT": 15,
    "AUTO_REFRESH_MS": 0,
}

def conf_get(name: str):
    """
    Read a THREATMAP setting from Django settings with sane defaults.
    Usage: conf_get("POINT_LIMIT")
    """
    user = getattr(settings, "THREATMAP", {})
    return user.get(name, DEFAULTS[name])
