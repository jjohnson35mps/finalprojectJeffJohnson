# src/security_ticker/services/sources.py

import json
import requests
import time
from pathlib import Path
from django.conf import settings

CACHE_FILE = Path(settings.BASE_DIR) / "data" / "kev_cache.json"
CACHE_TTL = 3600  # seconds = 1 hour
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known-exploited-vulnerabilities.json"

def _load_cache():
    """Load cache from disk if it exists and not expired."""
    if CACHE_FILE.exists():
        stat = CACHE_FILE.stat()
        age = time.time() - stat.st_mtime
        if age < CACHE_TTL:
            with CACHE_FILE.open("r", encoding="utf-8") as f:
                return json.load(f)
    return None

def _save_cache(data):
    """Save fetched data to cache file."""
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with CACHE_FILE.open("w", encoding="utf-8") as f:
        json.dump(data, f)

def fetch_kev_items(limit=10):
    """
    Fetch the KEV catalog list, cache hourly, return latest 'limit' items.
    Returns list of dicts: { 'title', 'subtitle', 'date', 'url' }
    """
    data = _load_cache()
    if data is None:
        resp = requests.get(KEV_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        _save_cache(data)

    vulns = data.get("vulnerabilities", [])
    vulns_sorted = sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)

    items = []
    for entry in vulns_sorted[:limit]:
        items.append({
            "title": entry.get("cveID", ""),
            "subtitle": f"{entry.get('vendorProject', '')} {entry.get('product', '')}".strip(),
            "date": entry.get("dateAdded", ""),
            "url": entry.get("notes", "") or ""
        })
    return items
