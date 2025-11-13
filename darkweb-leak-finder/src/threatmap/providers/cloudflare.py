# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/threatmap/providers/cloudflare.py

from __future__ import annotations
import logging, os, random
from typing import List, Dict, Tuple, Any
import requests

logger = logging.getLogger(__name__)

CENTROIDS: Dict[str, Tuple[float, float]] = {
    "US": (37.0902, -95.7129), "CN": (35.8617, 104.1954), "RU": (61.5240, 105.3188),
    "BR": (-14.2350, -51.9253), "IN": (20.5937, 78.9629), "GB": (55.3781, -3.4360),
    "DE": (51.1657, 10.4515), "JP": (36.2048, 138.2529), "FR": (46.2276, 2.2137),
    "CA": (56.1304, -106.3468), "AU": (-25.2744, 133.7751), "KR": (35.9078, 127.7669),
    "NL": (52.1326, 5.2913), "IT": (41.8719, 12.5674), "ES": (40.4637, -3.7492),
    "TR": (38.9637, 35.2433), "MX": (23.6345, -102.5528), "SG": (1.3521, 103.8198),
    "SE": (60.1282, 18.6435), "NO": (60.4720, 8.4689), "PL": (51.9194, 19.1451),
}

LAYER_URLS: Dict[str, Tuple[str, str]] = {
    "layer7_origin": ("radar/attacks/layer7/top/locations/origin", "originCountryAlpha2"),
    "layer7_target": ("radar/attacks/layer7/top/locations/target", "targetCountryAlpha2"),
    "layer3_origin": ("radar/attacks/layer3/top/locations/origin", "originCountryAlpha2"),
    "layer3_target": ("radar/attacks/layer3/top/locations/target", "targetCountryAlpha2"),
}
API_BASE = "https://api.cloudflare.com/client/v4/"

class CloudflareRadarProvider:
    def __init__(self, token: str | None = None):
        # 👇 env var name: set this before running `runserver`
        #   PowerShell example:
        #   $env:CLOUDFLARE_API_TOKEN = "your_token_here"
        self.token = token or os.getenv("CLOUDFLARE_API_TOKEN")

    def _url_for(self, source: str | None) -> Tuple[str, str]:
        endpoint, country_field = LAYER_URLS.get(source or "layer7_origin", LAYER_URLS["layer7_origin"])
        return f"{API_BASE}{endpoint}", country_field

    def _extract_rows(self, payload: dict) -> list[dict]:
        """
        Radar wraps arrays differently across endpoints/versions.
        Try common keys first; then fall back to 'first list in result'.
        """
        result = payload.get("result") or {}
        # Official Radar names for top locations: attacks_origin / attacks_target
        for k in ("attacks_origin", "attacks_target", "top_locations", "series", "data"):
            v = result.get(k)
            if isinstance(v, list):
                return v
        # Last resort: first list-like value under result
        for v in result.values():
            if isinstance(v, list):
                return v
        return []

    def fetch_points(self, limit: int, source: str | None = None, date_range: str = "1d") -> List[dict]:
        try:
            url, country_field = self._url_for(source)

            # ---------- Authorization header ----------
            headers = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                logger.error("CLOUDFLARE_API_TOKEN not set; using fallback data")
                return self._fallback(source)

            # ---------- 'name' param is REQUIRED by Radar ----------
            # origin -> attacks_origin, target -> attacks_target
            if "origin" in (source or ""):
                name = "attacks_origin"
            elif "target" in (source or ""):
                name = "attacks_target"
            else:
                name = "attacks_origin"

            params = {
                "name": name,
                "dateRange": date_range,
                "limit": limit,
                "format": "json",
            }

            r = requests.get(url, headers=headers, params=params, timeout=12)

            # 👇 this is the bit you asked about
            if not r.ok:
                logger.error(
                    "Cloudflare response body (HTTP %s) for %s: %s",
                    r.status_code,
                    r.url,
                    r.text[:500],  # first 500 chars for debugging
                )
                r.raise_for_status()

            payload = r.json() or {}
            rows = self._extract_rows(payload)
            if not rows:
                logger.warning("Cloudflare Radar: empty/unknown shape for %s", url)
                return self._fallback(source)

            layer = "L7" if "layer7" in url else "L3"
            direction = "origin" if "origin" in url else "target"

            # Normalize intensity relative to max 'value'
            max_val = max((float((row.get("value") or 0)) for row in rows), default=0.0) or 1.0
            out: List[dict] = []
            for row in rows[:limit]:
                cc = (row.get(country_field) or "").upper()
                if not cc or cc not in CENTROIDS:
                    continue
                val = float(row.get("value") or 0)
                lat, lon = CENTROIDS[cc]
                rel = min(1.0, (val / max_val) if max_val else 0.0)
                intensity = max(0.2, rel)
                out.append({
                    "lat": lat + random.uniform(-0.7, 0.7),
                    "lon": lon + random.uniform(-0.7, 0.7),
                    "intensity": round(float(intensity), 3),
                    "country": cc,
                    "metric": round(float(val), 3),
                    "layer": layer,
                    "direction": direction,
                })
            if not out:
                logger.warning("Cloudflare Radar produced no mappable rows for %s", url)
                return self._fallback(source)
            return out

        except Exception as exc:
            logger.error("Cloudflare Radar fetch failed: %s", exc)
            return self._fallback(source)

    @staticmethod
    def _fallback(source: str | None = None) -> List[dict]:
        sample = [
            {"lat": 37.0902, "lon": -95.7129, "intensity": 0.9, "country": "US", "metric": 25.0, "layer": "L7", "direction": "origin"},
            {"lat": 35.8617, "lon": 104.1954, "intensity": 0.8, "country": "CN", "metric": 22.0, "layer": "L7", "direction": "origin"},
            {"lat": 61.5240, "lon": 105.3188, "intensity": 0.7, "country": "RU", "metric": 18.0, "layer": "L7", "direction": "origin"},
            {"lat": 41.8719, "lon": 12.5674, "intensity": 0.5, "country": "IT", "metric": 10.0, "layer": "L7", "direction": "origin"},
        ]
        if source and "layer3" in source:
            for s in sample: s["layer"] = "L3"
        if source and "target" in source:
            for s in sample: s["direction"] = "target"
        return sample
