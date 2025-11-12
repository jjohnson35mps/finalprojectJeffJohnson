# src/threatmap/providers/cloudflare.py
# ------------------------------------------------------------
# Cloudflare Radar provider adapter (Layer-3 DDoS origins)
# Normalizes results into [lat, lon, intensity] for Leaflet heat.
# ------------------------------------------------------------
from __future__ import annotations
import logging
from typing import List
import requests

logger = logging.getLogger(__name__)

# Minimal centroid map for common ISO-2 countries.
# You can expand this as needed.
COUNTRY_COORDS = {
    "US": [37.0902, -95.7129], "CN": [35.8617, 104.1954], "RU": [61.5240, 105.3188],
    "BR": [-14.2350, -51.9253], "IN": [20.5937, 78.9629], "GB": [55.3781, -3.4360],
    "DE": [51.1657, 10.4515], "JP": [36.2048, 138.2529], "FR": [46.2276, 2.2137],
    "CA": [56.1304, -106.3468], "AU": [-25.2744, 133.7751], "KR": [35.9078, 127.7669],
    "NL": [52.1326, 5.2913], "IT": [41.8719, 12.5674], "ES": [40.4637, -3.7492],
    "TR": [38.9637, 35.2433], "MX": [23.6345, -102.5528], "SG": [1.3521, 103.8198],
    "SE": [60.1282, 18.6435], "NO": [60.4720, 8.4689], "PL": [51.9194, 19.1451],
}

# Cloudflare public Radar summary: top attack origins by location (country ISO-2).
RADAR_URL = (
    "https://api.cloudflare.com/client/v4/"
    "radar/attacks/layer3/summary/location/origin"
)

class CloudflareRadarProvider:
    """
    Fetches Cloudflare Radar Layer-3 attack origin summary and converts it
    to heatmap points. Intensity is normalized to 0..1 within the returned window.
    """

    def fetch_points(self, limit: int) -> List[List[float]]:
        try:
            # You can add params like ?since=24h later if desired.
            resp = requests.get(RADAR_URL, timeout=10)
            resp.raise_for_status()
            payload = resp.json() or {}
            result = (payload.get("result") or [])[:limit]

            # Guard: if schema shifts or empty
            if not isinstance(result, list) or not result:
                logger.warning("Cloudflare Radar: empty or unexpected result shape: %s", payload)
                return self._fallback()

            # Normalize intensity by the max "value" seen.
            max_val = max((float(r.get("value", 0)) for r in result), default=0.0) or 1.0
            points: List[List[float]] = []

            for row in result:
                iso = (row.get("location") or "").upper()
                val = float(row.get("value", 0))
                coords = COUNTRY_COORDS.get(iso)
                if not coords:
                    # Skip unknown ISO-2 codes until you add them above.
                    continue
                intensity = min(val / max_val, 1.0)
                points.append([coords[0], coords[1], round(intensity, 3)])

            # If everything skipped due to unknown ISO codes, provide fallback.
            return points or self._fallback()

        except Exception as exc:
            logger.error("Cloudflare Radar fetch failed: %s", exc)
            return self._fallback()

    @staticmethod
    def _fallback() -> List[List[float]]:
        # Safe sample so the UI doesn't look broken if the API hiccups.
        return [
            [37.0902, -95.7129, 0.9],   # US
            [35.8617, 104.1954, 0.8],   # CN
            [61.5240, 105.3188, 0.7],   # RU
            [41.8719, 12.5674, 0.5],    # IT
        ]
