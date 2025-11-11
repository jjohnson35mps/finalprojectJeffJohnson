# src/threatmap/providers/cloudflare.py
# ------------------------------------------------------------
# Cloudflare Radar provider adapter
# Returns points as [lat, lon, intensity] for the heat layer.
# ------------------------------------------------------------
from __future__ import annotations

import logging
from typing import List
import requests  # make sure 'requests' is installed in your venv: pip install requests

logger = logging.getLogger(__name__)

# Very small centroid map for demo; expand as needed
COUNTRY_COORDS = {
    "US": [37.0902, -95.7129],
    "CN": [35.8617, 104.1954],
    "RU": [61.5240, 105.3188],
    "BR": [-14.2350, -51.9253],
    "IN": [20.5937, 78.9629],
    "GB": [55.3781, -3.4360],
    "DE": [51.1657, 10.4515],
    "JP": [36.2048, 138.2529],
    "FR": [46.2276, 2.2137],
}

RADAR_URL = (
    "https://api.cloudflare.com/client/v4/"
    "radar/attacks/layer3/summary/location/origin"
)

class CloudflareRadarProvider:
    """
    Provider that fetches Cloudflare Radar Layer-3 attack origin summary
    and normalizes it into heatmap points.
    """

    def fetch_points(self, limit: int) -> List[List[float]]:
        try:
            resp = requests.get(RADAR_URL, timeout=10)
            resp.raise_for_status()
            result = (resp.json() or {}).get("result", [])[:limit]

            max_val = max((r.get("value", 1) for r in result), default=1)
            points: List[List[float]] = []

            for entry in result:
                iso = entry.get("location")
                val = float(entry.get("value", 0))
                coords = COUNTRY_COORDS.get(iso)
                if not coords:
                    continue
                intensity = 1.0 if max_val == 0 else min(val / max_val, 1.0)
                points.append([coords[0], coords[1], round(intensity, 3)])

            return points

        except Exception as exc:
            logger.error("Cloudflare Radar fetch failed: %s", exc)
            # Safe fallback so the UI still renders
            return [
                [37.0902, -95.7129, 0.9],
                [35.8617, 104.1954, 0.8],
                [61.5240, 105.3188, 0.7],
            ]
