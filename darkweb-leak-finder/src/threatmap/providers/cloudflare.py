# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# src/threatmap/services/cloudflare.py
#
# Purpose:
#   Fetch and normalize Cloudflare Radar attack telemetry into a lightweight
#   geo-point format for the ThreatMap heatmap.

from __future__ import annotations

import logging
import os
import random
from typing import List, Dict, Tuple, Any

import requests

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Country centroids (approximate lat/lon for plotting)
# ---------------------------------------------------------------------------
CENTROIDS: Dict[str, Tuple[float, float]] = {
    "US": (37.0902, -95.7129),
    "CN": (35.8617, 104.1954),
    "RU": (61.5240, 105.3188),
    "BR": (-14.2350, -51.9253),
    "IN": (20.5937, 78.9629),
    "GB": (55.3781, -3.4360),
    "DE": (51.1657, 10.4515),
    "JP": (36.2048, 138.2529),
    "FR": (46.2276, 2.2137),
    "CA": (56.1304, -106.3468),
    "AU": (-25.2744, 133.7751),
    "KR": (35.9078, 127.7669),
    "NL": (52.1326, 5.2913),
    "IT": (41.8719, 12.5674),
    "ES": (40.4637, -3.7492),
    "TR": (38.9637, 35.2433),
    "MX": (23.6345, -102.5528),
    "SG": (1.3521, 103.8198),
    "SE": (60.1282, 18.6435),
    "NO": (60.4720, 8.4689),
    "PL": (51.9194, 19.1451),
}


# ---------------------------------------------------------------------------
# Cloudflare Radar endpoints per visualization "source"
#   key -> (endpoint path, country code field in each row)
# ---------------------------------------------------------------------------
LAYER_URLS: Dict[str, Tuple[str, str]] = {
    "layer7_origin": ("radar/attacks/layer7/top/locations/origin", "originCountryAlpha2"),
    "layer7_target": ("radar/attacks/layer7/top/locations/target", "targetCountryAlpha2"),
    "layer3_origin": ("radar/attacks/layer3/top/locations/origin", "originCountryAlpha2"),
    "layer3_target": ("radar/attacks/layer3/top/locations/target", "targetCountryAlpha2"),
}

API_BASE = "https://api.cloudflare.com/client/v4/"


class CloudflareRadarProvider:
    """
    Adapter for Cloudflare Radar "top locations" APIs.

    Responsibilities:
      * Build the correct endpoint + query params for each layer/source.
      * Call Cloudflare with a bearer token from the environment.
      * Normalize the JSON response into a list of heatmap points:
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
      - A01: Broken Access Control
          * This class is a backend service; callers should ensure that any
            HTTP view using it is protected by appropriate auth decorators.
      - A05: Security Misconfiguration
          * Uses an API token from environment variables (no hard-coded secrets).
          * When token is missing, we return non-live fallback data instead
            of making unauthenticated calls.
      - A06: Vulnerable & Outdated Components
          * Uses the `requests` library with explicit timeouts to avoid
            indefinite hangs and basic error handling on non-2xx responses.
      - A09: Security Logging & Monitoring Failures
          * Logs failures at warning/error without logging secrets (token
            is only sent in headers and not echoed).
    """

    def __init__(self, token: str | None = None) -> None:
        """
        Initialize the provider with an optional API token.

        If no token is provided explicitly, we read it from:
          CLOUDFLARE_API_TOKEN
        """
        # NOTE: token is never logged; only used in the Authorization header.
        self.token = token or os.getenv("CLOUDFLARE_API_TOKEN")

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------
    def _url_for(self, source: str | None) -> Tuple[str, str]:
        """
        Map a logical 'source' (e.g. 'layer7_origin') to:
            (full_url, country_field_name)
        """
        endpoint, country_field = LAYER_URLS.get(
            source or "layer7_origin",
            LAYER_URLS["layer7_origin"],
        )
        return f"{API_BASE}{endpoint}", country_field

    def _extract_rows(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract the rows array from a Radar response.

        Radar wraps arrays differently across endpoints/versions. We try
        several known keys, then fall back to "first list-like value under
        'result'".
        """
        result = payload.get("result") or {}

        # Preferred/known keys for top-location data
        for key in ("attacks_origin", "attacks_target", "top_locations", "series", "data"):
            value = result.get(key)
            if isinstance(value, list):
                return value

        # Last resort: first list under result
        for value in result.values():
            if isinstance(value, list):
                return value

        return []

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------
    def fetch_points(
        self,
        limit: int,
        source: str | None = None,
        date_range: str = "1d",
    ) -> List[Dict[str, Any]]:
        """
        Fetch and normalize points from Cloudflare Radar.

        Args:
            limit:       Max number of points to return.
            source:      Logical key (e.g. 'layer7_origin', 'layer3_target').
            date_range:  Radar date range (e.g. '1d', '7d').

        Returns:
            A list of normalized point dictionaries suitable for the Leaflet
            heatmap client.

        Error handling:
            * On any error (network, auth, parsing), we log the issue and
              return a static fallback so the front-end can still render
              something.
        """
        try:
            url, country_field = self._url_for(source)

            # -----------------------------
            # Authorization header
            # -----------------------------
            headers: Dict[str, str] = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                # No token -> we cannot safely call Cloudflare; fallback only.
                logger.error("CLOUDFLARE_API_TOKEN not set; using fallback data")
                return self._fallback(source)

            # -----------------------------
            # Required 'name' parameter
            #   origin -> attacks_origin
            #   target -> attacks_target
            # -----------------------------
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

            # Explicit timeout helps avoid resource exhaustion issues.
            response = requests.get(url, headers=headers, params=params, timeout=12)

            if not response.ok:
                # Log status and first chunk of body for debugging;
                # Cloudflare Radar data is public threat telemetry, but we
                # still avoid logging the entire payload.
                logger.error(
                    "Cloudflare Radar HTTP %s for %s: %s",
                    response.status_code,
                    response.url,
                    response.text[:400],
                )
                response.raise_for_status()

            payload: Dict[str, Any] = response.json() or {}
            rows = self._extract_rows(payload)

            if not rows:
                logger.warning("Cloudflare Radar: empty/unknown response shape for %s", url)
                return self._fallback(source)

            layer = "L7" if "layer7" in url else "L3"
            direction = "origin" if "origin" in url else "target"

            # -----------------------------
            # Normalize intensity
            # -----------------------------
            max_val = max(
                (float(row.get("value") or 0) for row in rows),
                default=0.0,
            ) or 1.0

            points: List[Dict[str, Any]] = []
            for row in rows[:limit]:
                cc = (row.get(country_field) or "").upper()
                if not cc or cc not in CENTROIDS:
                    # Skip unknown/unsupported country codes
                    continue

                raw_val = float(row.get("value") or 0)
                lat, lon = CENTROIDS[cc]

                # Relative intensity (0.2–1.0 range)
                rel = (raw_val / max_val) if max_val else 0.0
                intensity = max(0.2, min(1.0, rel))

                points.append(
                    {
                        # Small jitter around centroid so dots don’t perfectly overlap
                        "lat": lat + random.uniform(-0.7, 0.7),
                        "lon": lon + random.uniform(-0.7, 0.7),
                        "intensity": round(float(intensity), 3),
                        "country": cc,
                        "metric": round(float(raw_val), 3),
                        "layer": layer,
                        "direction": direction,
                    }
                )

            if not points:
                logger.warning("Cloudflare Radar produced no mappable rows for %s", url)
                return self._fallback(source)

            return points

        except Exception as exc:
            # Generic catch-all so the front-end never hard-fails on radar issues.
            logger.error("Cloudflare Radar fetch failed: %s", exc)
            return self._fallback(source)

    # -----------------------------------------------------------------------
    # Fallback data when live Radar is unavailable
    # -----------------------------------------------------------------------
    @staticmethod
    def _fallback(source: str | None = None) -> List[Dict[str, Any]]:
        """
        Static sample points used when the live Radar feed is unavailable.

        This ensures the front-end has something to render instead of a blank map.
        """
        sample: List[Dict[str, Any]] = [
            {
                "lat": 37.0902,
                "lon": -95.7129,
                "intensity": 0.9,
                "country": "US",
                "metric": 25.0,
                "layer": "L7",
                "direction": "origin",
            },
            {
                "lat": 35.8617,
                "lon": 104.1954,
                "intensity": 0.8,
                "country": "CN",
                "metric": 22.0,
                "layer": "L7",
                "direction": "origin",
            },
            {
                "lat": 61.5240,
                "lon": 105.3188,
                "intensity": 0.7,
                "country": "RU",
                "metric": 18.0,
                "layer": "L7",
                "direction": "origin",
            },
            {
                "lat": 41.8719,
                "lon": 12.5674,
                "intensity": 0.5,
                "country": "IT",
                "metric": 10.0,
                "layer": "L7",
                "direction": "origin",
            },
        ]

        # Adjust layer/direction to roughly match the requested source
        if source and "layer3" in source:
            for s in sample:
                s["layer"] = "L3"
        if source and "target" in source:
            for s in sample:
                s["direction"] = "target"

        return sample
