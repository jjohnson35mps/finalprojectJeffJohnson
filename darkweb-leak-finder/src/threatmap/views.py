# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# ThreatMap views
#
# Purpose:
#   - Provide JSON APIs used by the Leaflet-based ThreatMap heatmap.
#   - All endpoints are authenticated and return normalized point data.
#
# OWASP Top 10 touchpoints:
#   - A01:2021 – Broken Access Control
#       * All endpoints are wrapped in @login_required so only authenticated
#         users can see attack telemetry.
#   - A03/A05:2021 – Injection / Security Misconfiguration
#       * Only controlled parameters are used (e.g., whitelisted "source").
#       * Responses are JSON only; there’s no template rendering here.
#   - A09:2021 – Security Logging and Monitoring Failures
#       * Any detailed provider/API logging is handled in lower layers
#         (e.g., providers / services modules) rather than here.

from __future__ import annotations

import random
from typing import List, Dict, Optional

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from .conf import conf_get
from .services.fetcher import get_points

# ---------------------------------------------------------------------------
# Constants / configuration
# ---------------------------------------------------------------------------

#: Allowed 'source' values that the Cloudflare provider understands.
#: This prevents arbitrary query strings from being passed straight through.
ALLOWED_SOURCES = {
    "layer7_origin",
    "layer7_target",
    "layer3_origin",
    "layer3_target",
}


# ---------------------------------------------------------------------------
# Live provider-backed heatmap (legacy/simple endpoint)
# ---------------------------------------------------------------------------

@login_required(login_url="login")
@require_GET
def heat_points(request):
    """
    Legacy/simple endpoint that returns:
        {
          "points": [...],
          "autoRefreshMs": <int>
        }

    Currently not wired in URLs by default, but kept for compatibility.

    OWASP:
      - A01 (Broken Access Control): protected via @login_required.
      - A05 (Security Misconfiguration): always uses server-side config
        via conf_get; no client can override timeouts/limits.
    """
    return JsonResponse(
        {
            "points": get_points(),                     # provider+cache-backed points
            "autoRefreshMs": conf_get("AUTO_REFRESH_MS"),
        }
    )


# ---------------------------------------------------------------------------
# Simulated / demo attack points
# ---------------------------------------------------------------------------

@login_required(login_url="login")
@require_GET
def attack_points(request):
    """
    Return simulated attack points for demo or offline scenarios.

    Not typically wired to URLs in production; kept as a development helper.

    OWASP:
      - A01: still authenticated, so not leaking telemetry to the public.
      - A05: no external input is used to generate the data.
    """
    points: List[Dict[str, float]] = []
    for _ in range(50):
        points.append(
            {
                "lat": random.uniform(-60, 75),
                "lon": random.uniform(-180, 180),
                "intensity": random.uniform(0.3, 1.0),
            }
        )
    # `safe=False` because we return a raw list, not a dict
    return JsonResponse(points, safe=False)


# ---------------------------------------------------------------------------
# Main ThreatMap endpoint (used by front-end heatmap.js)
#
#   GET /threatmap/api/points/?source=layer7_origin
#
# Response:
#   {
#     "points": [...],
#     "autoRefreshMs": <int>
#   }
# ---------------------------------------------------------------------------

@login_required(login_url="login")
@require_GET
def threat_points(request):
    """
    Primary JSON endpoint used by the ThreatMap front-end.

    Query parameters:
        ?source=layer7_origin|layer7_target|layer3_origin|layer3_target

    Returns:
        {
          "points": [ { "lat": float, "lon": float, "intensity": float, ... }, ... ],
          "autoRefreshMs": int
        }

    OWASP:
      - A01: access control via @login_required.
      - A03/A05: 'source' is validated against ALLOWED_SOURCES, so we do not
        pass arbitrary user input into provider logic.
      - A09: detailed provider/network errors should be logged at the provider
        layer (e.g., CloudflareRadarProvider), not exposed here.
    """
    # Normalize and validate the 'source' query parameter
    source_param: Optional[str] = request.GET.get("source") or None
    if source_param not in ALLOWED_SOURCES:
        # Unknown or missing source -> use provider default (e.g., L7 origin)
        source_param = None

    # Fetch provider-backed points with caching (handled down in get_points)
    points = get_points(source=source_param)

    # Use central THREATMAP config with sane defaults
    auto_ms: int = conf_get("AUTO_REFRESH_MS")

    return JsonResponse(
        {
            "points": points,
            "autoRefreshMs": auto_ms,
        }
    )
