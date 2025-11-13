# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/threatmap/views.py

from django.http import JsonResponse
from .services.fetcher import get_points
from .conf import conf_get
import random, json
from django.conf import settings

def heat_points(request):
    return JsonResponse({
        "points": get_points(),
        "autoRefreshMs": conf_get("AUTO_REFRESH_MS"),
    })

def attack_points(request):
    """Return simulated or live attack points for heat map"""
    # Example static or fetched data
    points = []
    for _ in range(50):
        points.append({
            "lat": random.uniform(-60, 75),
            "lon": random.uniform(-180, 180),
            "intensity": random.uniform(0.3, 1.0)
        })
    return JsonResponse(points, safe=False)

def threat_points(request):
    source = request.GET.get("source")  # e.g., layer7_origin/layer7_target/...
    points = get_points(source=source)
    auto_ms = settings.THREATMAP.get("AUTO_REFRESH_MS", 60000)
    return JsonResponse({"points": points, "autoRefreshMs": auto_ms}, safe=False)

