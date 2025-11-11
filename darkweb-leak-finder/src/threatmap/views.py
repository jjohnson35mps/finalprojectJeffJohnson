# src/threatmap/views.py
from django.http import JsonResponse
from .services.fetcher import get_points
from .conf import conf_get

def heat_points(request):
    return JsonResponse({
        "points": get_points(),
        "autoRefreshMs": conf_get("AUTO_REFRESH_MS"),
    })
