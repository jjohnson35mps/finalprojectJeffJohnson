# security_ticker/views.py
from django.http import JsonResponse
from .services.sources import fetch_kev_items

def ticker_feed(request):
    items = fetch_kev_items(limit=10)
    return JsonResponse({"items": items})
