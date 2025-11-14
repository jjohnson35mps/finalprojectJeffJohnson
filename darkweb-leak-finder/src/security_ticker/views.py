# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .services.sources import fetch_kev_items

@login_required(login_url='login')
def ticker_feed(request):
    items, source = fetch_kev_items(limit=10)
    resp = JsonResponse({"items": items, "source": source})
    resp["X-Ticker-Source"] = source  # handy for debugging in Network tab
    return resp
