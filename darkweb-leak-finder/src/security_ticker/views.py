# src/security_ticker/views.py
from django.http import JsonResponse
from .services.sources import fetch_kev_items

def ticker_feed(request):
    items = fetch_kev_items(limit=10)
    if not items:
        # fallback to local breaches to avoid a blank banner
        from breaches.models import BreachHit
        for b in BreachHit.objects.order_by("-occurred_on", "-id")[:10]:
            items.append({
                "title": (b.title or b.breach_name or "Breach").strip(),
                "date": b.occurred_on.isoformat() if b.occurred_on else "",
                "link": f"https://haveibeenpwned.com/Incident/{b.breach_name}",
            })
    return JsonResponse({"items": items})
