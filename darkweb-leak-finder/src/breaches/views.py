# src/breaches/views.py
# ------------------------------------------------------------
# Jeff Johnson — INF 601 Advanced Python — Final Project
# Views for adding identities and scanning them against HIBP.
# - add_identity:
#     GET  -> render the "Add Identity" form page
#     POST -> create/get EmailIdentity, flash a message, redirect to dashboard
# - scan_identity:
#     Look up one EmailIdentity, call HibpClient, create BreachHit rows,
#     handle API errors gracefully, then redirect to the identity detail page.

# src/breaches/views.py
from __future__ import annotations
import logging
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from .models import BreachHit, EmailIdentity
from .services.hibp import HibpClient, HibpAuthError, HibpRateLimitError

logger = logging.getLogger("breaches")

def add_identity(request):
    if request.method == "POST":
        email = (request.POST.get("email") or "").strip()
        if not email:
            messages.error(request, "Email is required.")
            return redirect("breaches:add")
        obj, created = EmailIdentity.objects.get_or_create(address=email)
        messages.success(request, f"{'Added' if created else 'Already exists'}: {obj.address}")
        return redirect("dashboard:home")
    return render(request, "breaches/add_identity.html")

def scan_identity(request, pk: int):
    identity = get_object_or_404(EmailIdentity, pk=pk)
    client = HibpClient()

    created = 0
    try:
        results = client.breaches_for_account(identity.address)

        logger.info("[SCAN] %s status=%s items=%s",
                    identity.address, client.last_status, client.last_items)

        for item in results or []:
            name = (item.get("Name") or "").strip() or "Unknown"
            domain = (item.get("Domain") or "").strip()
            date_str = item.get("BreachDate") or None
            _, made = BreachHit.objects.get_or_create(
                identity=identity,
                breach_name=name,
                defaults={"domain": domain, "occurred_on": date_str},
            )
            if made:
                created += 1

        # visible in the UI so you don't need to read the console
        messages.success(
            request,
            f"Scan complete for {identity.address}. "
            f"API status={client.last_status}, returned={client.last_items}, saved={created}."
        )

    except HibpAuthError as ex:
        messages.error(request, f"{ex} Set HIBP_API_KEY and HIBP_USER_AGENT in your .env or Run Config.")
    except HibpRateLimitError as ex:
        messages.warning(request, str(ex))
    except Exception as ex:
        logger.exception("[SCAN] unexpected error for %s", identity.address)
        messages.error(request, f"Scan failed: {ex}")

    return redirect("dashboard:detail", pk=identity.pk)
