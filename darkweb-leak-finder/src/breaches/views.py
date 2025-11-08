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
# ------------------------------------------------------------
# Jeff Johnson — INF 601 Advanced Python — Final Project
# Views for adding identities and scanning them against HIBP.
# - add_identity:
#     GET  -> render the "Add Identity" form page
#     POST -> create/get EmailIdentity, flash a message, redirect to dashboard
# - scan_identity:
#     Look up one EmailIdentity, call HibpClient, upsert BreachHit rows with
#     the full HIBP breach model, handle API errors gracefully, then redirect
#     to the identity detail page.

from __future__ import annotations

import logging
from typing import Any, Dict

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render

from .models import BreachHit, EmailIdentity
from .services.hibp import HibpClient, HibpAuthError, HibpRateLimitError

logger = logging.getLogger("breaches")


def add_identity(request):
    """
    Show the "Add Identity" page on GET; create the EmailIdentity on POST.
    """
    if request.method == "POST":
        email = (request.POST.get("email") or "").strip()
        if not email:
            messages.error(request, "Email is required.")
            return redirect("breaches:add")

        obj, created = EmailIdentity.objects.get_or_create(address=email)
        messages.success(request, f"{'Added' if created else 'Already exists'}: {obj.address}")
        return redirect("dashboard:home")

    return render(request, "breaches/add_identity.html")


def _date_or_none(val: str | None) -> str | None:
    """
    HIBP returns dates as 'YYYY-MM-DD' or ISO 'YYYY-MM-DDTHH:MM:SSZ'.
    Our DateField accepts 'YYYY-MM-DD'; trim if needed.
    """
    if not val:
        return None
    return val[:10]  # safe for both formats


def scan_identity(request, pk: int):
    """
    Scan one EmailIdentity against HIBP and persist the *full* breach model.

    - Uses truncateResponse=false (handled by HibpClient) to capture:
      title, description (HTML), data classes, flags, dates, logo path, etc.
    - Uses update_or_create to refresh existing rows on subsequent scans.
    - Surfaces a user-friendly banner and logs concise diagnostics.
    """
    identity = get_object_or_404(EmailIdentity, pk=pk)
    client = HibpClient()

    created_count = 0
    updated_count = 0

    try:
        results = client.breaches_for_account(identity.address)

        logger.info(
            "[SCAN] %s status=%s items=%s",
            identity.address, client.last_status, client.last_items
        )

        for item in results or []:
            # Normalize + map the full breach model
            name = (item.get("Name") or "").strip() or "Unknown"

            defaults: Dict[str, Any] = {
                # core
                "domain": (item.get("Domain") or "").strip(),
                "occurred_on": _date_or_none(item.get("BreachDate")),

                # full model fields
                "title": item.get("Title") or "",
                "description": item.get("Description") or "",
                "pwn_count": item.get("PwnCount"),
                "data_classes": item.get("DataClasses"),

                "is_verified": item.get("IsVerified"),
                "is_sensitive": item.get("IsSensitive"),
                "is_fabricated": item.get("IsFabricated"),
                "is_spam_list": item.get("IsSpamList"),
                "is_retired": item.get("IsRetired"),
                "is_malware": item.get("IsMalware"),
                "is_stealer_log": item.get("IsStealerLog"),
                "is_subscription_free": item.get("IsSubscriptionFree"),

                "added_on": _date_or_none(item.get("AddedDate")),
                "modified_on": _date_or_none(item.get("ModifiedDate")),
                "logo_path": item.get("LogoPath") or "",
            }

            obj, created = BreachHit.objects.update_or_create(
                identity=identity,
                breach_name=name,
                defaults=defaults,
            )
            if created:
                created_count += 1
            else:
                updated_count += 1

        messages.success(
            request,
            (
                f"Scan complete for {identity.address}. "
                f"API status={client.last_status}, returned={client.last_items}, "
                f"new={created_count}, updated={updated_count}."
            ),
        )

    except HibpAuthError as ex:
        messages.error(
            request,
            f"{ex} Set HIBP_API_KEY and HIBP_USER_AGENT in your .env or Run Configuration."
        )
    except HibpRateLimitError as ex:
        messages.warning(request, str(ex))
    except Exception as ex:  # defensive catch-all for unexpected issues
        logger.exception("[SCAN] unexpected error for %s", identity.address)
        messages.error(request, f"Scan failed: {ex}")

    return redirect("dashboard:detail", pk=identity.pk)
