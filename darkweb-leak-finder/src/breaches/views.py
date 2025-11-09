# src/breaches/views.py
from __future__ import annotations

import logging
from typing import Any, Dict

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .models import BreachHit, EmailIdentity, ShodanFinding
from .services.hibp import HibpClient, HibpAuthError, HibpRateLimitError
from .services.shodan_client import fetch_host, ShodanError

logger = logging.getLogger("breaches")

# -------- Dashboard --------
def dashboard(request):
    """
    Render the main dashboard with identities and recent Shodan scans.
    Template: breaches/main_db.html
    """
    identities = EmailIdentity.objects.order_by("address")
    scans = ShodanFinding.objects.order_by("-last_seen")[:12]
    return render(request, "breaches/main_db.html", {"identities": identities, "scans": scans})

# -------- Add Identity --------
def add_identity(request):
    """
    GET -> show form; POST -> create/get EmailIdentity, then go to dashboard.
    """
    if request.method == "POST":
        email = (request.POST.get("email") or "").strip()
        if not email:
            messages.error(request, "Email is required.")
            return redirect("breaches:add")

        obj, created = EmailIdentity.objects.get_or_create(address=email)
        messages.success(request, f"{'Added' if created else 'Already exists'}: {obj.address}")
        return redirect("breaches:dashboard")

    return render(request, "breaches/add_identity.html")

# -------- HIBP util --------
def _date_or_none(val: str | None) -> str | None:
    if not val:
        return None
    return val[:10]

# -------- Scan one identity (HIBP) --------
def scan_identity(request, pk: int):
    identity = get_object_or_404(EmailIdentity, pk=pk)
    client = HibpClient()

    created_count = 0
    updated_count = 0

    try:
        results = client.breaches_for_account(identity.address)
        logger.info("[SCAN] %s status=%s items=%s", identity.address, client.last_status, client.last_items)

        for item in results or []:
            name = (item.get("Name") or "").strip() or "Unknown"
            defaults: Dict[str, Any] = {
                "domain": (item.get("Domain") or "").strip(),
                "occurred_on": _date_or_none(item.get("BreachDate")),
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
            _, created = BreachHit.objects.update_or_create(identity=identity, breach_name=name, defaults=defaults)
            if created: created_count += 1
            else:       updated_count += 1

        messages.success(
            request,
            f"Scan complete for {identity.address}. API status={client.last_status}, "
            f"returned={client.last_items}, new={created_count}, updated={updated_count}."
        )

    except HibpAuthError as ex:
        messages.error(request, "Authentication failed with HIBP. Set HIBP_API_KEY and HIBP_USER_AGENT.")
        logger.warning("HIBP auth error: %s", ex)
    except HibpRateLimitError as ex:
        messages.warning(request, str(ex))
        logger.warning("HIBP rate limit: %s", ex)
    except Exception as ex:
        logger.exception("[SCAN] unexpected error for %s", identity.address)
        messages.error(request, f"Scan failed: {ex}")

    # back to dashboard (you can change later to an identity detail view)
    return redirect("breaches:dashboard")

# -------- Scan target (Shodan) --------
def scan_target(request):
    if request.method != "POST":
        messages.error(request, "Invalid request method.")
        return redirect("breaches:dashboard")

    target = (request.POST.get("target") or "").strip()
    if not target:
        messages.error(request, "Please enter a domain or IP.")
        return redirect("breaches:dashboard")

    try:
        data = fetch_host(target)
        if not data:
            messages.info(request, f"No Shodan data found for {target}.")
            return redirect("breaches:dashboard")

        ip = data.get("ip_str") or data.get("ip")
        if not ip:
            messages.error(request, "Shodan returned no IP for this host.")
            return redirect("breaches:dashboard")

        hostnames = data.get("hostnames") or []
        ports_raw = data.get("ports") or []
        try:
            ports = sorted({int(p) for p in ports_raw})
        except Exception:
            ports = list(ports_raw)

        org = data.get("org") or ""
        os_field = data.get("os") or ""
        last_seen = data.get("last_update") or timezone.now()

        ShodanFinding.objects.update_or_create(
            ip=ip,
            defaults={
                "hostnames": hostnames,
                "ports": ports,
                "org": org,
                "os": os_field,
                "raw": data,
                "last_seen": last_seen,
            },
        )

        messages.success(request, f"Shodan scan saved for {ip}.")

    except ShodanError as e:
        logger.warning("Shodan scan failed for %s: %s", target, e)
        messages.error(request, f"Shodan scan failed: {e}")
    except Exception as e:
        logger.exception("Unexpected error running shodan scan for %s", target)
        messages.error(request, f"Unexpected error: {e}")

    return redirect("breaches:dashboard")
