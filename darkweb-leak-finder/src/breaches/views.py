# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/breaches/views.py

from __future__ import annotations
import logging
from typing import Any, Dict
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from .models import BreachHit, EmailIdentity, ShodanFinding
from .services.hibp import HibpClient, HibpAuthError, HibpRateLimitError
from .services.shodan_client import fetch_host, ShodanError
from datetime import datetime
from django.views.decorators.http import require_POST

logger = logging.getLogger("breaches")

@login_required(login_url='login')
def dashboard(request):
    identities = EmailIdentity.objects.order_by("address")
    scans = ShodanFinding.objects.order_by("-last_seen")[:12]
    return render(request, "breaches/main_db.html", {"identities": identities, "scans": scans})

@login_required(login_url='login')
def add_identity(request):
    if request.method == "POST":
        email = (request.POST.get("email") or "").strip()
        if not email:
            messages.error(request, "Email is required.")
            return redirect("breaches:add")

        obj, created = EmailIdentity.objects.get_or_create(address=email)
        messages.success(request, f"{'Added' if created else 'Already exists'}: {obj.address}")
        return redirect("breaches:dashboard")

    return render(request, "breaches/add_identity.html")

@login_required(login_url='login')
def _date_or_none(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        logger.debug(f"[SCAN] invalid date format received: {value!r}")
        return None

@login_required(login_url='login')
def _none_if_blank(v):
    return None if (v is None or (isinstance(v, str) and v.strip() == "")) else v

@login_required(login_url='login')
def _safe_date(v):
    """Return 'YYYY-MM-DD' or None (never empty string)."""
    if not v:
        return None
    s = str(v).strip()
    if not s:
        return None
    # keep only the date part if a timestamp sneaks in
    s = s[:10]
    # very light validation
    return s if len(s) == 10 and s[4] == "-" and s[7] == "-" else None

@login_required(login_url='login')
@require_POST
def scan_identity(request, pk: int):
    identity = get_object_or_404(EmailIdentity, pk=pk)
    client = HibpClient()

    created_count = 0
    updated_count = 0

    try:
        results = client.breaches_for_account(identity.address)
        logger.info("[SCAN] %s status=%s items=%s",
                    identity.address, client.last_status, client.last_items)

        seen_names: set[str] = set()

        for item in results or []:
            # Support normalized keys (our client) OR raw HIBP keys
            raw_name = (item.get("breach_name") or item.get("Name") or "").strip()
            title    = (item.get("title")       or item.get("Title") or "").strip()
            domain   = (item.get("domain")      or item.get("Domain") or "").strip()

            breach_dt = _safe_date(item.get("occurred_on") or item.get("BreachDate"))
            added_dt  = _safe_date(item.get("added_on")     or item.get("AddedDate"))
            mod_dt    = _safe_date(item.get("modified_on")  or item.get("ModifiedDate"))

            # Prefer stable identifiers; fall back deterministically
            name = raw_name or title or domain or f"unknown-{breach_dt or 'na'}-{added_dt or 'na'}" or "Unknown"

            # Avoid intra-batch collisions and DB collisions on (identity, breach_name)
            base = name
            if name in seen_names:
                n = 2
                candidate = f"{base} ({n})"
                while BreachHit.objects.filter(identity=identity, breach_name=candidate).exists() or candidate in seen_names:
                    n += 1
                    candidate = f"{base} ({n})"
                name = candidate
            seen_names.add(name)

            defaults: Dict[str, Any] = {
                "domain": domain,
                "occurred_on": breach_dt,            # None or 'YYYY-MM-DD'
                "title": title or raw_name or domain,
                "description": item.get("description") or item.get("Description") or "",
                "pwn_count": item.get("pwn_count", item.get("PwnCount")),
                "data_classes": item.get("data_classes") or item.get("DataClasses") or [],
                "is_verified": bool(item.get("is_verified", item.get("IsVerified", False))),
                "is_sensitive": bool(item.get("is_sensitive", item.get("IsSensitive", False))),
                "is_fabricated": bool(item.get("is_fabricated", item.get("IsFabricated", False))),
                "is_spam_list": bool(item.get("is_spam_list", item.get("IsSpamList", False))),
                "is_retired": bool(item.get("is_retired", item.get("IsRetired", False))),
                "is_malware": bool(item.get("is_malware", item.get("IsMalware", False))),
                "is_stealer_log": bool(item.get("is_stealer_log", item.get("IsStealerLog", False))),
                "is_subscription_free": bool(item.get("is_subscription_free", item.get("IsSubscriptionFree", False))),
                "added_on": added_dt,               # None or 'YYYY-MM-DD'
                "modified_on": mod_dt,              # None or 'YYYY-MM-DD'
                "logo_path": "",                    # we don't store LogoPath
            }

            # Belt-and-suspenders: never allow "" into DateFields
            for k in ("occurred_on", "added_on", "modified_on"):
                if defaults[k] == "":
                    defaults[k] = None

            _, created = BreachHit.objects.update_or_create(
                identity=identity,
                breach_name=name,
                defaults=defaults,
            )
            created_count += 1 if created else 0
            updated_count += 0 if created else 1

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

    return redirect("breaches:identity_detail", pk=identity.pk)

@login_required(login_url='login')
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

@login_required(login_url='login')
def identity_detail(request, pk: int):
    identity = get_object_or_404(EmailIdentity, pk=pk)
    hits = (
        BreachHit.objects
        .filter(identity=identity)
        #.exclude(breach_name__isnull=True)
        #.exclude(breach_name__exact="")
        #.exclude(breach_name__iexact="unknown")
        .order_by("-occurred_on", "-added_on", "-id")
    )
    logger.info("Identity %s - breach hits count=%s", identity.address, hits.count())
    return render(request, "breaches/identity_detail.html", {
        "identity": identity,
        "hits": hits,             # <- expose hits
    })

@login_required(login_url='login')
@require_POST
def delete_identity(request, pk: int):
    identity = get_object_or_404(EmailIdentity, pk=pk)
    addr = identity.address
    identity.delete()  # BreachHit rows will cascade-delete (FK CASCADE)
    messages.success(request, f"Removed identity: {addr}")
    return redirect("breaches:dashboard")

@login_required(login_url='login')
@require_POST
def delete_scan(request, pk: int):
    scan = get_object_or_404(ShodanFinding, pk=pk)
    ip = scan.ip
    scan.delete()
    messages.success(request, f"Removed Shodan scan for {ip}.")
    return redirect("breaches:dashboard")