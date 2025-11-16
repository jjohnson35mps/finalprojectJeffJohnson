# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/breaches/views.py
#
# OWASP Top 10 considerations:
#   - A01/A07 (Access Control & AuthN/Z):
#       * All mutating views are protected with @login_required.
#       * Destructive actions (delete, scan) also use @require_POST.
#   - A02/A05 (Security Misconfiguration / Error Handling):
#       * We do not surface raw exceptions to end users; detailed errors go
#         to logs, while messages shown to users are generic.
#   - A03/A05 (Injection / XSS):
#       * User input (email, target) is treated as untrusted; we do not build
#         raw SQL or dynamic code with it.
#   - A06 (Sensitive Data Exposure):
#       * Email addresses and IPs are PII; logs use light masking for debug.
#   - A09 (Logging & Monitoring):
#       * Structured logging via the "breaches" logger; avoid dumping full
#         raw API responses or secrets.

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import BreachHit, EmailIdentity, ShodanFinding
from .services.hibp import HibpClient, HibpAuthError, HibpRateLimitError
from .services.shodan_client import fetch_host, ShodanError

logger = logging.getLogger("breaches")


# ---------------------------------------------------------------------------
# Utility helpers (logging, date normalization)
# ---------------------------------------------------------------------------

def _mask_email(addr: str) -> str:
    """
    Return a lightly masked version of an email address for logging.

    Example: "jeff@example.com" -> "j***@example.com"

    OWASP (A06): helps avoid excessive PII exposure in logs.
    """
    if not addr or "@" not in addr:
        return addr or ""
    local, _, domain = addr.partition("@")
    if len(local) <= 1:
        masked_local = "*"
    else:
        masked_local = local[0] + "***"
    return f"{masked_local}@{domain}"


def _date_or_none(value: str) -> Optional[datetime.date]:
    """
    Parse 'YYYY-MM-DD' into a date object or return None on failure.

    Currently unused, but kept as a defensive parser for any future date
    fields that might be stored as strings.
    """
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        logger.debug("[SCAN] invalid date format received: %r", value)
        return None


def _none_if_blank(v: Any) -> Any:
    """
    Normalize empty strings to None; used when writing to nullable fields.
    """
    return None if (v is None or (isinstance(v, str) and v.strip() == "")) else v


def _safe_date(v: Any) -> Optional[str]:
    """
    Return a 'YYYY-MM-DD' string or None (never empty string).

    Accepts full timestamps and truncates to first 10 chars.
    Very light format validation; deeper validation happens earlier
    in the pipeline (HIBP client).
    """
    if not v:
        return None
    s = str(v).strip()
    if not s:
        return None
    # keep only the date part if a timestamp sneaks in
    s = s[:10]
    # very light validation
    return s if len(s) == 10 and s[4] == "-" and s[7] == "-" else None


# ---------------------------------------------------------------------------
# Dashboard / landing view
# ---------------------------------------------------------------------------

@login_required(login_url="login")
def dashboard(request):
    """
    Main dashboard view.

    - Shows:
        * All EmailIdentity records (ordered by address).
        * Recent ShodanFinding scans (most recent 12).
    - OWASP:
        * A01/A07: protected by login_required.
        * No user input processing; read-only data display.
    """
    identities = EmailIdentity.objects.order_by("address")
    scans = ShodanFinding.objects.order_by("-last_seen")[:12]
    return render(
        request,
        "breaches/main_db.html",
        {"identities": identities, "scans": scans},
    )


# ---------------------------------------------------------------------------
# EmailIdentity management
# ---------------------------------------------------------------------------

@login_required(login_url="login")
def add_identity(request):
    """
    Add a new EmailIdentity for breach monitoring.

    - POST: validate and create (or reuse) an identity, then redirect.
    - GET: (not commonly used in UI) returns a detail template; the primary
      add form lives on the dashboard.

    OWASP:
      - A01/A07: login_required protects the endpoint.
      - A03: email is treated as untrusted; we simply store it; HIBP
        lookups occur in scan_identity.
    """
    if request.method == "POST":
        email = (request.POST.get("email") or "").strip()
        if not email:
            messages.error(request, "Email is required.")
            return redirect("breaches:add")

        obj, created = EmailIdentity.objects.get_or_create(address=email)
        messages.success(
            request,
            f"{'Added' if created else 'Already exists'}: {obj.address}",
        )
        return redirect("breaches:dashboard")

    # Optional: could redirect to dashboard instead of rendering a template.
    # return render(request, "breaches/identity_detail.html")
    return redirect("breaches:dashboard")

@login_required(login_url="login")
@require_POST
def scan_identity(request, pk: int):
    """
    Trigger a HIBP scan for a specific EmailIdentity and upsert BreachHit rows.

    Steps:
      - Fetch HIBP breach data for the identity's email.
      - Normalize and deduplicate breach names.
      - update_or_create BreachHit records per breach.
      - Report status to the user via Django messages.

    OWASP:
      - A01/A07: login_required + require_POST for state-changing action.
      - A03/A05: external API data is normalized; no direct use in SQL or code.
      - A06: logs use masked email where possible to limit PII exposure.
    """
    identity = get_object_or_404(EmailIdentity, pk=pk)
    client = HibpClient()

    created_count = 0
    updated_count = 0

    try:
        results = client.breaches_for_account(identity.address)
        logger.info(
            "[SCAN] %s status=%s count=%s",
            _mask_email(identity.address),
            client.last_status,
            len(results or []),
        )

        seen_names: set[str] = set()

        for item in results or []:
            # Support normalized keys (our client) OR raw HIBP keys
            raw_name = (item.get("breach_name") or item.get("Name") or "").strip()
            title = (item.get("title") or item.get("Title") or "").strip()
            domain = (item.get("domain") or item.get("Domain") or "").strip()

            breach_dt = _safe_date(item.get("occurred_on") or item.get("BreachDate"))
            added_dt = _safe_date(item.get("added_on") or item.get("AddedDate"))
            mod_dt = _safe_date(item.get("modified_on") or item.get("ModifiedDate"))

            # Prefer stable identifiers; fall back deterministically
            name = (
                raw_name
                or title
                or domain
                or f"unknown-{breach_dt or 'na'}-{added_dt or 'na'}"
                or "Unknown"
            )

            # Avoid intra-batch collisions and DB collisions on (identity, breach_name)
            base = name
            if name in seen_names:
                n = 2
                candidate = f"{base} ({n})"
                while (
                    BreachHit.objects.filter(
                        identity=identity,
                        breach_name=candidate,
                    ).exists()
                    or candidate in seen_names
                ):
                    n += 1
                    candidate = f"{base} ({n})"
                name = candidate
            seen_names.add(name)

            defaults: Dict[str, Any] = {
                "domain": domain,
                "occurred_on": breach_dt,  # None or 'YYYY-MM-DD'
                "title": title or raw_name or domain,
                "description": item.get("description")
                or item.get("Description")
                or "",
                "pwn_count": item.get("pwn_count", item.get("PwnCount")),
                "data_classes": item.get("data_classes")
                or item.get("DataClasses")
                or [],
                "is_verified": bool(
                    item.get("is_verified", item.get("IsVerified", False))
                ),
                "is_sensitive": bool(
                    item.get("is_sensitive", item.get("IsSensitive", False))
                ),
                "is_fabricated": bool(
                    item.get("is_fabricated", item.get("IsFabricated", False))
                ),
                "is_spam_list": bool(
                    item.get("is_spam_list", item.get("IsSpamList", False))
                ),
                "is_retired": bool(
                    item.get("is_retired", item.get("IsRetired", False))
                ),
                "is_malware": bool(
                    item.get("is_malware", item.get("IsMalware", False))
                ),
                "is_stealer_log": bool(
                    item.get("is_stealer_log", item.get("IsStealerLog", False))
                ),
                "is_subscription_free": bool(
                    item.get(
                        "is_subscription_free",
                        item.get("IsSubscriptionFree", False),
                    )
                ),
                "added_on": added_dt,      # None or 'YYYY-MM-DD'
                "modified_on": mod_dt,     # None or 'YYYY-MM-DD'
                "logo_path": "",           # we don't store LogoPath
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
            if created:
                created_count += 1
            else:
                updated_count += 1

        messages.success(
            request,
            f"Scan complete for {identity.address}. "
            f"New: {created_count}, updated: {updated_count}.",
        )

    except HibpAuthError as ex:
        messages.error(
            request,
            "Authentication failed with HIBP. Check HIBP_API_KEY and HIBP_USER_AGENT settings.",
        )
        logger.warning("HIBP auth error for %s: %s", _mask_email(identity.address), ex)
    except HibpRateLimitError as ex:
        messages.warning(request, str(ex))
        logger.warning("HIBP rate limit for %s: %s", _mask_email(identity.address), ex)
    except Exception as ex:
        # OWASP A05: do not expose raw exceptions to users.
        logger.exception(
            "[SCAN] unexpected error for %s",
            _mask_email(identity.address),
        )
        messages.error(
            request,
            "An unexpected error occurred while scanning this identity. "
            "Please try again later.",
        )

    return redirect("breaches:identity_detail", pk=identity.pk)


# ---------------------------------------------------------------------------
# Shodan-style host scanning
# ---------------------------------------------------------------------------

@login_required(login_url="login")
@require_POST
def scan_target(request):
    """
    Submit a domain or IP to the Shodan client and store a summarized result.

    - Reads "target" from POST data.
    - Uses fetch_host() to call Shodan and normalize the response.
    - Upserts a ShodanFinding row keyed by IP.

    OWASP:
      - A01/A07: login_required + require_POST.
      - A03: target is untrusted; fetch_host handles resolution safely.
      - A05: generic error messages to user; details in logs.
    """
    target = (request.POST.get("target") or "").strip()
    if not target:
        messages.error(request, "Please enter a domain or IP.")
        return redirect("breaches:dashboard")

    try:
        data = fetch_host(target)
        if not data:
            messages.info(request, f"No data found for {target}.")
            return redirect("breaches:dashboard")

        ip = data.get("ip_str") or data.get("ip")
        if not ip:
            messages.error(request, "No IP could be determined for this host.")
            return redirect("breaches:dashboard")

        hostnames = data.get("hostnames") or []
        ports_raw = data.get("ports") or []

        # Defensive parsing: ensure ports is a list of ints where possible.
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

        messages.success(request, f"Scan saved for {ip}.")

    except ShodanError as e:
        logger.warning("Shodan scan failed for %s: %s", target, e)
        messages.error(
            request,
            "Scan failed due to an error contacting the host intelligence service.",
        )
    except Exception as e:
        logger.exception("Unexpected error running scan for %s", target)
        messages.error(
            request,
            "An unexpected error occurred while running the scan. "
            "Please try again later.",
        )

    return redirect("breaches:dashboard")


# ---------------------------------------------------------------------------
# Identity detail view
# ---------------------------------------------------------------------------

@login_required(login_url="login")
def identity_detail(request, pk: int):
    """
    Show all BreachHit records for a specific EmailIdentity.

    OWASP:
      - A01/A07: access is restricted via login_required; per-user scoping
        would be added here in a multi-tenant setting.
      - A06: logs use masked email to limit PII exposure.
    """
    identity = get_object_or_404(EmailIdentity, pk=pk)
    hits = (
        BreachHit.objects.filter(identity=identity)
        .order_by("-occurred_on", "-added_on", "-id")
    )

    logger.info(
        "Identity %s - breach hits count=%s",
        _mask_email(identity.address),
        hits.count(),
    )

    return render(
        request,
        "breaches/identity_detail.html",
        {
            "identity": identity,
            "hits": hits,
        },
    )


# ---------------------------------------------------------------------------
# Delete views (destructive actions)
# ---------------------------------------------------------------------------

@login_required(login_url="login")
@require_POST
def delete_identity(request, pk: int):
    """
    Delete an EmailIdentity and cascade-delete associated BreachHit rows.

    OWASP:
      - A01/A07: login_required + require_POST.
      - A06: only minimal PII (email) included in the user-facing message.
    """
    identity = get_object_or_404(EmailIdentity, pk=pk)
    addr = identity.address
    identity.delete()  # BreachHit rows will cascade-delete (FK CASCADE)
    messages.success(request, f"Removed identity: {addr}")
    return redirect("breaches:dashboard")


@login_required(login_url="login")
@require_POST
def delete_scan(request, pk: int):
    """
    Delete a stored ShodanFinding.

    OWASP:
      - A01/A07: login_required + require_POST.
      - A06: IP address is PII; we only echo it minimally in the message.
    """
    scan = get_object_or_404(ShodanFinding, pk=pk)
    ip = scan.ip
    scan.delete()
    messages.success(request, f"Removed scan for {ip}.")
    return redirect("breaches:dashboard")
