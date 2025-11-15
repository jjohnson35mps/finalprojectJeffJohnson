# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# dashboard/views.py
#
# High-level dashboard views for ShadowScan:
#   - home: list of monitored identities
#   - detail: breach history for a single identity
#
# OWASP Top 10 touchpoints:
#   - A01: Broken Access Control
#       * Both views are protected with @login_required.
#       * If this app ever becomes multi-tenant, add per-user
#         ownership checks (e.g., filter identities by request.user).
#   - A02: Security Misconfiguration
#       * No secrets or environment-specific settings are hard-coded here.
#       * Strict use of Django’s render() & ORM helps avoid misconfig errors.
#   - A03/A05: Injection / Security Misconfiguration
#       * No raw SQL; all DB access via Django ORM.
#   - A09: Security Logging and Monitoring
#       * These views do not log PII directly. Any additional logging
#         should be done carefully in a dedicated logger, avoiding
#         sensitive data (email addresses, breach details) where possible.

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render

from breaches.models import EmailIdentity


@login_required(login_url="login")
def home(request):
    """
    Dashboard landing page.

    Responsibilities:
      - Show the list of monitored email identities, most recently created first.
      - Delegate detailed breach information to the detail view.

    Template:
      - Renders: dashboard/home.html

    Security notes (OWASP):
      - Access control (A01) is enforced via @login_required.
      - The query uses the ORM (no raw SQL), mitigating injection risks (A03).
    """
    # Fetch all monitored identities, newest first.
    identities = EmailIdentity.objects.order_by("-created_at")

    # Render the dashboard home with the identity list in context.
    return render(
        request,
        "dashboard/home.html",
        {
            "identities": identities,
        },
    )


@login_required(login_url="login")
def detail(request, pk: int):
    """
    Detail page for a single identity and its breach history.

    Responsibilities:
      - Fetch a single EmailIdentity by primary key.
      - Load related BreachHit records via the reverse relationship.
      - Order breaches by most recent occurrence, then by name.

    Template:
      - Renders: dashboard/detail.html

    Security notes (OWASP):
      - A01: Access control is enforced via @login_required.
        If the system is ever multi-tenant (per-user identities),
        this view should additionally enforce ownership, e.g.:
            get_object_or_404(EmailIdentity, pk=pk, owner=request.user)
      - A03/A05: Uses ORM & safe template rendering; no raw SQL or
        direct HTML building here.
    """
    # Safely resolve the identity or return 404 if the pk is invalid.
    identity = get_object_or_404(EmailIdentity, pk=pk)

    # Use the related-name "hits" from BreachHit.identity, newest breaches first.
    hits = identity.hits.order_by("-occurred_on", "breach_name")

    # Render the detail template with both the identity and its breach hits.
    return render(
        request,
        "dashboard/detail.html",
        {
            "identity": identity,
            "hits": hits,
        },
    )
