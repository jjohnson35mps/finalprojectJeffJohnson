# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# dashboard/views.py
#
# High-level dashboard views for ShadowScan:
#   - home: list of monitored identities
#   - detail: delegates to breaches.identity_detail for a single identity
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
#   - A04: Insecure Design
#       * The detail view delegates to the canonical breaches.identity_detail
#         implementation, avoiding duplicated logic and reducing the risk
#         of subtle drift between multiple detail views.
#   - A09: Security Logging and Monitoring
#       * These views do not log PII directly. Any additional logging
#         should be done carefully in a dedicated logger, avoiding
#         sensitive data (email addresses, breach details) where possible.

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from breaches.models import EmailIdentity


@login_required(login_url="login")
def home(request):
    """
    Dashboard landing page.

    Responsibilities:
      - Show the list of monitored email identities, most recently created first.
      - Delegate detailed breach information to the detail view (which in turn
        delegates to breaches.identity_detail).

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
    Detail page entry point for a single identity and its breach history.

    Responsibilities:
      - Validate that the requested EmailIdentity exists (404 on invalid pk).
      - Delegate the actual rendering and breach-query logic to the canonical
        breaches.identity_detail view to avoid duplicated business logic.

    Template:
      - The actual rendering is performed by breaches.identity_detail using
        breaches/identity_detail.html.

    Security notes (OWASP):
      - A01: Access control is enforced via @login_required here and again
        in breaches.identity_detail (defense in depth).
      - A03/A05: Uses ORM & safe redirects; no raw SQL or direct HTML building.
      - A04: Centralizing the detail logic in the breaches app reduces the
        chance of inconsistencies between multiple detail implementations.
    """
    # Safely resolve the identity or return 404 if the pk is invalid.
    get_object_or_404(EmailIdentity, pk=pk)

    # Delegate to the canonical breaches detail view.
    return redirect("breaches:identity_detail", pk=pk)
