# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/core/urls.py
#
# Project-level routing glue for core views.
#
# OWASP Top 10 touchpoints:
#   - A01/A07: Broken Access Control / Identification & Authentication Failures
#       * URL patterns here only define the routing.
#       * Actual access control is enforced in the underlying views
#         (e.g., @login_required on dashboard/breaches views).
#       * Keep sensitive routes (admin tools, debug endpoints) behind
#         proper authentication/authorization and do not expose them here
#         without protections in the corresponding views.
#
#   - A02: Security Misconfiguration
#       * No secrets, API keys, or environment-specific configuration
#         should be encoded in URL patterns.
#       * Avoid adding any "debug-only" views to this module in a way
#         that could be enabled in production.
#
#   This module delegates to app-level URLconfs so each app owns its own
#   routing privately, and the project wiring stays minimal and auditable.

from django.urls import path, include


# ---------------------------------------------------------------------------
# Root URL patterns
# ---------------------------------------------------------------------------
urlpatterns = [
    # "/" → dashboard home (see dashboard/urls.py for details).
    path("", include("dashboard.urls")),

    # "/breaches/" → breach monitoring & Shodan scan views.
    # All sensitive behavior (API calls, lookups) is performed server-side
    # within the "breaches" app views, which are responsible for auth checks.
    path("breaches/", include("breaches.urls")),
]
