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
#   - A03: Injection
#       * This module only delegates to other URLConfs via include().
#         Any query parameters or path variables are handled and validated
#         in the underlying apps (dashboard, breaches), not here.
#
#   - A04: Insecure Design
#       * This module keeps routing concerns minimal and delegates to
#         app-level URLConfs so each app owns its own routing. This
#         supports modular design and reduces accidental tight coupling.
#
#   - A09: Security Logging & Monitoring
#       * Logging is performed in the views (e.g., dashboard/breaches
#         when sensitive data is accessed). Keeping routing simple here
#         makes it easier to reason about which views are hit for which
#         paths when analyzing logs.
#
#   This module delegates to app-level URLconfs so each app owns its own
#   routing privately, and the project wiring stays minimal and auditable.

from django.urls import include, path


# ---------------------------------------------------------------------------
# Root URL patterns for the "core" entry point
# ---------------------------------------------------------------------------
urlpatterns = [
    # "/" → dashboard home (see dashboard/urls.py for details).
    #   - In the main project urls.py, this module is typically mounted
    #     under a prefix (e.g., "core/"), so this pattern becomes "/core/".
    #   - Access control and logging are handled in dashboard.views.home.
    path("", include("dashboard.urls")),

    # "/breaches/" → breach monitoring & Shodan scan views.
    #   - All sensitive behavior (API calls, lookups) is performed server-side
    #     within the "breaches" app views, which are responsible for auth checks.
    #   - This delegation helps keep routing concerns separate from business
    #     logic, supporting a cleaner and more secure design (A04).
    path("breaches/", include("breaches.urls")),
]
