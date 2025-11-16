"""
INF601 - Advanced Programming in Python
Jeff Johnson
Final Project

dashboard/urls.py

URL routing for the `dashboard` app.

Responsibilities:
  - Expose the dashboard home view (list/summary).
  - Expose a detail view for a single identity by primary key.

OWASP Top 10 touchpoints:
  - A01: Broken Access Control
      * These URL patterns are intentionally simple; access control
        must be enforced in the corresponding views (e.g. @login_required
        and per-user authorization checks).
  - A02: Security Misconfiguration
      * No secrets or environment-specific configuration is stored here.
      * Paths use Django’s built-in converters (e.g. <int:pk>) to avoid
        ambiguous routing and reduce parsing issues.
  - A03: Injection
      * Path parameters such as `pk` are treated as untrusted input.
        Views should use get_object_or_404 and avoid building raw SQL
        or unsafe API calls directly from these values.
  - A05/A08 (Validation / Software & Data Integrity)
      * `pk` is constrained to an integer by the path converter; any
        further validation (e.g., ownership checks) is performed in views.
  - A09: Security Logging & Monitoring
      * Views behind these routes should log key events (e.g., access to
        sensitive dashboards) via the application's logging configuration.
"""

from django.urls import path

from . import views

# Namespacing for this app's URL patterns; used as "dashboard:home", etc.
app_name = "dashboard"

# Public URL mappings for the dashboard app.
urlpatterns = [
    # Dashboard home:
    #   - Typically a high-level summary page (e.g., list of identities,
    #     recent scans, or other security metrics).
    #   - Access control (e.g., @login_required) is enforced in views.home
    #     to ensure only authenticated users can see the dashboard (A01).
    path("", views.home, name="home"),

    # Detail view for a single identity or dashboard object:
    #   - Uses <int:pk> to ensure we only match integer IDs.
    #   - Views must ensure the current user is allowed to see this record
    #     (avoiding Insecure Direct Object References / A01).
    #   - Should log access to high-sensitivity objects for monitoring (A09).
    path("<int:pk>/", views.detail, name="detail"),
]
