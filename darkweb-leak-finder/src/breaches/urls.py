# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/breaches/urls.py
#
# URL routing for the "breaches" app.
#
# OWASP Top 10 considerations:
#   - A01/A07 (Broken Access Control & AuthN/Z):
#       * These URLs do NOT enforce access control by themselves.
#       * Views must use @login_required and, where appropriate, object-level
#         checks (e.g., ownership) to ensure only authorized users can view
#         or modify identities and scan results.
#   - A03 (Injection / Input Handling):
#       * Path parameters (e.g., <int:pk>) are untrusted input. Views must
#         use get_object_or_404 (or equivalent) and avoid building raw SQL
#         or unsafe API calls directly from these values.
#   - A02 (Security Misconfiguration):
#       * Routes are explicit and minimal; we avoid overlapping or ambiguous
#         URL patterns which can make access control and logging harder.
#   - A04 (Insecure Design):
#       * Breach-related functionality is isolated in this app and URLConf,
#         which limits the blast radius of future changes and keeps concerns
#         separated from threat map / ticker / core views.
#   - A09 (Security Logging & Monitoring):
#       * The views behind these routes should log key events (e.g., scans,
#         deletions) via the "breaches" logger configured in settings.py.

from django.urls import path

from . import views

# Namespace for URL reversing: "breaches:dashboard", "breaches:add", etc.
app_name = "breaches"

urlpatterns = [
    # ------------------------------------------------------------------
    # Dashboard / landing page
    # ------------------------------------------------------------------
    # Main dashboard:
    #   - Lists monitored email identities.
    #   - Shows recent Shodan-like scan results.
    # Access control:
    #   - Views.dashboard should require authentication and avoid leaking
    #     information about identities or hosts to anonymous users (A01).
    path("", views.dashboard, name="dashboard"),

    # ------------------------------------------------------------------
    # EmailIdentity: create, view, scan, delete
    # ------------------------------------------------------------------
    # Add a new email identity to monitor.
    #   - Form input (email address) must be validated and normalized
    #     server-side; do not trust only client-side validation (A03/A05).
    path("add/", views.add_identity, name="add"),

    # Detail view for a single EmailIdentity and its breach hits.
    #   - Must ensure the requesting user is allowed to view this identity
    #     (e.g., ownership or role-based access) to prevent IDOR issues (A01).
    path("identity/<int:pk>/", views.identity_detail, name="identity_detail"),

    # Trigger a HIBP scan for a specific EmailIdentity.
    #   - Should enforce rate limiting and logging in the view to avoid
    #     abuse of the upstream API and to support monitoring (A09).
    path("identity/<int:pk>/scan/", views.scan_identity, name="scan_identity"),

    # Delete an EmailIdentity and its associated breach hits.
    #   - Deletion actions should be POST-only (not GET) and CSRF-protected
    #     in the view/template to avoid CSRF-based data loss (A01/A05).
    path("identity/<int:pk>/delete/", views.delete_identity, name="delete_identity"),

    # ------------------------------------------------------------------
    # Shodan-like scans: create and delete host findings
    # ------------------------------------------------------------------
    # Submit a domain/IP for a new Shodan-style scan.
    #   - Input must be validated as a hostname/IP and not blindly passed
    #     into shell commands or unsafe API parameters (A03).
    path("scan/", views.scan_target, name="scan_target"),

    # Remove a stored ShodanFinding by primary key.
    #   - As with identity deletion, this should be a CSRF-protected POST
    #     or DELETE action in the view to avoid unintended destructive GETs.
    path("scan/<int:pk>/delete/", views.delete_scan, name="delete_scan"),
]
