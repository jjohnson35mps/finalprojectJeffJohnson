# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/breaches/urls.py
#
# URL routing for the "breaches" app.
#
# OWASP Top 10 considerations:
#   - A01/A07 (Access Control & AuthN/Z):
#       * These URLs do NOT enforce access control by themselves.
#       * Views must use login_required / permission checks to ensure only
#         authorized users can view or modify identities and scan results.
#   - A03/A05 (Injection / Input Handling):
#       * Path parameters (e.g., <int:pk>) are treated as untrusted input.
#         Views must use get_object_or_404 or equivalent and avoid building
#         raw SQL from these values.
#   - A05 (Security Misconfiguration):
#       * Keep routes explicit and avoid unnecessary duplicate/ambiguous
#         endpoints. This file contains only the minimal, documented routes.

from django.urls import path

from . import views

# Namespace for URL reversing: "breaches:dashboard", etc.
app_name = "breaches"

urlpatterns = [
    # ------------------------------------------------------------------
    # Dashboard / landing page
    # ------------------------------------------------------------------
    path("", views.dashboard, name="dashboard"),

    # ------------------------------------------------------------------
    # EmailIdentity: create, view, scan, delete
    # ------------------------------------------------------------------
    # Add a new email identity to monitor.
    path("add/", views.add_identity, name="add"),

    # Detail view for a single EmailIdentity and its breach hits.
    path("identity/<int:pk>/", views.identity_detail, name="identity_detail"),

    # Trigger a HIBP scan for a specific EmailIdentity.
    path("identity/<int:pk>/scan/", views.scan_identity, name="scan_identity"),

    # Delete an EmailIdentity and its associated breach hits.
    path("identity/<int:pk>/delete/", views.delete_identity, name="delete_identity"),

    # ------------------------------------------------------------------
    # Shodan-like scans: create and delete host findings
    # ------------------------------------------------------------------
    # Submit a domain/IP for a new Shodan-style scan.
    path("scan/", views.scan_target, name="scan_target"),

    # Remove a stored ShodanFinding by primary key.
    path("scan/<int:pk>/delete/", views.delete_scan, name="delete_scan"),
]
