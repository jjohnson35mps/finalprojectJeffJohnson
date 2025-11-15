"""
INF601 - Advanced Programming in Python
Jeff Johnson
Final Project

dashboard/admin.py (or core admin placeholder)

This module exists so Django can auto-discover admin customizations for
the app. At the moment we don't expose any additional models in the
Django admin beyond the built-ins, so this file is intentionally minimal.

OWASP Top 10 touchpoints:
  - A01: Broken Access Control / A07: Identification & Authentication
      * Access to /admin/ is protected by Django's authentication and
        staff/superuser flags; no public endpoints are defined here.
  - A02: Security Misconfiguration:
      * Any admin hardening (HTTPS, secure cookies, strong passwords,
        admin URL renaming) is handled in settings and deployment, not
        in this file.
  - A03/A05/A06 (Injection / XSS / Insecure design):
      * This file declares no views, templates, or dynamic logic that
        would parse user input, so there is no direct injection surface.
"""

# Import the Django admin site so this module is discovered by Django’s
# admin auto-discovery. If you later add models for this app, you’ll
# register them here with @admin.register(...) or admin.site.register(...).
from django.contrib import admin  # noqa: F401
