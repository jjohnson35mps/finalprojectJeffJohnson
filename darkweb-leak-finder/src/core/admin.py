# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# core/admin.py (or project-level admin module)
# ---------------------------------------------
# Django admin integration for this project.
# Models are registered in their respective app-level admin.py files.
# This module exists so Django can auto-discover admin customizations.
#
# OWASP Top 10 touchpoints:
#   - A01/A07 (Access Control & Auth):
#       Django admin is protected by built-in authentication/permissions.
#       Any sensitive models should be registered with care and require
#       staff/superuser access.
#   - A02 (Security Misconfiguration):
#       Admin site should only be exposed over HTTPS in production and
#       restricted to trusted users/IPs via deployment settings (not here).

from django.contrib import admin  # noqa: F401

"""
This module currently relies on app-level admin configurations.

- Each Django app (e.g., `breaches`, `security_ticker`, `threatmap`)
  defines its own `admin.py` to register models with the admin site.
- Importing `django.contrib.admin` here ensures Django loads the admin
  subsystem as part of the project.

If you later need global admin customizations (e.g., custom site header,
custom index, or global actions), implement them in this module.
"""
