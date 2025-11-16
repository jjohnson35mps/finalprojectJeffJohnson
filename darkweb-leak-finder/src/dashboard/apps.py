"""
INF601 - Advanced Programming in Python
Jeff Johnson
Final Project

dashboard/apps.py

Django application configuration for the `dashboard` app. This class is
picked up by Django via INSTALLED_APPS and can be used to attach app-level
signals or startup logic later.

OWASP Top 10 touchpoints (high level):
  - A02: Security Misconfiguration
      * Centralizing app config in AppConfig makes it easier to reason
        about where any future startup logic (signals, checks, etc.) lives.
      * No secrets or environment-specific values are stored here.
  - A01/A07 (Broken Access Control / Identification & Authentication Failures)
      * All access control for views, templates, and APIs in `dashboard`
        should be enforced in views, URL patterns, and decorators, not
        in this config file. This file intentionally contains no logic
        that changes authentication behavior.
"""

from django.apps import AppConfig


class DashboardConfig(AppConfig):
    """
    Application configuration for the `dashboard` app.

    Attributes:
        default_auto_field:
            Uses BigAutoField for primary keys by default, which avoids
            integer overflow and is the recommended Django default.
        name:
            The dotted path Django uses to register this app. This must
            match the app’s Python package name.
    """
    default_auto_field = "django.db.models.BigAutoField"
    name = "dashboard"
