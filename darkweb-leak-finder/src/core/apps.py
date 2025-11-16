# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# core/apps.py
# ---------------------------------------------
# Django "core" app configuration.
# This app holds project-wide utilities (layouts, base templates, shared
# CSS/JS, common models/mixins, etc.).
#
# OWASP Top 10 touchpoints:
#   - A02: Security Misconfiguration
#       * App-level security settings (middlewares, auth, etc.) belong
#         in settings.py, not in AppConfig.
#       * This module should not hard-code secrets, API keys, or
#         environment-specific configuration.
#   - A01/A07: Access Control & Auth
#       * Any core middleware or signals that enforce access control
#         should be registered here in a predictable, auditable way
#         (for example, in ready()).
#
#   This file currently provides a minimal, explicit AppConfig so Django
#   can discover the "core" application and attach any future hooks.

from django.apps import AppConfig


class CoreConfig(AppConfig):
    """
    Core application configuration.

    - default_auto_field:
        Uses BigAutoField for primary keys by default, which helps avoid
        overflow on large tables.

    - name:
        Canonical dotted path for this app; used by Django to locate
        templates, static files, and app-specific code.

    Security notes:
      * Do not read environment variables or secrets here; keep those
        in settings.py or dedicated config modules.
      * If you ever override AppConfig.ready(), limit it to safe,
        idempotent startup logic (signals, logging config, etc.).
    """
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"
