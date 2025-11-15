# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# App configuration for the "breaches" Django application.
#
# OWASP Top 10 considerations:
#   - A01/A07 (Access Control): This file does not define any runtime permissions.
#     Access enforcement is handled in views (login_required, per-object checks)
#     and in Django's global auth system.
#   - A05 (Security Misconfiguration): The AppConfig should not contain secrets,
#     keys, or environment-specific logic. Keeping this class minimal helps avoid
#     accidental leakage or misconfiguration.
#   - A06 (Insecure Design): AppConfig is intentionally lean so application
#     initialization is predictable and cannot accidentally execute unsafe logic.
#   - A09 (Logging / Monitoring): Logging is handled in service modules, not here.

from django.apps import AppConfig


class BreachesConfig(AppConfig):
    """
    Django application configuration for the 'breaches' app.

    - default_auto_field: ensures new models use BigAutoField (safer defaults).
    - name: the dotted Python import path for the app.
    """
    default_auto_field = "django.db.models.BigAutoField"
    name = "breaches"
