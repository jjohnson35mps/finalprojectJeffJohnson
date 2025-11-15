# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# src/security_ticker/apps.py
#
# Purpose:
#   Django application configuration for the "security_ticker" app.
#
# OWASP Top 10 touchpoints:
#   - A02: Cryptographic Failures
#       * This config class must NOT store secrets or API keys. All sensitive
#         configuration (e.g., KEV feed tokens, upstream API keys) should be
#         kept in environment variables or Django settings, not here.
#   - A04: Insecure Design
#       * AppConfig should remain a thin wiring layer. Business logic,
#         network calls, or security-critical behavior must *not* be placed
#         in `ready()` or other lifecycle hooks to avoid surprises and make
#         behavior testable elsewhere.

from django.apps import AppConfig


class SecurityTickerConfig(AppConfig):
    """
    Application configuration for the `security_ticker` app.

    Responsibilities:
      - Declare the app name so Django can discover templates, static assets,
        and templatetags under `security_ticker/`.
      - Set a human-readable `verbose_name` for the Django admin.

    Security notes:
      - Do not add any secret values, API endpoints, or business logic here.
        Keep this class focused on metadata only.
    """
    # Use BigAutoField as the default primary key type for any models
    # defined in this app (future-proofing for large tables).
    default_auto_field = "django.db.models.BigAutoField"

    # Python path to this app; used internally by Django.
    name = "security_ticker"

    # Label shown in Django admin (and other introspection UIs).
    verbose_name = "Security Ticker"
