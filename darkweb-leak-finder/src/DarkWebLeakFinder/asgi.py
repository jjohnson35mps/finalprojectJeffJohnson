# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# src/DarkWebLeakFinder/asgi.py
# -----------------------------
# ASGI entrypoint for the DarkWebLeakFinder Django project.
#
# OWASP Top 10 touchpoints:
#   - A02: Security Misconfiguration
#       * This module wires Django to an ASGI server (e.g., uvicorn, daphne).
#       * It should NOT contain secrets, debug flags, or environment-specific
#         configuration; those belong in settings and environment variables.
#       * In production, ensure that:
#           - DJANGO_SETTINGS_MODULE points to a hardened settings module
#             (e.g., DarkWebLeakFinder.settings_prod).
#           - DEBUG is disabled and secure middleware/settings are enabled.
#   - A09: Security Logging & Monitoring
#       * Any logging or security middleware is configured in settings.py.
#       * This file just exposes the ASGI application object; do not add
#         request-handling logic here.

import os

from django.core.asgi import get_asgi_application


# ---------------------------------------------------------------------------
# Configure the default settings module for the 'asgi' command
# ---------------------------------------------------------------------------
# For local/dev and coursework, we default to the main settings module.
# In a real deployment, you can override this environment variable at the
# process level to point to a different settings file:
#     DJANGO_SETTINGS_MODULE=DarkWebLeakFinder.settings_prod
#
# Using os.environ.setdefault means:
#   - If DJANGO_SETTINGS_MODULE is already defined in the environment,
#     we respect that (safer for production).
#   - Otherwise, we fall back to DarkWebLeakFinder.settings.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "DarkWebLeakFinder.settings")


# ---------------------------------------------------------------------------
# ASGI application object
# ---------------------------------------------------------------------------
# The ASGI server (uvicorn/daphne/etc.) imports this module and uses the
# `application` callable as the entrypoint for HTTP/WebSocket handling.
application = get_asgi_application()
