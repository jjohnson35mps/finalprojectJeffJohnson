# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# DarkWebLeakFinder/wsgi.py
# -------------------------
# WSGI entrypoint for the Django project.
#
# OWASP Top 10 touchpoints:
#   - A02: Security Misconfiguration
#       * This module relies on DJANGO_SETTINGS_MODULE being set to a
#         secure settings module where DEBUG is disabled and production
#         security settings (ALLOWED_HOSTS, HTTPS, secure cookies, etc.)
#         are configured correctly.
#   - A05: Identification & Authentication Failures
#       * Actual auth logic lives in Django views/middleware; this file
#         simply exposes the application object to the WSGI server.
#   - A09: Security Logging & Monitoring
#       * Logging configuration is handled in settings.py; the WSGI
#         layer should be fronted by a well-configured server (e.g.
#         gunicorn + nginx) that also logs access and errors.

import os

from django.core.wsgi import get_wsgi_application


# ---------------------------------------------------------------------------
# Configure the Django settings module
# ---------------------------------------------------------------------------
# In production, the environment should *already* define DJANGO_SETTINGS_MODULE
# (e.g., via systemd unit, container env, or web server config).
# This fallback ensures local/dev usage works but can be overridden externally.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "DarkWebLeakFinder.settings")


# ---------------------------------------------------------------------------
# WSGI application callable
# ---------------------------------------------------------------------------
# Expose the WSGI application object that a WSGI-compliant server
# (gunicorn, uWSGI, mod_wsgi, etc.) will use to forward HTTP requests
# into Django.
application = get_wsgi_application()
