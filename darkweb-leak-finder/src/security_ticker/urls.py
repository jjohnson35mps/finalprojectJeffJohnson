# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# src/security_ticker/urls.py
#
# Purpose:
#   URL configuration for the `security_ticker` app. Exposes a single
#   endpoint that returns a JSON feed of security / KEV items used by
#   the marquee-style ticker in the UI.
#
# OWASP Top 10 touchpoints (routing layer):
#   - A01: Broken Access Control
#       * This endpoint is read-only and should typically be safe to expose
#         broadly, but access control (if required) must be enforced in
#         `ticker_feed` (the view), not in this file.
#   - A05: Security Misconfiguration
#       * No secrets or environment-specific behavior should be hardcoded here.
#         URL patterns are intentionally simple and predictable.
#   - A09: Security Logging & Monitoring Failures
#       * Any request/response auditing and anomaly detection should be done
#         in middleware or the view, not inside the URLconf.

from django.urls import path

from .views import ticker_feed


# Namespace for reversing URLs:
#   - e.g., {% url 'security_ticker:ticker-feed' %}
app_name = "security_ticker"


# Public URL patterns for this app.
urlpatterns = [
    # JSON ticker feed
    #
    # Example usage:
    #   Front-end JS (ticker.js) fetches from `/api/ticker/` as wired in
    #   the project-level urls.py:
    #       path("api/ticker/", include(("security_ticker.urls", "security_ticker"), ...))
    #
    # Security notes:
    #   - The view must:
    #       * Validate and sanitize any user-supplied input (if added later).
    #       * Avoid returning sensitive internal details in error responses.
    #       * Fail "closed" when upstream feeds are unavailable.
    path("", ticker_feed, name="ticker-feed"),
]
