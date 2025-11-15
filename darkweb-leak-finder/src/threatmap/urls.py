# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# ThreatMap URL configuration
#
# Purpose:
#   - Wire up the JSON API endpoint used by the front-end heatmap
#     (Leaflet + ThreatMap dashboard).
#
# OWASP Top 10 touchpoints:
#   - A01:2021 – Broken Access Control:
#       * Any authentication/authorization (e.g., login_required) MUST be
#         enforced in the view (views.threat_points), not here.
#         This module only defines routes.
#   - A05:2021 – Security Misconfiguration:
#       * API path is clearly namespaced under /threatmap/api/ to avoid
#         confusion with unrelated endpoints and make it easier to apply
#         security controls (rate limiting, logging) at the URL level.

from django.urls import path
from . import views

#: Namespace for the threatmap application
app_name = "threatmap"

#: Public URL patterns for the ThreatMap app.
#: NOTE: The view itself should enforce any required authN/authZ.
urlpatterns = [
    # JSON endpoint returning normalized attack "points" for the heatmap.
    # Example: /threatmap/api/points/?source=layer7_origin
    path("api/points/", views.threat_points, name="threat_points"),
]
