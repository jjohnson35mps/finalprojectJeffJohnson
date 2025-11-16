# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# DarkWebLeakFinder/urls.py
# -------------------------
# Root URL configuration for the project.
#
# OWASP Top 10 touchpoints:
#   - A01: Broken Access Control
#       * Actual access control is enforced in views (e.g., @login_required),
#         but URL structure keeps auth-related routes grouped under /accounts/.
#   - A02: Security Misconfiguration
#       * Uses Django’s built-in auth views and admin, which come with secure
#         defaults (CSRF, session handling) when combined with middleware.
#   - A05: Identification & Authentication Failures
#       * Leverages Django’s auth system and login/logout views instead of
#         custom password/session code.
#   - A09: Security Logging & Monitoring
#       * Request errors and authentication failures are logged via Django’s
#         logging configuration in settings.py.
#   - A04: Insecure Design (routing / separation of concerns)
#       * Each Django app exposes its own URLConf which is included here
#         (breaches, dashboard, threatmap, security_ticker, core), keeping
#         functionality modular and limiting unintended coupling.

from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from core import views as core_views


urlpatterns = [
    # ---------------------------------------------------------------------
    # Django admin
    # ---------------------------------------------------------------------
    # In a real deployment you would:
    #   - Protect /admin/ with strong authentication (and possibly IP allowlists).
    #   - Consider changing the URL prefix or requiring 2FA.
    path("admin/", admin.site.urls),

    # ---------------------------------------------------------------------
    # Authentication & registration
    # ---------------------------------------------------------------------
    # NOTE: More specific /accounts/* routes are declared BEFORE the broader
    # "accounts/" include so they take precedence. This avoids surprising
    # routing behavior and makes it explicit which views handle login/register.
    #
    # Explicit login view using a custom template.
    # Using Django’s LoginView avoids re-implementing auth logic.
    path(
        "accounts/login/",
        auth_views.LoginView.as_view(template_name="registration/login.html"),
        name="login",
    ),

    # Registration view (coursework-only; not part of Django core auth)
    path("accounts/register/", core_views.register, name="register"),

    # Stand-alone logout route at /logout/.
    # We rely on LOGOUT_REDIRECT_URL in settings.py for the redirect target
    # instead of hard-coding next_page here.
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),

    # Built-in Django auth URLs under /accounts/:
    #   /accounts/password_change/, /accounts/password_reset/, etc.
    # These views:
    #   - Use CSRF protection
    #   - Use Django’s session middleware
    #   - Avoid exposing raw credentials in URLs (A05).
    path("accounts/", include("django.contrib.auth.urls")),

    # ---------------------------------------------------------------------
    # Core application routes
    # ---------------------------------------------------------------------
    # Breaches app:
    #   - Handles email breach lookups, identity detail, and Shodan-based scans.
    #   - Access control is enforced in breaches.views via @login_required.
    path("", include(("breaches.urls", "breaches"), namespace="breaches")),

    # Dashboard app:
    #   - Higher-level overview pages / landing dashboard.
    path(
        "dashboard/",
        include(("dashboard.urls", "dashboard"), namespace="dashboard"),
    ),

    # Core app:
    #   - Currently just delegates to dashboard and breaches URLs (see core/urls.py).
    #   - Keeping this app separate supports modular design and clearer routing.
    path("core/", include(("core.urls", "core"), namespace="core")),

    # ---------------------------------------------------------------------
    # Security ticker API
    # ---------------------------------------------------------------------
    # Read-only ticker API endpoint used by the front-end to show recent
    # vulnerability headlines. Must not expose secrets or internal logs.
    #   - A03: Injection
    #       * Any query params should be validated in security_ticker.views
    #         before being used in downstream API calls.
    path(
        "api/ticker/",
        include(
            ("security_ticker.urls", "security_ticker"),
            namespace="security_ticker",
        ),
    ),

    # ---------------------------------------------------------------------
    # Threat map API & views
    # ---------------------------------------------------------------------
    # ThreatMap app:
    #   - Provides JSON and front-end views for global attack heat map.
    #   - External API tokens are handled in settings/env (not in URLs).
    #   - A03: Injection
    #       * Query parameters (e.g., source) are validated in threatmap.views.
    path(
        "threatmap/",
        include(("threatmap.urls", "threatmap"), namespace="threatmap"),
    ),
]
