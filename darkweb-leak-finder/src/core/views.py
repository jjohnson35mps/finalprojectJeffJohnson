# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# src/core/views.py (auth-related helpers)
# ----------------------------------------
# Registration views for Django's built-in User model.
#
# OWASP Top 10 touchpoints:
#   - A01 / A07 (Broken Access Control / Identification & Auth Failures)
#       * Registration is open only to anonymous users; authenticated
#         users are redirected to the dashboard.
#       * Password policy and account protections are enforced via
#         Django's AUTH_PASSWORD_VALIDATORS (configured in settings.py).
#   - A02 (Security Misconfiguration)
#       * No secrets or environment-specific values are read here.
#       * CSRF protection is provided by Django’s middleware and the
#         {% csrf_token %} tag in the template.
#   - A09 (Security Logging & Monitoring)
#       * For a production-grade system, consider logging successful
#         and failed registrations in a separate audit log.

from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect


def register_view(request):
    """
    Handle user registration using Django's built-in UserCreationForm.

    Behavior:
      - If the user is already authenticated:
          * Redirect them to the breaches dashboard, so they can't
            "register again" while logged in (A01/A07).
      - If the request is POST:
          * Bind form data, validate, and create a new user.
          * On success, auto-login the new user and redirect to the
            breaches dashboard.
      - If the request is GET:
          * Render an empty registration form.

    Security notes:
      - Password strength and complexity are enforced by the global
        AUTH_PASSWORD_VALIDATORS configuration.
      - CSRF protection is enabled via middleware + template tag.
      - No sensitive details (e.g., why a registration failed) are
        leaked to the browser beyond standard form errors.
    """
    # Prevent already-authenticated users from seeing the registration page
    if request.user.is_authenticated:
        return redirect("breaches:dashboard")

    if request.method == "POST":
        # Bind POST data to the built-in registration form
        form = UserCreationForm(request.POST)

        if form.is_valid():
            # Create the user account
            user = form.save()

            # Immediately log in the new user to improve UX
            login(request, user)

            # Redirect to the main dashboard after successful registration
            return redirect("breaches:dashboard")
        # If invalid, fall through and re-render form with errors
    else:
        # Unbound form for initial GET request
        form = UserCreationForm()

    # Render the registration template with the form
    return render(request, "registration/register.html", {"form": form})


def register(request):
    """
    Backwards-compatible alias for register_view.

    If any URLconf or legacy code still references `register`, keep it
    working by delegating here. This avoids duplicated logic and keeps
    the security behavior in a single place.
    """
    return register_view(request)
