#!/usr/bin/env python
# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# manage.py-like entrypoint for Django admin tasks.
#
# OWASP Top 10 considerations:
#   - A01:2021 – Broken Access Control
#       * This script is a local CLI tool; it is not exposed over HTTP.
#       * Access is controlled by the host OS user permissions.
#   - A02/A05:2021 – Cryptographic Failures / Security Misconfiguration
#       * Sensitive values (API keys, secrets) are pulled from environment
#         variables via a .env file, not hard-coded in source.
#       * In production, .env files should be protected by file permissions
#         or replaced by a secrets manager (Azure Key Vault, etc.).
#   - A09:2021 – Security Logging and Monitoring Failures
#       * Any logging configuration is handled in Django settings; this
#         script just bootstraps Django.

import os
import sys
from pathlib import Path  # Cross-platform filesystem paths


# ---------------------------------------------------------------------------
# Environment loading helper
# ---------------------------------------------------------------------------

def _load_env() -> None:
    """
    Load environment variables from a .env file if present.

    Search order:
      1) <repo_root>/.env
         - repo_root is the parent directory of this file's directory.
         - Recommended place for local development secrets.
      2) <here>/.env
         - Allows src/.env as a fallback (e.g., when running from src/).

    Rationale:
      - Keeps secrets such as HIBP_API_KEY, SHODAN_API_KEY, etc. out of
        the committed source code.
      - Works nicely with python-dotenv during development.

    OWASP notes:
      - A02/A05 (Cryptographic Failures / Misconfiguration):
          * This pattern discourages hard-coded secrets.
          * In production, prefer environment variables or a dedicated
            secrets store instead of .env files on disk.
    """
    here = Path(__file__).resolve().parent
    repo_root = here.parent
    candidates = [repo_root / ".env", here / ".env"]

    try:
        # Optional dependency; used only if installed.
        from dotenv import load_dotenv  # type: ignore[import]
    except Exception:
        load_dotenv = None  # If python-dotenv is missing, we simply skip

    if load_dotenv:
        for env_path in candidates:
            if env_path.exists():
                load_dotenv(env_path)
                break  # Stop at the first .env found


# ---------------------------------------------------------------------------
# Main Django management entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Run Django administrative commands (runserver, migrate, createsuperuser, etc.).

    Steps:
      1) Load environment variables from .env (if available).
      2) Set the default Django settings module.
      3) Delegate to Django's management command runner.

    OWASP notes:
      - A05 (Security Misconfiguration):
          * This script does not enable DEBUG or modify security-related
            settings; that is handled in DarkWebLeakFinder.settings.
          * Proper separation keeps configuration in one place.
    """
    # Ensure environment variables are available to settings and services.
    _load_env()

    # Default to our project settings module if not already configured.
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "DarkWebLeakFinder.settings")

    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        # Clear, user-friendly error if Django is not installed or the venv
        # is not activated.
        raise ImportError(
            "Couldn't import Django. Is it installed, and is your virtualenv active?"
        ) from exc

    # Hand off control to Django's management framework.
    execute_from_command_line(sys.argv)


# ---------------------------------------------------------------------------
# Script entrypoint guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Standard Python entrypoint to allow `python manage.py <command>` usage.
    main()
