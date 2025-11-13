#!/usr/bin/env python
# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
"""Django's command-line utility for administrative tasks."""
#!/usr/bin/env python
"""
manage.py — Django's command-line utility for administrative tasks.

Enhancements:
- Loads environment variables from a .env file before Django boots.
- Looks for .env in the REPO ROOT (preferred) and falls back to src/.env.
- Fails gracefully if python-dotenv is not installed (won't block Django).
"""
import os
import sys
from pathlib import Path  # needed for cross-platform path handling

def _load_env() -> None:
    """
    Load environment variables from a .env file if present.

    Search order:
      1) <repo_root>/.env     (repo_root is parent of this file's directory)
      2) <here>/.env          (allows src/.env as a fallback)

    This lets you keep secrets (e.g., HIBP_API_KEY) out of source code.
    """
    here = Path(__file__).resolve().parent
    repo_root = here.parent
    candidates = [repo_root / ".env", here / ".env"]

    try:
        from dotenv import load_dotenv  # pip install python-dotenv
    except Exception:
        load_dotenv = None  # if missing, just skip silently

    if load_dotenv:
        for env_path in candidates:
            if env_path.exists():
                load_dotenv(env_path)
                break  # stop at the first .env found

def main() -> None:
    """Run administrative tasks (e.g., runserver, migrate, createsuperuser)."""
    _load_env()  # ensure os.getenv(...) works inside settings and services
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "DarkWebLeakFinder.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Is it installed, and is your virtualenv active?"
        ) from exc
    execute_from_command_line(sys.argv)

if __name__ == "__main__":
    main()
