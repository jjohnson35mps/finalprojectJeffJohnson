#!/usr/bin/env python
"""
INF601 - Advanced Programming in Python
Jeff Johnson
Final Project

Simple HTTP route checker.

What it does:
  - Sends GET requests to a list of hard-coded paths on your dev server.
  - Follows redirects (e.g., to /accounts/login/) and checks for a final 200.
  - Prints PASS/FAIL with the returned status code.

OWASP notes:
  - Only safe GET requests are used; no state-changing POST/DELETE calls.
  - No secrets are embedded; base URL is localhost/dev-only.
  - This is a diagnostic helper and should not be exposed as part of the app.
"""

from __future__ import annotations

import sys
from typing import List, Tuple

import requests


# Base URL of your running Django dev server.
# Change this if you’re running on a different port/host.
BASE_URL = "http://127.0.0.1:8000"

# Each tuple: (description, path)
# NOTE: Paths with pk=1 assume you have an object with pk=1; adjust as needed.
ENDPOINTS: List[Tuple[str, str]] = [
    # Project-level / auth / admin
    ("Admin index", "/admin/"),
    ("Login page", "/accounts/login/"),
    ("Register page", "/accounts/register/"),
    ("Logout endpoint", "/logout/"),

    # Breaches app (root include)
    ("Breaches dashboard (root)", "/"),
    ("Add identity form", "/add/"),
    ("Identity detail (pk=1)", "/identity/1/"),
    ("Identity scan (pk=1)", "/identity/1/scan/"),
    ("Identity delete (pk=1)", "/identity/1/delete/"),
    ("Scan target form", "/scan/"),
    ("Scan delete (pk=1)", "/scan/1/delete/"),

    # Dashboard app
    ("Dashboard home", "/dashboard/"),
    ("Dashboard detail (pk=1)", "/dashboard/1/"),

    # Security ticker
    ("Security ticker feed", "/api/ticker/"),

    # Threat map
    ("Threatmap points API", "/threatmap/api/points/"),
]


def check_endpoint(description: str, path: str) -> bool:
    """
    Build the full URL, send a GET request, and return True if the
    final status code after redirects is 200.

    We allow redirects so that login-protected paths which redirect to
    /accounts/login/ still result in a 200 (for the login page).
    """
    url = BASE_URL.rstrip("/") + path
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
    except requests.RequestException as exc:
        print(f"[FAIL] {description:35} {path:25} -> ERROR: {exc}")
        return False

    if resp.status_code == 200:
        print(f"[PASS] {description:35} {path:25} -> 200")
        return True
    else:
        print(f"[FAIL] {description:35} {path:25} -> {resp.status_code}")
        return False


def main() -> int:
    """
    Iterate over all endpoints and check them.
    Exit code is 0 if all are 200, else 1 (useful for CI or scripting).
    """
    print("=" * 72)
    print("Simple HTTP route check – expecting 200 OK for each endpoint")
    print(f"Base URL: {BASE_URL}")
    print("=" * 72)

    all_ok = True
    for desc, path in ENDPOINTS:
        ok = check_endpoint(desc, path)
        if not ok:
            all_ok = False

    print("=" * 72)
    print("All endpoints OK." if all_ok else "Some endpoints FAILED.")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
