#!/usr/bin/env python
"""
Ultimate stressor / fuzz tester for ShadowScan (DarkWebLeakFinder).

What it does:
  - Optionally logs in once using /accounts/login/ with a valid user.
  - Runs for DURATION_SECONDS (default: 1 hour).
  - Uses MAX_WORKERS threads to hammer endpoints concurrently.
  - Tries to provoke:
      * 4xx: 400/401/403/404/405 from bad methods, invalid paths, invalid PKs, etc.
      * 5xx: by pushing weird inputs, large payloads, and malformed values.
  - Fuzzes form inputs with:
      * XSS-like payloads
      * SQL injection-ish patterns
      * Long strings, unicode noise, path traversal-ish strings, etc.
      * VERY LARGE bodies on login/register to exercise body-handling paths.
  - Logs each request and a final summary by status code and exceptions.

Config flags:
  - ENABLE_DESTRUCTIVE controls whether we send POSTs to endpoints
    that create or change data (add identity, scan_target, register spam).
  - ENABLE_LOGIN controls whether we attempt to authenticate first.
"""

import concurrent.futures
import os
import random
import string
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List

import requests

# ------------------------------
# Configuration
# ------------------------------

BASE_URL = "http://127.0.0.1:8000"  # dev server base URL
USERNAME = ""                        # valid Django user (if using ENABLE_LOGIN)
PASSWORD = ""                        # that user's password

DURATION_SECONDS = 3600              # 1 hour
MAX_WORKERS = 20                     # higher concurrency ("double the stress")

# If True, will send POSTs to endpoints that create/change data
# (add identity, scan target, register). This can:
#   - Hammer HIBP/Shodan/external APIs
#   - Pollute your DB with junk users/identities
ENABLE_DESTRUCTIVE = False

# Toggle: set to False when you want to fuzz as an anonymous user.
ENABLE_LOGIN = False

# ------------------------------
# Data structures & globals
# ------------------------------

@dataclass
class RequestSpec:
    method: str
    path: str
    desc: str
    # kind controls how we build the payload:
    # "plain", "email_form", "scan_form",
    # "login_form", "login_big_form",
    # "register_form", "register_big_form"
    kind: str


STATUS_COUNTER = Counter()
LOCK = threading.Lock()

LOG_FILE = None  # will be opened in main()

# ------------------------------
# Logging helper
# ------------------------------


def log_line(msg: str) -> None:
    """
    Thread-safe logging to both stdout and a log file in the project root.
    """
    global LOG_FILE
    with LOCK:
        print(msg)
        if LOG_FILE is not None:
            LOG_FILE.write(msg + "\n")
            LOG_FILE.flush()


# ------------------------------
# Fuzz payloads
# ------------------------------

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\" onmouseover=\"alert(1)",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "'; DROP TABLE users; --",
    "admin'--",
    "1; SELECT pg_sleep(5); --",
]

PATHISH_PAYLOADS = [
    "../../etc/passwd",
    "..\\..\\windows\\system32",
    "/../../../var/log/auth.log",
]

UNICODE_NOISE = [
    "测试测试",
    "💣💥🔥",
    "АБВГДЕёжзий",
    "𝓈𝓆𝓁𝒾𝓃𝒿𝑒𝒸𝓉",
]

LONG_STR = "A" * 8000
LONG_EMAIL_LOCAL = "a" * 200

GENERIC_FUZZ = (
    XSS_PAYLOADS
    + SQLI_PAYLOADS
    + PATHISH_PAYLOADS
    + UNICODE_NOISE
    + [
        LONG_STR,
        f"{LONG_EMAIL_LOCAL}@example.com",
        "",
        "null",
        "undefined",
        "NaN",
    ]
)


def random_string(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def random_fuzz() -> str:
    return random.choice(GENERIC_FUZZ)


# ------------------------------
# Login helper
# ------------------------------


def login(session: requests.Session) -> bool:
    """
    Attempt to log in via /accounts/login/.

    Returns:
      True  -> login appears successful (we're not on the login page after POST).
      False -> login failed (still on login page or unexpected status).

    This function NEVER exits the process; the caller decides what to do
    (e.g., continue fuzzing as anonymous).
    """
    login_url = f"{BASE_URL}/accounts/login/"

    # GET the login page to obtain CSRF cookie
    try:
        r = session.get(login_url, timeout=10)
        r.raise_for_status()
    except Exception as exc:
        log_line(f"[LOGIN] Failed to GET login page: {exc}")
        return False

    csrftoken = session.cookies.get("csrftoken", "")

    payload = {
        "username": USERNAME,
        "password": PASSWORD,
        "csrfmiddlewaretoken": csrftoken,
        "next": "/",
    }

    headers = {"Referer": login_url}

    try:
        # Allow redirects so we end up wherever Django sends us
        r = session.post(
            login_url,
            data=payload,
            headers=headers,
            timeout=10,
            allow_redirects=True,
        )
    except Exception as exc:
        log_line(f"[LOGIN] Exception during POST to login: {exc}")
        return False

    if r.status_code not in (200, 302):
        log_line(f"[LOGIN] Unexpected status: {r.status_code}")
        log_line(f"[LOGIN] Final URL: {r.url}")
        return False

    # If still on login page, creds likely invalid
    if "/accounts/login/" in r.url and r.status_code == 200:
        log_line("[LOGIN] Still on login page, check USERNAME/PASSWORD.")
        log_line(f"[LOGIN] Final URL: {r.url}")
        return False

    log_line(f"[LOGIN] Logged in as {USERNAME or '<blank>'}, status={r.status_code}, redirect={r.url}")
    return True


# ------------------------------
# Request specs builder
# ------------------------------


def build_request_specs() -> List[RequestSpec]:
    """
    Build a list of baseline request types.
    We mix:
      - Normal GETs
      - 404s
      - Invalid PKs
      - Bad methods
      - Form fuzz targets (including big-body variants)
    """
    bad_pk = 999999
    long_qs = "x" * 8000

    specs: List[RequestSpec] = [
        # Core/dashboard
        RequestSpec("GET", "/", "dashboard root", "plain"),
        RequestSpec("GET", "/dashboard/", "dashboard home", "plain"),
        RequestSpec("GET", "/does-not-exist/", "forced 404", "plain"),

        # Breaches identity details (including invalid pk/invalid type)
        RequestSpec("GET", "/identity/1/", "identity detail pk=1", "plain"),
        RequestSpec("GET", f"/identity/{bad_pk}/", "identity detail large pk 404", "plain"),
        RequestSpec("GET", "/identity/not-an-int/", "identity detail invalid pk", "plain"),

        # ThreatMap API (valid + invalid source + long qs)
        RequestSpec("GET", "/threatmap/api/points/", "threatmap default", "plain"),
        RequestSpec("GET", "/threatmap/api/points/?source=layer7_origin", "threatmap layer7_origin", "plain"),
        RequestSpec("GET", "/threatmap/api/points/?source=foo", "threatmap invalid source", "plain"),
        RequestSpec("GET", f"/threatmap/api/points/?source={long_qs}", "threatmap long source", "plain"),

        # Ticker API (valid + noisy qs)
        RequestSpec("GET", "/api/ticker/", "ticker feed", "plain"),
        RequestSpec("GET", f"/api/ticker/?noise={long_qs}", "ticker feed long query", "plain"),

        # Weird methods to provoke 405 / 4xx
        RequestSpec("DELETE", "/threatmap/api/points/", "DELETE threatmap", "plain"),
        RequestSpec("PUT", "/api/ticker/", "PUT ticker feed", "plain"),
        RequestSpec("POST", "/does-not-exist/", "POST invalid path", "plain"),

        # Login fuzz (invalid creds, fuzz username/password)
        RequestSpec("POST", "/accounts/login/", "login form fuzz", "login_form"),
        # Big-body login to exercise body-handling behavior
        RequestSpec("POST", "/accounts/login/", "login big body", "login_big_form"),

        # Register fuzz
        RequestSpec("POST", "/accounts/register/", "register form fuzz", "register_form"),
        # Big-body register (large passwords) to exercise body-handling
        RequestSpec("POST", "/accounts/register/", "register big body", "register_big_form"),
    ]

    if ENABLE_DESTRUCTIVE:
        specs.extend(
            [
                # Add identity fuzz (email field)
                RequestSpec("POST", "/add/", "add identity fuzz", "email_form"),
                # Scan target fuzz (target field)
                RequestSpec("POST", "/scan/", "scan_target fuzz", "scan_form"),
            ]
        )

    return specs


# ------------------------------
# Request sender
# ------------------------------


def send_one(session: requests.Session, spec: RequestSpec, idx: int) -> None:
    """
    Send a single request and log the result.
    """
    url = f"{BASE_URL}{spec.path}"
    method = spec.method.upper()

    try:
        if method == "GET":
            resp = session.get(url, timeout=10)

        elif method == "POST":
            csrftoken = session.cookies.get("csrftoken", "")

            # Default POST payload: just CSRF token.
            data: Dict[str, str] = {"csrfmiddlewaretoken": csrftoken}
            headers: Dict[str, str] = {"Referer": url}

            # ~3 MB body chunk to exercise large-body behavior
            BIG = "X" * (3 * 1024 * 1024)

            if spec.kind == "email_form":
                # Fuzz the email field
                email_payloads = [
                    f"test+{random_string()}@example.com",
                    random_fuzz(),
                ]
                data["email"] = random.choice(email_payloads)

            elif spec.kind == "scan_form":
                # Fuzz the target field
                target_payloads = [
                    "127.0.0.1",
                    "localhost",
                    f"{random_string()}.example.invalid",
                    random_fuzz(),
                ]
                data["target"] = random.choice(target_payloads)

            elif spec.kind == "login_form":
                # Fuzz username/password
                login_payloads = [
                    (USERNAME, random_fuzz()),
                    (random_fuzz(), PASSWORD),
                    (random_fuzz(), random_fuzz()),
                ]
                user_val, pass_val = random.choice(login_payloads)
                data.update(
                    {
                        "username": user_val,
                        "password": pass_val,
                        "next": "/",
                    }
                )

            elif spec.kind == "login_big_form":
                # Huge body to exercise form/body handling on login
                data.update(
                    {
                        "username": BIG,
                        "password": BIG,
                        "next": "/",
                    }
                )

            elif spec.kind == "register_form":
                # Fuzz registration fields (username/password1/password2)
                user_val = random_fuzz()[:150] or random_string()
                pwd_val = random_fuzz() or random_string()
                data.update(
                    {
                        "username": user_val,
                        "password1": pwd_val,
                        "password2": pwd_val,
                    }
                )

            elif spec.kind == "register_big_form":
                # Huge body for registration; mismatch passwords so no real user is created
                data.update(
                    {
                        "username": random_string(12),
                        "password1": BIG,
                        "password2": BIG + "mismatch",
                    }
                )

            # For generic POSTs (if any), we just send CSRF + whatever is in data
            resp = session.post(url, data=data, headers=headers, timeout=30)

        elif method in ("DELETE", "PUT", "PATCH"):
            resp = session.request(method, url, timeout=10)

        else:
            resp = session.get(url, timeout=10)

        status = resp.status_code
        with LOCK:
            STATUS_COUNTER[status] += 1

        prefix = "[OK]   "
        if 400 <= status <= 499:
            prefix = "[4xx] "
        elif 500 <= status <= 599:
            prefix = "[5xx] "

        log_line(f"{prefix}#{idx:06d} {method} {spec.path} -> {status} ({spec.desc})")

    except Exception as e:
        with LOCK:
            STATUS_COUNTER["EXC"] += 1
        log_line(f"[ERR]  #{idx:06d} {method} {spec.path} -> exception: {e}")


# ------------------------------
# Main loop
# ------------------------------


def main() -> None:
    global LOG_FILE

    # Open log file in project root with timestamped name
    root_dir = os.path.dirname(os.path.abspath(__file__))
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(root_dir, f"stressor_{ts}.log")
    LOG_FILE = open(log_path, "a", encoding="utf-8")
    log_line(f"[INFO] Logging to {log_path}")

    session = requests.Session()

    # Optional login, depending on ENABLE_LOGIN
    if ENABLE_LOGIN:
        ok = login(session)
        if not ok:
            log_line("[LOGIN] Login failed; continuing as anonymous session.")
    else:
        log_line("[LOGIN] Skipping login; running as anonymous user.")

    specs = build_request_specs()

    log_line(f"[INFO] Running for {DURATION_SECONDS} seconds (~{DURATION_SECONDS/60:.1f} minutes)")
    log_line(f"[INFO] Using {MAX_WORKERS} workers")
    log_line(f"[INFO] Destructive POSTs enabled: {ENABLE_DESTRUCTIVE}")
    log_line(f"[INFO] Login enabled: {ENABLE_LOGIN}")
    log_line("")

    start = time.time()
    end = start + DURATION_SECONDS

    req_idx = 0

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures: List[concurrent.futures.Future] = []

            # Continuously schedule requests until time is up
            while time.time() < end:
                req_idx += 1
                spec = random.choice(specs)
                futures.append(executor.submit(send_one, session, spec, req_idx))

            # Wait for in-flight requests to complete
            for f in concurrent.futures.as_completed(futures):
                _ = f.result()

        log_line("\n=== Summary ===")
        total = sum(v for k, v in STATUS_COUNTER.items() if k != "EXC")
        for status, count in sorted(STATUS_COUNTER.items(), key=lambda x: str(x[0])):
            log_line(f"{status}: {count}")
        log_line(f"Total responses (excluding exceptions): {total}")

    finally:
        if LOG_FILE is not None:
            LOG_FILE.close()
            LOG_FILE = None


if __name__ == "__main__":
    main()
