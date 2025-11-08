# src/breaches/services/hibp.py
# Robust HIBP client with logging and last-call metadata.
from __future__ import annotations
import os, time, logging
from typing import Any, List
from urllib.parse import quote
import requests

logger = logging.getLogger("breaches")

class HibpError(Exception): pass
class HibpAuthError(HibpError): """HIBP API key missing/invalid (HTTP 401)."""
class HibpRateLimitError(HibpError): """Rate limit hit (HTTP 429)."""

class HibpClient:
    BASE = "https://haveibeenpwned.com/api/v3"

    def __init__(self) -> None:
        self.key = (os.getenv("HIBP_API_KEY") or "").strip()
        self.ua  = (os.getenv("HIBP_USER_AGENT") or "DarkWebLeakFinder/1.0").strip()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.ua,
            "hibp-api-key": self.key or "missing",
            "Accept": "application/json",
        })
        # expose last call metadata for the view to show
        self.last_status: int | None = None
        self.last_url: str | None = None
        self.last_items: int | None = None
        self.last_ct: str | None = None

    def breaches_for_account(self, email: str) -> List[dict[str, Any]]:
        if not self.key:
            logger.info("[HIBP] no API key set; returning [] (demo mode)")
            self.last_status, self.last_url, self.last_items = None, None, 0
            return []

        account = quote(email.strip().lower(), safe="")
        url = f"{self.BASE}/breachedaccount/{account}"
        params = {"truncateResponse": "false", "includeUnverified": "true"}

        time.sleep(1.6)  # be polite; helps with 429s
        resp = self.session.get(url, params=params, timeout=20)

        self.last_status = resp.status_code
        self.last_url = resp.url
        self.last_ct = resp.headers.get("Content-Type", "")
        logger.info("[HIBP] GET %s -> %s | CT=%s", resp.url, resp.status_code, self.last_ct)

        if resp.status_code == 404:
            self.last_items = 0
            return []
        if resp.status_code == 401:
            raise HibpAuthError("HIBP 401 Unauthorized: API key missing/invalid.")
        if resp.status_code == 429:
            raise HibpRateLimitError("HIBP 429 Rate limited. Try again shortly.")

        resp.raise_for_status()

        if not self.last_ct.lower().startswith("application/json"):
            logger.info("[HIBP] non-JSON response; ignoring body preview=%r", (resp.text or "")[:120])
            self.last_items = 0
            return []

        data = resp.json()
        self.last_items = len(data) if isinstance(data, list) else 0
        logger.info("[HIBP] items=%s", self.last_items)
        return data if isinstance(data, list) else []
