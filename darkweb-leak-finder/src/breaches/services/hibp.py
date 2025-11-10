# src/breaches/services/hibp.py
# Robust HIBP client with logging and last-call metadata.
from __future__ import annotations
import os, time, logging
from typing import Any, List, Optional
from urllib.parse import quote
import requests

logger = logging.getLogger("breaches")

class HibpError(Exception): ...
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
        # Expose last call metadata for the UI
        self.last_status: int | None = None
        self.last_url: str | None = None
        self.last_items: int | None = None
        self.last_ct: str | None = None

    # -------------------------
    # Public API
    # -------------------------
    def breaches_for_account(self, email: str) -> List[dict[str, Any]]:
        """
        Return a normalized list of breach dicts with this schema:
          {
            "breach_name": str,
            "title": str,              # same as breach_name
            "domain": str,
            "breach_date": str|None,   # 'YYYY-MM-DD'
            "occurred_on": str|None,   # same as breach_date
            "pwn_count": int,
            "data_classes": list[str],
            "description": str,
          }
        Notes:
        - Records without a Name are dropped (prevents 'Unknown' cards).
        - LogoPath is intentionally omitted.
        """
        if not self.key:
            logger.info("[HIBP] no API key set; returning [] (demo mode)")
            self.last_status, self.last_url, self.last_items = None, None, 0
            return []

        account = quote(email.strip().lower(), safe="")
        url = f"{self.BASE}/breachedaccount/{account}"
        params = {"truncateResponse": "false", "includeUnverified": "true"}

        # polite delay to help avoid 429s
        time.sleep(1.6)
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
        if not isinstance(data, list):
            self.last_items = 0
            return []

        # Normalize and DROP nameless entries (None)
        normalized = []
        for raw in data:
            if isinstance(raw, dict):
                nb = self._normalize_breach(raw)
                if nb is not None:
                    normalized.append(nb)

        self.last_items = len(normalized)
        logger.info("[HIBP] items=%s (normalized)", self.last_items)
        return normalized

    # -------------------------
    # Internals
    # -------------------------
    def _normalize_breach(self, b: dict[str, Any]) -> Optional[dict[str, Any]]:
        """
        Map HIBP fields to our schema and drop any logo-related fields.
        Returns None if 'Name' is missing/blank.
        """
        name = (b.get("Name") or "").strip()
        if not name:
            # Drop nameless records to avoid "Unknown" UI blocks
            return None

        domain = (b.get("Domain") or "").strip()
        breach_date = (b.get("BreachDate") or None)
        pwn_count = int(b.get("PwnCount") or 0)

        # HIBP supplies a list for DataClasses; be liberal anyway.
        dc = b.get("DataClasses")
        if isinstance(dc, (list, tuple)):
            data_classes = [str(x).strip() for x in dc if str(x).strip()]
        elif isinstance(dc, str):
            # Fallback if a CSV string ever appears
            data_classes = [s.strip() for s in dc.split(",") if s.strip()]
        else:
            data_classes = []

        description = (b.get("Description") or "").strip()

        # NEVER include LogoPath/logo_path
        return {
            "breach_name": name,
            "title": name,               # convenience for templates
            "domain": domain,
            "breach_date": breach_date,
            "occurred_on": breach_date,
            "pwn_count": pwn_count,
            "data_classes": data_classes,
            "description": description,
        }
