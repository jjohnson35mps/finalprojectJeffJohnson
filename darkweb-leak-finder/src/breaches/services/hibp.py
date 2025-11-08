# Thin service client for HIBP (requests-based)
import os
import time
from typing import Any
import requests

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
HIBP_BASE = "https://haveibeenpwned.com/api/v3"

class HibpClient:
    def __init__(self, api_key: str | None = None, backoff: float = 1.6) -> None:
        self.api_key = api_key or HIBP_API_KEY
        self.backoff = backoff
        self.session = requests.Session()
        self.session.headers.update({
            "hibp-api-key": self.api_key,
            "user-agent": "INF601G-Grad-Project/1.0"
        })

    def breaches_for_account(self, email: str) -> list[dict[str, Any]]:
        # Respect API terms: may need rate limiting or 404 semantics
        url = f"{HIBP_BASE}/breachedaccount/{email}?truncateResponse=false"
        resp = self.session.get(url)
        if resp.status_code == 404:
            return []
        if resp.status_code == 429:
            time.sleep(self.backoff)
            return self.breaches_for_account(email)
        resp.raise_for_status()
        return resp.json()
