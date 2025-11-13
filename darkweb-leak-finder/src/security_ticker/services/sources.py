# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project

from __future__ import annotations
import os, time, requests
from typing import List, Dict, Any, Tuple

# Primary (correct) CISA feed – uses underscores
CISA_KEV_JSONS: List[str] = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
]

# Fallback (normalized)
NVD_KEV_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev"

DEFAULT_TIMEOUT = int(os.getenv("SEC_TICKER_TIMEOUT_SECONDS", "8"))
UA = os.getenv("SEC_TICKER_USER_AGENT", "DarkWebLeakFinder/1.0 (+ticker)")

def _get_json(url: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    r = requests.get(url, timeout=timeout, headers={"User-Agent": UA})
    if r.status_code in (403, 404):
        raise requests.HTTPError(f"{r.status_code} for {url}", response=r)
    r.raise_for_status()
    return r.json()

def fetch_kev_items(limit: int = 10) -> Tuple[List[Dict[str, str]], str]:
    """
    Returns (items, source). Items: [{"title","date","link"}].
    """
    last_err = None

    # Try CISA first
    for url in CISA_KEV_JSONS:
        try:
            data = _get_json(url)
            vulns = data.get("vulnerabilities") or data.get("known_exploited_vulnerabilities") or []
            items: List[Dict[str, str]] = []
            for v in vulns[:limit]:
                cve = v.get("cveID") or v.get("cve_id") or ""
                date = (v.get("dateAdded") or v.get("date_added") or "")[:10]
                items.append({
                    "title": cve or (v.get("vendorProject") or "CISA KEV"),
                    "date": date,
                    "link": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}" if cve else "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                })
            if items:
                return (items, "cisa_json")
        except Exception as e:
            last_err = e
            time.sleep(0.2)

    # Fallback: NVD hasKev
    try:
        data = _get_json(NVD_KEV_API)
        results = data.get("vulnerabilities", [])
        items = []
        for obj in results[:limit]:
            cve = obj.get("cve", {}).get("id") or ""
            pub = obj.get("cve", {}).get("published") or ""
            items.append({
                "title": cve or "NVD hasKev",
                "date": pub[:10],
                "link": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "https://nvd.nist.gov/",
            })
        if items:
            return (items, "nvd_hasKev")
    except Exception as e:
        last_err = e

    return ([{"title": "No KEV feed available", "date": "", "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}],
            f"fallback: {last_err!s}" if last_err else "fallback")
