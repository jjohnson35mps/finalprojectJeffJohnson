# src/security_ticker/services/sources.py
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities"  # no .json

def fetch_kev_items(limit: int = 10):
    """
    Return a list of dicts: [{"title": str, "date": "YYYY-MM-DD", "link": str}, ...]
    Built from CISA KEV JSON. Falls back to empty list if request fails.
    """
    headers = {
        "User-Agent": "DarkWebLeakFinder/1.0 (contact@example.com)",
        "Accept": "application/json",
    }
    try:
        resp = requests.get(KEV_URL, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        # CISA KEV JSON schema exposes "vulnerabilities": [...]
        vulns = data.get("vulnerabilities", [])
        items = []
        for v in vulns[:limit]:
            cve   = v.get("cveID") or "CVE-unknown"
            when  = v.get("dateAdded") or ""
            vend  = (v.get("vendorProject") or "").strip()
            prod  = (v.get("product") or "").strip()
            desc  = (v.get("shortDescription") or "").strip()

            title_bits = [cve]
            if vend or prod:
                title_bits.append(f"{vend} {prod}".strip())
            if desc:
                title_bits.append(desc)

            items.append({
                "title": " — ".join(b for b in title_bits if b),
                "date": when[:10],
                "link": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
            })
        return items

    except Exception:
        # Don’t crash the endpoint; let the view decide how to handle an empty list.
        return []
