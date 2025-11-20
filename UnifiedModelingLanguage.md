# ShadowScan / DarkWebLeakFinder – Unified Modeling Language and Diagram Notes

## High-Level Component Diagram (Textual)
-----------------------------------------
Components:
- Web Browser (User)
- Django Application
  - core app
  - breaches app
  - dashboard app
  - security_ticker app
  - threatmap app
- External Services
  - HIBP API
  - Shodan API
  - Cloudflare Radar API
  - KEV / vulnerability feed
Connections:
- Browser → Django (HTTP/HTTPS)
- Django (breaches) → HIBP API
- Django (breaches) → Shodan API
- Django (threatmap) → ThreatMap provider
- Django (security_ticker) → KEV feed

## Class Diagram
-----------------------------------------
Classes:
- core.TimeStampedModel
  - created_at: DateTime
  - updated_at: DateTime
- breaches.EmailIdentity (inherits TimeStampedModel)
  - address: EmailField (unique)
  - hits: Reverse FK to BreachHit(* → 1)
- breaches.BreachHit (inherits TimeStampedModel)
  - identity: FK → EmailIdentity(* → 1)
  - breach_name: CharField
  - domain: CharField
  - occurred_on: DateField
  - title: CharField
  - description: TextField
  - pwn_count: BigIntegerField
  - data_classes: JSONField
  - boolean flags: is_verified, is_sensitive, etc.
  - added_on: DateField
  - modified_on: DateField
  - logo_path: CharField
  - logo_url(): computed property
- breaches.ShodanFinding
  - ip: GenericIPAddressField
  - hostnames: JSONField
  - ports: JSONField
  - org: CharField
  - os: CharField
  - raw: JSONField
  - created_on: DateTime
  - last_seen: DateTime  

Relationships:
- TimeStampedModel is an abstract superclass of EmailIdentity and BreachHit.
- EmailIdentity 1 ----- * BreachHit (one identity can have many breach hits).
- ShodanFinding is an independent entity used by the dashboard to present host intelligence, with no direct association to EmailIdentity.

## Sequence Diagram – HIBP Scan
---------------------------------------
Actors:
- User (Browser)
- Django (breaches.scan_identity)
- HibpClient
- Database  

Sequence (text form):
1. User clicks "Scan" on identity detail page.
2. Browser sends POST /identity/&lt;pk&gt;/scan/
3. Django view scan_identity:
   - Validates user (login_required).
   - Loads EmailIdentity from DB.
   - Instantiates HibpClient.
   - Calls HibpClient.breaches_for_account(email).
4. HibpClient calls HIBP API and returns JSON data.
5. Django loops over each breach:
   - Normalizes fields.
   - Calls BreachHit.update_or_create(...).
6. Database writes or updates rows.
7. Django sets success messages.
8. Django responds with redirect to identity detail.
9. Browser follows redirect and fetches identity detail page.

## Sequence Diagram – Shodan Scan
-----------------------------------------
Actors:
- User (Browser)
- Django (breaches.scan_target)
- Shodan client
- Database  

Sequence:
1. User submits a host in the dashboard scan form.
2. Browser sends POST /scan/ with "target" field.
3. Django view scan_target:
   - Validates user and POST method.
   - Reads target.
   - Calls fetch_host(target).
4. Shodan client performs remote lookup and returns host JSON.
5. Django normalizes fields (ip, hostnames, ports, org, os, last_seen).
6. Django calls ShodanFinding.update_or_create(ip, defaults).
7. Database persists/updates record.
8. Django sets messages, redirects to dashboard.
9. Browser loads updated dashboard with new scan result.

## Sequence Diagram – ThreatMap API
-------------------------------------------
Actors:
- Front-end ThreatMap script (JavaScript)
- Django (threatmap.threat_points)
- ThreatMap provider  

Sequence:
1. JS sends GET /threatmap/api/points/?source=layer7_origin.
2. Django view threat_points:
   - Enforces login_required.
   - Validates "source" parameter.
   - Calls get_points(source).
3. Service get_points:
   - Talks to ThreatMap provider with constrained parameters.
   - Returns normalized list of points.
4. Django reads AUTO_REFRESH_MS from conf.
5. Django returns JSON with points and autoRefreshMs.
6. JS updates Leaflet heatmap and schedules next poll.

## Sequence Diagram – Security Ticker
---------------------------------------------
Actors:
- Front-end ticker script (JavaScript)
- Django (security_ticker.ticker_feed)
- fetch_kev_items service
- KEV / vulnerability feed  

Sequence:
1. JS sends GET /api/ticker/ (authenticated).
2. Django view ticker_feed:
   - Enforces login_required.
   - Calls fetch_kev_items(limit=10).
3. Service fetch_kev_items:
   - Talks to KEV / vulnerability feed.
   - Returns list of items and a source label.
4. Django wraps items and source into JsonResponse.
5. Django sets X-Ticker-Source and no-store cache headers.
6. JS updates the scrolling ticker UI element.
