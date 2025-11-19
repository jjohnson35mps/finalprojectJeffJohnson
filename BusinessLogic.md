# ShadowScan / DarkWebLeakFinder – Business Logic and Architecture Document
1. Overview
-----------
ShadowScan (DarkWebLeakFinder) is a modular Django web application that helps a security practitioner:
- Monitor email addresses for public data breaches via the HaveIBeenPwned (HIBP) API.
- Run Shodan host scans and store normalized host intelligence.
- Visualize global attack telemetry via a ThreatMap fed by Cloudflare Radar–style data.
- Display a scrolling ticker of high-priority vulnerabilities such as CISA KEV items.
- Manage user accounts, registration, and authentication securely using Django’s built-in auth system.  

Major Django apps:
- core – shared models and auth-related helper views
- breaches – email breach monitoring and Shodan scans
- dashboard – high-level summarized list/landing pages
- security_ticker – JSON feed for the scrolling security ticker
- threatmap – JSON API for the Leaflet-based heatmap
- project-level URL configuration – global routing and inclusion of app URLConfs
The system is designed with explicit attention to OWASP Top 10 issues, especially:
- A01: Broken Access Control
- A02/A05: Security Misconfiguration / Error Handling
- A03: Injection
- A06: Sensitive Data Exposure
- A09: Security Logging and Monitoring Failures

2. Authentication and Core Flows
--------------------------------
2.1 Registration Flow
Entry points:
- GET /accounts/register/
- POST /accounts/register/
Key behaviors:
- If the user is already authenticated, the system immediately redirects to the breaches dashboard to prevent unnecessary re-registration.
- For POST:
  - Binds user input to Django’s UserCreationForm.
  - Validates username and password against globally configured AUTH_PASSWORD_VALIDATORS.
  - On success:
    - Creates the user.
    - Immediately logs them in.
    - Redirects to the main breaches dashboard view.
  - On validation errors:
    - Re-renders the registration form with error messages.
  - On suspicious input (e.g., malformed POST body, type errors):
    - Logs a warning and returns a generic 400 Bad Request which avoids exposing stack traces.  

Business goal:
- Provide a simple, safe way to onboard users and drop them straight into the primary dashboard with minimal friction, while still enforcing password policy and protecting against fuzzing / malformed inputs.

2.2 Login / Logout Flow  

Login:
- URL: /accounts/login/
- Implemented using Django’s LoginView.
- On success:
  - Redirects either to the original protected URL requested or to a default landing page.  

Logout:
- URL: /logout/
- Implemented using Django’s LogoutView.
- Uses LOGOUT_REDIRECT_URL in settings to decide where the user goes after logging out.  

Business goal:
- Delegate all credential handling and session management to well-tested Django auth views and middleware, reducing the risk of custom authentication mistakes.

3. Breach Monitoring Domain (breaches app)
------------------------------------------
The breaches app is the heart of the system, tying together monitored email identities, breach data from HIBP, and host intelligence from Shodan scans.  

3.1 Main Breach Dashboard
Entry:
- URL: /
- View: breaches.dashboard (login_required)  

Logic:
- Queries all EmailIdentity records ordered by email address.
- Queries the 12 most recent ShodanFinding records ordered by last_seen.
- Renders breaches/main_db.html with:
  - identities: list of monitored email identities.
  - scans: recent host intelligence findings.  

Business goal:
- Provide a single pane of glass summarizing both:
  - Which identities are being monitored.
  - What host scans have been run recently.

3.2 Add Email Identity
Entry:
- URL: /add/
- View: breaches.add_identity (login_required)
- Methods: primarily POST from dashboard form.  

Logic:
- On POST:
  - Reads the email field from POST data, trims whitespace.
  - If empty:
    - Adds an error message and redirects back to the add route (redisplaying the dashboard with messages).
  - If non-empty:
    - Uses EmailIdentity.objects.get_or_create(address=email) to avoid duplicates.
    - Sets a success message indicating whether the identity was newly added or already existed.
    - Redirects back to the main breaches dashboard.
- On GET:
  - Implementation simply redirects to the dashboard; the primary UX is dashboard-based self-service.  

Business goal:
- Let users build up a monitored set of email addresses with deduplication and minimal friction.

3.3 HIBP Scan for a Single Identity
Entry:
- URL: /identity/<pk>/scan/
- View: breaches.scan_identity (login_required, require_POST)  

Logic:
1. Look up the EmailIdentity by primary key; return 404 for invalid IDs.
2. Instantiate HibpClient (a dedicated client for the HIBP API).
3. Call client.breaches_for_account(identity.address) to retrieve breach data.
4. Log a summary:
   - Email is masked with _mask_email() to reduce PII in logs.
   - Last HTTP status and the count of returned breaches are recorded.
5. For each breach item:
   - Extract normalized fields:
     - raw_name (internal Name)
     - title
     - domain
     - breach dates and metadata dates using a helper that ensures YYYY-MM-DD or None.
   - Determine a stable breach_name:
     - Prefer the raw HIBP Name.
     - Fall back to title, then domain, then a deterministic synthetic name.
   - Ensure uniqueness per identity:
     - Track names seen within the batch.
     - If a collision is found, append suffixes like " (2)", " (3)" while also checking the database for existing collisions.
   - Construct a defaults dictionary with:
     - domain, title, description, pwn_count, data_classes.
     - Boolean flags (is_verified, is_sensitive, is_fabricated, etc.).
     - added_on, modified_on as normalized dates or None.
     - logo_path as a stored relative logo filename.
   - Clean empty strings from date fields before saving.
   - Perform BreachHit.objects.update_or_create(identity=identity, breach_name=name, defaults=defaults).
   - Count how many records were created vs updated.
6. After processing all breaches:
   - Add a Django messages.success summarizing:
     - email
     - number of new vs updated records.
7. Handle exceptions:
   - HibpAuthError:
     - Show an error message about API key / user agent configuration.
     - Log a warning.
   - HibpRateLimitError:
     - Show a warning about hitting the rate limit.
     - Log a warning for monitoring.
8. Redirect:
   - Return a redirect to breaches:identity_detail for that identity.  

Business goal:
- Normalize possibly messy external HIBP data into a clean relational model.
- Deduplicate logically equivalent breaches for a given user.
- Provide clear feedback without leaking sensitive API or internal error details to the end user.

3.4 Identity Breach Detail View
Entry:
- URL: /identity/&lt;pk&gt;/
- View: breaches.identity_detail (login_required)  

Logic:
- Get the EmailIdentity or 404.
- Query BreachHit objects related to that identity ordered by:
  - occurred_on descending,
  - added_on descending,
  - id descending.
- Log the identity and count of hits using a masked email address.
- Render breaches/identity_detail.html with:
  - identity
  - hits  

Business goal:
- Provide a timeline-style view of all breaches that affected a given identity, with the most recent/most relevant occurrences at the top.

3.5 Delete Email Identity
Entry:
- URL: /identity/&lt;pk&gt;/delete/
- View: breaches.delete_identity (login_required, require_POST)  

Logic:
- Fetch the EmailIdentity, or 404.
- Save the address in a temporary variable for message display.
- Call delete() on the identity, relying on cascade delete to remove associated BreachHit records.
- Add a success message indicating that the identity was removed.
- Redirect to the dashboard.  

Business goal:
- Allow users to hard-delete monitored identities and all associated breach hits in a controlled, POST-only, CSRF-protected workflow.

3.6 Shodan Host Scan
Entry:
- URL: /scan/
- View: breaches.scan_target (login_required, require_POST)  

Logic:
1. Read and trim the "target" field (hostname or IP) from POST data.
2. If target is empty:
   - Show error message and redirect back to the dashboard.
3. Else:
   - Call fetch_host(target) which:
     - Contacts a Shodan backend.
     - Returns normalized JSON for the host.
4. If no data is returned:
   - Set an informational message and redirect back to the dashboard.
5. If data is returned:
   - Extract:
     - ip (either ip_str or ip)
     - hostnames (list)
     - ports (list or set)
     - org (organization)
     - os (operating system label)
   - Normalize ports:
     - Try to cast to integers and deduplicate.
     - On failure, store raw port values.
   - Handle last_seen:
     - Accept a raw string timestamp or datetime.
     - Parse into a timezone-aware datetime using Django’s utilities.
     - Fall back to timezone.now() if parsing fails.
   - Call ShodanFinding.objects.update_or_create(ip=ip, defaults={...}) to:
     - Either insert a new finding.
     - Or update an existing one for that host.
   - Add a success message referencing the IP.  

Error handling:
- If the remote call fails (ShodanError):
  - Log a warning.
  - Display a generic error message about contacting the intelligence service.  

Business goal:
- Provide a lightweight way to enrich the dashboard with host intelligence about specific domains/IPs that the analyst cares about.

3.7 Delete ShodanFinding
Entry:
- URL: /scan/&lt;pk&gt;/delete/
- View: breaches.delete_scan (login_required, require_POST)  

Logic:
- Fetch ShodanFinding by primary key; 404 if missing.
- Delete the record.
- Add a success message that the scan for the given IP was removed.
- Redirect to dashboard.  

Business goal:
- Let users clean up or remove obsolete host scan records while preserving a clear, POST-only destructive path.

4. Dashboard App Flows
----------------------
4.1 Dashboard Home
Entry:
- URL: /dashboard/
- View: dashboard.home (login_required)  

Logic:
- Fetch all EmailIdentity objects ordered by newest first (created_at descending).
- Render dashboard/home.html with identities context.  

Business goal:
- Provide a simple landing page summarizing monitored identities without showing every breach detail by default.

4.2 Dashboard Detail Delegation
Entry:
- URL: /dashboard/&lt;pk&gt;/
- View: dashboard.detail (login_required)  

Logic:
- Validate that an EmailIdentity with the given pk exists using get_object_or_404.
- Immediately redirect to breaches:identity_detail for the same pk.  

Business goal:
- Keep the dashboard implementation thin, delegating the canonical detail behavior to the breaches app, avoiding code duplication and drift.

5. ThreatMap Domain
-------------------
5.1 Allowed Sources  

The ThreatMap views define an ALLOWED_SOURCES set containing:
- layer7_origin
- layer7_target
- layer3_origin
- layer3_target  

Business rule:
- Only these whitelisted values are accepted for the "source" query parameter to avoid passing arbitrary user-controlled strings to the provider layer.

5.2 Main ThreatMap Endpoint
Entry:
- URL: /threatmap/api/points/?source=layer7_origin|layer7_target|layer3_origin|layer3_target
- View: threatmap.threat_points (login_required, require_GET)  

Logic:
1. Read the source query parameter from request.GET.
2. If source is not one of the allowed values:
   - Default to None and let the provider/module decide what default data to return.
3. Call get_points(source=source_param) to fetch points from the provider with appropriate caching.
4. Read AUTO_REFRESH_MS from configuration using conf_get.
5. Return a JSON dictionary:
   - points: normalized provider points
   - autoRefreshMs: integer polling interval for the front-end  

Business goal:
- Provide a compact API for the Leaflet-based front-end ThreatMap, safely constraining inputs and centralizing configuration.

6. Security Ticker Domain
-------------------------
6.1 Ticker Feed Endpoint
Entry:
- URL: /api/ticker/
- View: security_ticker.ticker_feed (login_required, require_GET)  

Logic:
1. Ensure that the user is authenticated; anonymous requests are redirected to login.
2. Within a try/except block:
   - Call fetch_kev_items(limit=10) to retrieve recent vulnerability items
     from configured sources (such as CISA KEV or NVD with a KEV flag).
3. On success:
   - Receive a list of items and a source label.
   - Build a JsonResponse with:
     - items: list of {title, date, link}
     - source: name of the backend source or strategy used.
4. On failure:
   - Log a warning with the error.
   - Return a fallback JSON payload:
     - A single item "Security feed unavailable" pointing the user to the KEV catalog.
     - source = "error".
5. Set additional headers:
   - X-Ticker-Source: for debugging (which backend was used).
   - Cache-Control: "no-store" so intermediaries do not cache time-sensitive data.  

Business goal:
- Power a scrolling ticker UI element with high-priority vulnerability headlines while failing gracefully when upstream feeds are unavailable.

7. Data Model Summary
---------------------
7.1 core.TimeStampedModel
- Abstract base model providing:
  - created_at: auto_now_add datetime
  - updated_at: auto_now datetime
- Used by:
  - EmailIdentity
  - BreachHit  

Business goal:
- Uniformly track creation and modification times for security-relevant records.

7.2 breaches.EmailIdentity  

Represents a single monitored email address.  

Fields:
- address: EmailField, unique.
- created_at, updated_at via TimeStampedModel.  

Business rules:
- Each email address appears only once in the table.
- BreachHit records reference EmailIdentity via a ForeignKey with cascade delete.

7.3 breaches.BreachHit  

Represents a single breach that affected one EmailIdentity.  

Key fields:
- identity: FK → EmailIdentity (CASCADE)
- breach_name: internal identifier, used for deduplication per identity
- domain, title, description
- pwn_count
- data_classes: JSON list
- boolean flags describing breach characteristics
- added_on, occurred_on, modified_on
- logo_path and computed property logo_url
Meta:
- unique_together: (identity, breach_name)
- indexes: on breach_name and (identity, breach_name)
- ordering: newest breach first
Business goal:
- Provide a normalized, query-friendly representation of HIBP-style breach data per identity.

7.4 breaches.ShodanFinding  

Represents normalized host intelligence.  

Fields:
- ip: GenericIPAddressField
- hostnames: JSON list
- ports: JSON list
- org, os: textual fields
- raw: JSON of full provider payload
- created_on: inserted automatically
- last_seen: updated whenever a new observation comes in; default now
Meta:
- ordering: by last_seen descending, then id
Business goal:
- Keep a simple record per IP that can be refreshed in-place as new scans occur, while preserving a chronological ordering.

8. Cross-Cutting Security and Logging
-------------------------------------
Access control:
- login_required is applied to all sensitive views and APIs.
- state-changing endpoints (scan, delete, register) are POST-only and CSRF-protected.  

Input validation:
- Query parameters for ThreatMap restricted to ALLOWED_SOURCES.
- HIBP and Shodan responses are normalized server-side before storage.
- Generic exception handling prevents raw stack traces (500s) from escaping to end users.  

Logging:
- Minimal PII logging, with email masking and caution around raw JSON from external APIs.
- Warnings for rate limit, auth failures, and upstream connectivity issues.  

Overall business objective:
- Provide a cohesive security analyst dashboard that unifies breach monitoring, host intelligence, and security news, while explicitly addressing common OWASP risks and maintaining a clean, modular Django architecture.
