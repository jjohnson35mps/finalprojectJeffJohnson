# ShadowScan / DarkWebLeakFinder – Flowchart-Style Logic Descriptions
1. Account Registration Flow
----------------------------------------
```
Start
  ↓
User navigates to /accounts/register/
  ↓
Is user already authenticated?
  → Yes: Redirect to breaches dashboard → End
  → No:
      ↓
      User submits registration form (POST)?
        → No: Render empty registration form → End
        → Yes:
            ↓
            Bind form and validate
            ↓
            Is form valid?
              → No: Re-render form with errors → End
              → Yes:
                  ↓
                  Create user account
                  ↓
                  Log user in
                  ↓
                  Redirect to breaches dashboard
                  ↓
                  End
```

2. Add Identity and HIBP Scan Flow
----------------------------------
```
Start on dashboard
  ↓
User enters email in "Add identity" form and submits POST /add/
  ↓
Is email empty?
  → Yes: Show error message, redirect back to dashboard → End
  → No:
      ↓
      get_or_create EmailIdentity(address)
      ↓
      Show success or "already exists" message
      ↓
      User clicks "Scan" on identity row → POST /identity/<pk>/scan/
      ↓
      Load EmailIdentity by pk
      ↓
      Call HibpClient.breaches_for_account(email)
      ↓
      For each breach item:
        - Normalize name, dates, flags
        - Ensure unique breach_name per identity
        - update_or_create BreachHit
      ↓
      Count created/updated
      ↓
      Show success message about scan results
      ↓
      Redirect to identity detail
      ↓
      End
```

3. Identity Detail & Delete Flow
--------------------------------
```
User navigates to /identity/<pk>/
  ↓
Load EmailIdentity or return 404
  ↓
Query related BreachHit records, ordered by recency
  ↓
Render identity detail template with breach list
  ↓
User optionally posts to /identity/<pk>/delete/
  ↓
On delete POST:
    - Load identity or 404
    - Delete identity (cascades to BreachHit)
    - Show success message
    - Redirect to dashboard
  ↓
End
```

4. Shodan Scan Flow
-------------------
```
User on dashboard enters "target" and submits POST /scan/
  ↓
Is target empty?
  → Yes: Show error, redirect to dashboard → End
  → No:
      ↓
      Call fetch_host(target)
      ↓
      Any host data returned?
        → No: Show "no data" info, redirect → End
        → Yes:
            ↓
            Extract ip, hostnames, ports, org, last_update
            ↓
            Normalize ports and last_seen datetime
            ↓
            update_or_create ShodanFinding for ip
            ↓
            Show success message
            ↓
            Redirect to dashboard
            ↓
            End
```
User can later POST /scan/<pk>/delete/ to remove a given ShodanFinding:
  - Load finding
  - Delete
  - Redirect to dashboard with confirmation.

5. ThreatMap API Flow
---------------------
```
Front-end JS:
  - On page load or interval, send GET GET /threatmap/api/points/?source=layer7_origin|layer7_target|layer3_origin|layer3_target

Server:
  ↓
  Authenticate user (login_required)
  ↓
  Read "source" parameter
  ↓
  Is source in allowed set?
    → No: Set source to None (use provider default)
    → Yes: Use source as provided
  ↓
  Call get_points(source)
  ↓
  Load autoRefreshMs from configuration
  ↓
  Return JSON {points, autoRefreshMs}
  ↓
  JS renders heatmap and schedules next call using autoRefreshMs
```

6. Security Ticker Flow
-----------------------
```
Front-end JS:
  - Periodically requests GET /api/ticker/
Server:
  ↓
  Authenticate user (login_required)
  ↓
  Try:
    - Call fetch_kev_items(limit=10)
    - On success:
        Build JSON with "items" and "source"
  Except:
    - Log warning
    - Build fallback JSON with a single "Security feed unavailable" item
  ↓
  Set X-Ticker-Source and Cache-Control: no-store headers
  ↓
  Return JSON response
  ↓
  JS updates ticker UI with returned items
  ↓
  End
```
