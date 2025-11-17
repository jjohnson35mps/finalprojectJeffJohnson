### INF601 - Advanced Programming in Python  
### Jeff Johnson  
### Final Project — ShadowScan: Cyber Exposure Intelligence

---

# ShadowScan: Cyber Exposure Intelligence

A full-stack **Django cybersecurity intelligence platform** designed to aggregate and visualize exposure data from multiple security APIs. ShadowScan provides centralized insights into email breach history, internet-facing asset risk, and global cyber-attack telemetry. The platform features a dark-themed UI, modular Django apps, an admin dashboard, live security ticker, Cloudflare Radar heatmap, and robust API integrations — all aligned with OWASP principles and the INF601 Final Project requirements.

---

## Description

### What this app does

ShadowScan provides a comprehensive cybersecurity situational awareness dashboard by integrating multiple security intelligence datasets:

- **Email Breach Intelligence (HIBP API)**  
  Check if an email identity has appeared in known breach corpuses.  
  Store breach history, timestamps, and classifications.
  API: https://haveibeenpwned.com/api/v3

- **Shodan Host Reconnaissance**  
  Query Shodan to gather exposed ports, services, and host metadata.  
  Generate quick-look asset summaries from any IPv4/hostname input.
  API: https://api.shodan.io/shodan/host/{ip}?key={key}

- **Global Threat Telemetry (Cloudflare Radar × 4)**  
  Includes global Layer-3 and Layer-7 attack data:  
  - `layer7_origin` — Top application-level attack origin regions  
  - `layer7_target` — Top application-level attack target regions  
  - `layer3_origin` — Top network-level attack origin regions  
  - `layer3_target` — Top network-level attack target regions  
  Data is visualized as a world heatmap with live updates.
  API: radar/attacks/layer7/top/locations/origin
       radar/attacks/layer7/top/locations/target
       radar/attacks/layer3/top/locations/origin
       radar/attacks/layer3/top/locations/target

- **Security Ticker (KEV + CVE Intelligence)**  
  Displays actively exploited vulnerabilities and high-severity CVEs from curated sources.

- **Dashboard**  
  Unified landing page providing a quick summary of identities, breach data, Shodan findings, and global threat activity.

- **Authentication & User Management**  
  Register, login, logout — full Django auth flows, dark-UI templates, and secure session handling.

- **Admin Interface**  
  Full Django Admin integration for all models: identities, breach hits, Shodan results, threat telemetry, etc.

- **Modular Architecture**  
  Django apps include:
  - `core` — Base templates, dark theme, middleware  
  - `breaches` — HIBP + Shodan services  
  - `dashboard` — Home pages, summaries  
  - `security_ticker` — Threat feed & ticker visualization  
  - `threatmap` — Cloudflare Radar ingestion + heatmap UI

- **Security Hardening (OWASP Integration)**  
  Rate limits, input validation, size-limit middleware, defensive coding, and separation of concerns.

---

## Technologies Used

- **Python 3.13.7**  
- **Django 5.2.8**  
- **Bootstrap 5 (Dark Theme)**  
- **SQLite / Django ORM**  
- **JavaScript Heatmap Rendering (Leaflet / custom)**  
- **REST API Integrations**  
  - HaveIBeenPwned (HIBP)  
  - Shodan  
  - Cloudflare Radar (4 endpoints)  
- **GitHub Actions (CI Workflow)**  
- **Docker + docker-compose (optional local build)**

---

## Project Structure

```
darkweb-leak-finder
│   .env
│   .gitignore
│   docker-compose.yml
│   Dockerfile
│   hibp.py
│   manage.py
│   pyproject.toml
│   requirements.txt
│   ruff.toml
│
├───.github
│   └───workflows
│           ci.yml
│
├───data
│       db.sqlite3
│
└───src
    │   manage.py
    │   pytest.ini
    │
    ├───DarkWebLeakFinder
    │   │   asgi.py
    │   │   settings.py
    │   │   urls.py
    │   │   wsgi.py
    │   │   __init__.py
    │
    ├───breaches
    │   │   admin.py
    │   │   apps.py
    │   │   models.py
    │   │   urls.py
    │   │   views.py
    │   │   __init__.py
    │   │
    │   ├───migrations
    │   │   │   0001_initial.py
    │   │   │   0002_breachhit_added_on_breachhit_data_classes_and_more.py
    │   │   │   0003_shodanfinding.py
    │   │   │   0004_alter_breachhit_options_alter_breachhit_data_classes_and_more.py
    │   │   │   __init__.py
    │   │
    │   ├───services
    │   │   │   hibp.py
    │   │   │   shodan_client.py
    │   │
    │   ├───static
    │   │   └───breaches
    │   │       ├───css
    │   │       ├───img
    │   │       └───js
    │   │
    │   ├───templates
    │   │   └───breaches
    │   │           identity_detail.html
    │   │           main_db.html
    │   │
    │   ├───templatetags
    │   │   │   hibp_extras.py
    │   │   │   __init__.py
    │   │
    │   └───tests
    │           __init__.py
    │
    ├───core
    │   │   admin.py
    │   │   apps.py
    │   │   middleware.py
    │   │   models.py
    │   │   urls.py
    │   │   views.py
    │   │   __init__.py
    │   │
    │   ├───migrations
    │   │   │   __init__.py
    │   │
    │   ├───services
    │   │       utils.py
    │   │
    │   ├───static
    │   │   └───core
    │   │       │   dark.css
    │   │       ├───css
    │   │       ├───img
    │   │       └───js
    │   │
    │   ├───templates
    │   │   └───core
    │   │           base.html
    │   │
    │   └───tests
    │           __init__.py
    │
    ├───dashboard
    │   │   admin.py
    │   │   apps.py
    │   │   models.py
    │   │   urls.py
    │   │   views.py
    │   │   __init__.py
    │   │
    │   ├───migrations
    │   │   │   __init__.py
    │   │
    │   ├───services
    │   │
    │   ├───static
    │   │   └───dashboard
    │   │       ├───css
    │   │       ├───img
    │   │       └───js
    │   │
    │   ├───templates
    │   │   ├───dashboard
    │   │   │       detail.html
    │   │   │       home.html
    │   │   │
    │   │   └───registration
    │   │           login.html
    │   │           register.html
    │   │
    │   └───tests
    │           __init__.py
    │
    ├───data
    │       kev_cache.json
    │
    ├───security_ticker
    │   │   apps.py
    │   │   urls.py
    │   │   views.py
    │   │   __init__.py
    │   │
    │   ├───migrations
    │   │
    │   ├───services
    │   │   │   sources.py
    │   │   │   __init__.py
    │   │
    │   ├───static
    │   │   └───security_ticker
    │   │       ├───css
    │   │       │       ticker.css
    │   │       ├───img
    │   │       └───js
    │   │               ticker.js
    │   │
    │   ├───templates
    │   │   └───security_ticker
    │   │           _ticker.html
    │   │
    │   ├───templatetags
    │   │   │   breach_extras.py
    │   │   │   security_ticker_tags.py
    │   │   │   __init__.py
    │   │
    │   └───tests
    │           __init__.py
    │
    ├───templates
    │   (project-level templates, if any)
    │
    └───threatmap
        │   admin.py
        │   apps.py
        │   conf.py
        │   models.py
        │   urls.py
        │   views.py
        │   __init__.py
        │
        ├───management
        │   ├───commands
        │   │       fetch_threatmap.py
        │   │
        │   └───__init__.py
        │
        ├───providers
        │   │   base.py
        │   │   cloudflare.py
        │   │   __init__.py
        │
        ├───services
        │   │   fetcher.py
        │   │   __init__.py
        │
        ├───static
        │   └───threatmap
        │       └───js
        │               heatmap.js
        │
        ├───templates
        │   └───threatmap
        │           heatmap.html
        │
        └───tests
                test_providers.py
                __init__.py

```

---

## API Integrations

### 🔹 HaveIBeenPwned (HIBP)
Used for **breach intelligence**:
- `https://haveibeenpwned.com/api/v3`  
- API key required (stored in `.env`)
- Returns breach metadata, data classes, timestamps.

### 🔹 Shodan API
Used for **exposure reconnaissance**:
- `https://api.shodan.io/shodan/host/{ip}?key={key}`  
- Discover open ports, vulnerabilities, and host metadata.

### 🔹 Cloudflare Radar (4 Endpoints)
All used via `cloudflare.py` provider:

| Key | Endpoint | Field | Description |
|------|----------|--------|-------------|
| `layer7_origin` | `radar/attacks/layer7/top/locations/origin` | originCountryAlpha2 | Where HTTP-level attacks originate |
| `layer7_target` | `radar/attacks/layer7/top/locations/target` | targetCountryAlpha2 | Where HTTP-level attacks are targeted |
| `layer3_origin` | `radar/attacks/layer3/top/locations/origin` | originCountryAlpha2 | Where network-level attacks originate |
| `layer3_target` | `radar/attacks/layer3/top/locations/target` | targetCountryAlpha2 | Where network-level attacks are targeted |

Data is normalized → stored → rendered on an interactive **global heat map**.

---

### Database Schema:
BreachesEmailIdentity
-id (PK)
-created_at
-updated_at
-address — unique
Stores a user-submitted email address to monitor for breaches. 

BreachesBreachHit
- id (PK)
- created_at
- updated_at
- breach_name
- domain
- occurred_on
- identity_id — (FK → BreachesEmailIdentity.id)
- added_on
- data_classes (JSON)
- description
- is_fabricated
- is_malware
- is_retired
- is_sensitive
- is_spam_list
- is_stealer_log
- is_subscription_free
- is_verified
- logo_path
- modified_on
- pwn_count
- title
- UNIQUE: (identity_id, breach_name)
Stores all HIBP breach events tied to a specific monitored email identity.

BreachesShodanFinding
- id (PK)
- ip
- hostnames (JSON)
- ports (JSON)
- org
- raw (JSON)
- created_on
- last_seen
- os
Stores Shodan scan results for host/IP lookups performed through the app.

---

# Using the Application

1. Clone the repository
    ```
    git clone https://github.com/jjohnson35mps/finalprojectJeffJohnson.git
    ```
2. **Create and populate required files**
   - Run the Django commands below to create required files:
     ```
     python -c "from pathlib import Path; Path('darkweb-leak-finder/.env').touch()"
     mkdir darkweb-leak-finder/data
     ```

3. **Create your database**
   - Run the Django commands below to initialize your database:
     ```
     cd darkweb-leak-finder/src
     python manage.py makemigrations
     python manage.py migrate
     python manage.py createsuperuser
     ```

4. **Start the development server**
    - Add the API keys for Have I been Powned, Shodan, and Cloudflare to darkweb-leak-finder/.env
    - If not in darkweb-leak-finder/src, cd darkweb-leak-finder/src
   ```
   python manage.py runserver 8000
   ```
5. Access the application
    - App: http://127.0.0.1:8000/    
    - Admin: http://127.0.0.1:8000/admin/

6. Register a user
    - Go to http://127.0.0.1:8000/accounts/login/ and create a new user account.    
    - Then login through /accounts/login/.    
    - Logout via /accounts/logout/.

7. Use the Email Breach Check
    - Enter any email address into the **Email Data Breach Check** field.
    - Click **Add** to store the identity in the dashboard.
    - Click **Scan** to query the HIBP API and retrieve breach history.
    - Results show breach names, dates, data classes, and descriptions.
    - Click **Remove** to delete the identity from the system.

8. Use the Domain or IP Port Scan
    - Enter a domain (example.com) or IPv4 address (1.2.3.4).
    - Click **Scan** to query the Shodan API.
    - The results panel displays:
        - Hostnames  
        - Organization  
        - Open ports / services  
        - Discovery timestamp  
    - Click **Rescan** to refresh the data.
    - Click **Remove** to delete the scan entry.

9. Interact with the Global Attack Heat Map
    - Use the dropdown selector at the top of the map to choose a dataset:
        - **Application Attack Point of Origin** (layer7_origin)  
        - **Application Attack Target** (layer7_target)  
        - **Network Attack Point of Origin** (layer3_origin)  
        - **Network Attack Target** (layer3_target)
    - Pan and zoom the world map using the mousewheel and controls.
    - The right-hand sidebar displays:
        - Top countries for attacks and targets  
        - Percentage of observed activity  
        - Attack context and threat explanation

10. Use the admin interface
    - Log into http://127.0.0.1:8000/admin/ with your superuser credentials to manage all ShadowScan models, including:
        - Email Identities  
        - Breach Hits  
        - Shodan Findings  
        - ThreatMap source data  


Quick Info:
Click the “About this tool” button on the home page to open the required Bootstrap modal.
All templates extend from base.html for consistent site styling.

 
### Dependencies
 
- Python 3.13.7
- Django 5.2.8
- Operating System: 
    - Windows

- Required libraries (install with pip):
```
pip install -r requirements.txt
```

## Installing
 
1. Clone or download this project to your local machine.
2. Create and populate required files**
   - python -c "from pathlib import Path; Path('darkweb-leak-finder/.env').touch()"
   - mkdir darkweb-leak-finder/data
3. Go to the project root.
4. Ensure you have the required dependencies listed above installed
   - pip install -r requirements.txt
5. Initialize the database.
   - python manage.py makemigrations
   - python manage.py migrate
   - python manage.py createsuperuser
6. Start the development server.
   - python manage.py runserver 8000
 
## Executing program

Run the server
```
python manage.py runserver
```
The server will run on http://127.0.0.1:8000
Default username and password admin/admin
## Help
 
If you encounter issues, re-run pip installs and re-seed the app settings:
```
pip install -r requirements.txt
python manage.py runserver

```
## Robustness Verification

To validate application stability and confirm compliance with OWASP-aligned error handling requirements, 
I performed a full stress/fuzz test against all major endpoints using a custom multithreaded stressor script.
The tool submitted thousands of intentionally malformed requests including:
  - Invalid HTTP methods
  - Oversized POST bodies
  - Long or malformed query parameters
  - Non-integer and out-of-range primary keys
  - Randomized payloads simulating XSS/SSTI/SQL injection patterns
  - Missing or altered CSRF tokens
  - API endpoint abuse and high-frequency polling

Key Findings
 - No 500 Internal Server Errors occurred during the entire stress test.
 - All unexpected input was handled gracefully with the appropriate HTTP status codes.
 - No unhandled exceptions surfaced in terminal logs.
 - Authentication-protected endpoints redirected safely and consistently.
 - The system remained responsive and stable throughout high-volume concurrent load.
 - Invalid API requests (e.g., Cloudflare Radar with wrong parameters) did not break the UI and were captured safely.

Conclusion
The ShadowScan system demonstrates strong resilience, graceful error handling, and full alignment with INF601
graduate-level expectations for robustness. The application is suitable for real-world deployment scenarios and
successfully prevents system crashes or information leakage when exposed to malformed input.

## Self-Reflection: Robustness & Error Handling

One of the key goals for this project was ensuring that the application behaved predictably and safely under stress,
particularly given the cybersecurity context. After completing the main features, I performed an extensive stress/fuzz
test against the entire ShadowScan endpoint surface. The intention was to simulate real-world adversarial behavior,
including malformed HTTP requests, injection-style payloads, incorrect primary keys, invalid API requests,
and oversized inputs.

During testing, I discovered that the logout endpoint returned a 405 (Method Not Allowed) for GET requests.
After reviewing Django's security practices, I confirmed that this was correct behavior, as logout should only accept
POST to prevent CSRF-based forced logout attacks. No further changes were needed.

Aside from this expected 405 result, the application held up exceptionally well. I observed zero crashes and zero
500-level errors. All malformed inputs resulted in appropriate responses (400, 403, 404, 413), which confirms that
my validation logic, error handling, and API exception wrappers are working as intended. This robustness directly 
aligns with Jason’s emphasis on preventing unexpected crashes during the final project review.

Through this process, I gained a deeper understanding of how Django handles malformed requests, how to create
defensive view logic, and how important it is in cybersecurity-focused applications to anticipate invalid or
malicious inputs. This is an area of the project I am particularly proud of.

## Authors
 
Jeff Johnson
 
## Version History
 
- 0.1
  - Initial Release
 
## License
 
This project is licensed under the MIT License - see the LICENSE.md file for details
 
## Acknowledgments
 
Inspiration, code snippets, etc.
- [Django Tutorial](https://docs.djangoproject.com/en/5.2/intro/tutorial01/)
- [ChatGPT](https://chatgpt.com/g/g-p-690d2161b8388191be61b9e1de8517d7-final-project/project)
*** I use a ChatGPT paid acct, so I cannot share ***

