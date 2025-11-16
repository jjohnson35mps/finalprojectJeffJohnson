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

- **Shodan Host Reconnaissance**  
  Query Shodan to gather exposed ports, services, host metadata, and vulnerabilities.  
  Generate quick-look asset summaries from any IPv4/hostname input.

- **Global Threat Telemetry (Cloudflare Radar × 4)**  
  Includes global Layer-3 and Layer-7 attack data:  
  - `layer7_origin` — Top HTTP attack origin regions  
  - `layer7_target` — Top HTTP attack target regions  
  - `layer3_origin` — Top network-level attack origin regions  
  - `layer3_target` — Top network-level attack target regions  
  Data is visualized as a world heatmap with live updates.

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
- **Django 5.x**  
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
darkweb-leak-finder/
│ .env
│ .gitignore
│ docker-compose.yml
│ Dockerfile
│ manage.py
│ pyproject.toml
│ README.md ← This file
│ requirements.txt
│ ruff.toml
│
├───.github/workflows
│ ci.yml ← GitHub Actions CI
│
├───data
│ db.sqlite3
│
└───src
│ manage.py
│ pytest.ini
│
├───breaches
│ ├───services (HIBP + Shodan clients)
│ ├───templates/breaches
│ ├───templatetags
│ ├───migrations
│ ├───static/breaches
│ ├───tests
│ └───models.py, views.py, urls.py
│
├───core
│ ├───middleware.py ← Query/body size guards (OWASP)
│ ├───templates/core/base.html
│ ├───static/core/dark.css
│ ├───services
│ └───urls.py, views.py
│
├───DarkWebLeakFinder (project config)
│ settings.py
│ urls.py
│
├───dashboard
│ ├───templates/dashboard
│ ├───static/dashboard
│ ├───urls.py, views.py
│
├───security_ticker
│ ├───services/sources.py
│ ├───templates/security_ticker/_ticker.html
│ ├───static/security_ticker
│ ├───templatetags/security_ticker_tags.py
│ └───urls.py, views.py
│
└───threatmap
├───providers/cloudflare.py ← 4× Radar API endpoints
├───management/commands/fetch_threatmap.py
├───templates/threatmap/heatmap.html
├───static/threatmap/js/heatmap.js
├───services/fetcher.py
├───tests/test_providers.py
└───models.py, views.py, urls.py
```

---

## API Integrations

### 🔹 HaveIBeenPwned (HIBP)
Used for **breach intelligence**:
- `/breachedaccount/{email}`  
- API key required (stored in `.env`)
- Returns breach metadata, data classes, timestamps.

### 🔹 Shodan API
Used for **exposure reconnaissance**:
- `/shodan/host/{ip}`  
- Discover open ports, vulnerabilities, and host metadata.

### 🔹 Cloudflare Radar (4 Endpoints)
All used via your `cloudflare.py` provider:

| Key | Endpoint | Field | Description |
|------|----------|--------|-------------|
| `layer7_origin` | `radar/attacks/layer7/top/locations/origin` | originCountryAlpha2 | Where HTTP-level attacks originate |
| `layer7_target` | `radar/attacks/layer7/top/locations/target` | targetCountryAlpha2 | Where HTTP-level attacks are targeted |
| `layer3_origin` | `radar/attacks/layer3/top/locations/origin` | originCountryAlpha2 | Where network-level attacks originate |
| `layer3_target` | `radar/attacks/layer3/top/locations/target` | targetCountryAlpha2 | Where network-level attacks are targeted |

Data is normalized → stored → rendered on an interactive **global heat map**.

---

# Using the Application

## 1. Clone the repository
```
git clone https://github.com/jjohnson35mps/finalprojectJeffJohnson.git
cd darkweb-leak-finder


### Database Schema:
- **Question:** id, question_text, pub_date  
- **Choice:** id, question (FK), choice_text, votes  

Foreign keys and relationships are managed automatically through Django’s ORM and migrations.

---

## Using The App

1. **Create your database**
   - Run the Django commands below to initialize your database:
     ```
     python manage.py makemigrations
     python manage.py migrate
     python manage.py createsuperuser
     ```

2. **Start the development server**
   ```bash
   python manage.py runserver 8000
   
3. Access the application
    - App: http://127.0.0.1:8000/    
    - Admin: http://127.0.0.1:8000/admin/

4. Register a user
    - Go to http://127.0.0.1:8000/accounts/login/ and create a new user account.    
    - Then login through /accounts/login/.    
    - Logout via /accounts/logout/.

5. Use the Email Breach Check
    - Enter any email address into the **Email Data Breach Check** field.
    - Click **Add** to store the identity in your dashboard.
    - Click **Scan** to query the HIBP API and retrieve breach history.
    - Results show breach names, dates, data classes, and descriptions.
    - Click **Remove** to delete the identity from the system.

6. Use the Domain or IP Port Scan
    - Enter a domain (example.com) or IPv4 address (1.2.3.4).
    - Click **Scan** to query the Shodan API.
    - The results panel displays:
        - Hostnames  
        - Organization  
        - Open ports / services  
        - Discovery timestamp  
    - Click **Rescan** to refresh the data.
    - Click **Remove** to delete the scan entry.

7. Interact with the Global Attack Heat Map
    - Use the dropdown selector at the top-right of the map to choose a dataset:
        - **Application Attack Point of Origin** (layer7_origin)  
        - **Application Attack Target** (layer7_target)  
        - **Network Attack Point of Origin** (layer3_origin)  
        - **Network Attack Target** (layer3_target)
    - Hover over hotspot regions to view country-specific attack distribution.
    - Pan and zoom the world map using the mousewheel and controls.
    - The right-hand sidebar displays:
        - Top attacking countries  
        - Percentage of observed activity  
        - Attack context and threat explanation

8. Use the admin interface
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
2. Go to the project root.
3. Ensure you have the required dependencies listed above installed
   - pip install -r requirements.txt
4. Initialize the database.
   - python manage.py makemigrations
   - python manage.py migrate
   - python manage.py createsuperuser
5. Start the development server.
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

