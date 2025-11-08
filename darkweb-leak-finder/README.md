# darkweb-leak-finder

Graduate-level Django project scaffold for **Dark Web Leak Finder** (INF601G).
This scaffold is optimized for the *Advanced* rubric: modular apps, reusable code,
documentation, CI hooks, and security-conscious defaults.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Create the Django shell; this scaffold keeps app code ready-to-drop-in
django-admin startproject DarkWebLeakFinder src
python manage.py startapp core src/core
python manage.py startapp breaches src/breaches
python manage.py startapp dashboard src/dashboard
```

Then copy the scaffolded app files (models, views, urls, services, etc.) into the generated apps
if you prefer Django to create the base app structure first.

## Apps
- **core**: shared utilities, settings helpers, validators, and base templates/components.
- **breaches**: email identities, breach hits, and HIBP integration.
- **dashboard**: UI layer + charts/tables and admin-facing pages.

## Security
- Use `.env` (see `.env.example`) and configure `SECRET_KEY`, `ALLOWED_HOSTS`, and DB credentials.
- Follow Django’s security checklist for production.

## Rubric Fit (Advanced)
- Modularization & reuse via app boundaries and services.
- Dashboard + Admin ready.
- CI and docs included to support deployment and feedback.
