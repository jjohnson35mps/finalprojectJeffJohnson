# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
#
# DarkWebLeakFinder/settings.py
# -----------------------------
# Django settings for the DarkWebLeakFinder project.
#
# OWASP Top 10 touchpoints:
#   - A02: Security Misconfiguration
#       * Secrets and environment-specific config are read from environment
#         variables via python-dotenv.
#       * DEBUG is controllable via environment; it MUST be False in production.
#   - A05: Identification & Authentication Failures
#       * Uses Django’s built-in auth system and password validators.
#   - A07: Identification & Authentication / Session Management
#       * Session cookie lifetime and browser-close behavior are configured.
#   - A09: Security Logging & Monitoring Failures
#       * LOGGING is configured to keep app and request logs visible in dev.
#   - A01: Broken Access Control
#       * Enforced mainly in views (login_required, per-user checks), not here,
#         but settings like MIDDLEWARE and INSTALLED_APPS enable that.

from pathlib import Path
import os

from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# Paths / project layout
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent  # src/
PROJECT_ROOT = BASE_DIR.parent                     # darkweb-leak-finder/
DATA_DIR = PROJECT_ROOT / "data"

# ---------------------------------------------------------------------------
# Environment / secrets loading
# ---------------------------------------------------------------------------
# Load environment variables from src/.env (development convenience only).
# In production, you should rely on real environment variables instead.
load_dotenv(BASE_DIR / ".env")

# API keys and tokens (read from env; never hard-code real secrets)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
HIBP_API_KEY = os.getenv("HIBP_API_KEY")
HIBP_USER_AGENT = os.getenv("HIBP_USER_AGENT")
CLOUDFLARE_RADAR_TOKEN = os.getenv("CLOUDFLARE_RADAR_TOKEN", "")

# ---------------------------------------------------------------------------
# Core security settings
# ---------------------------------------------------------------------------
# SECRET_KEY:
#   - For coursework/dev, we fall back to a static dev key.
#   - In any real deployment, you MUST override DJANGO_SECRET_KEY in the env.
SECRET_KEY = os.getenv(
    "DJANGO_SECRET_KEY",
    "django-insecure-o3-g@82m@r2x^g+a&@a62^0nzzh$etkwvmdd!ofta=f8yt(ldi",  # dev only
)

# DEBUG:
#   - Default True for local development.
#   - Set DJANGO_DEBUG=False in production (A02: Security Misconfiguration).
DEBUG = os.getenv("DJANGO_DEBUG", "True").lower() in {"1", "true", "yes"}

# Allowed hosts for host-header validation (A05/A01 defense-in-depth).
# In production, expand this via DJANGO_ALLOWED_HOSTS (comma-separated).
ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")


# ---------------------------------------------------------------------------
# Logging (A09: Security Logging & Monitoring)
# ---------------------------------------------------------------------------
# Logs to the dev server console so you can see HIBP/Shodan calls and errors.
# Avoid logging secrets (API keys, tokens, passwords).
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
    },
    "loggers": {
        # Application-level logger used by breaches app
        "breaches": {"handlers": ["console"], "level": "INFO"},
        # Keep Django request errors visible
        "django.request": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
    },
}


# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------
INSTALLED_APPS = [
    # Django core apps
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Project apps
    "core",
    "breaches",
    "dashboard",
    "security_ticker",
    "threatmap",

    # Utilities
    "django.contrib.humanize",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",                # CSRF (A02/A05)
    "django.contrib.auth.middleware.AuthenticationMiddleware",  # Auth/session
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",   # Clickjacking
]

ROOT_URLCONF = "DarkWebLeakFinder.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],  # Rely on app templates (breaches, dashboard, etc.)
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "DarkWebLeakFinder.wsgi.application"


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# For this project, SQLite is sufficient. The path can be overridden with
# SQLITE_PATH in the environment for flexibility. In production, you would
# typically switch to PostgreSQL or another hardened backend.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.getenv("SQLITE_PATH", str(DATA_DIR / "db.sqlite3")),
    }
}


# ---------------------------------------------------------------------------
# Password validation (A05: Authentication)
# ---------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",  # noqa: E501
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# ---------------------------------------------------------------------------
# Internationalization / localization
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True


# ---------------------------------------------------------------------------
# Static files (CSS, JavaScript, Images)
# ---------------------------------------------------------------------------
STATIC_URL = "/static/"
# If you later add STATIC_ROOT for collectstatic in production, keep it
# outside version control and ensure proper permissions.


# ---------------------------------------------------------------------------
# Primary key / model defaults
# ---------------------------------------------------------------------------
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ---------------------------------------------------------------------------
# Custom app settings
# ---------------------------------------------------------------------------
# Security ticker cache settings (seconds)
SECURITY_TICKER_CACHE_TIMEOUT = 3600  # 1 hour

# ThreatMap configuration (kept simple, safe defaults)
THREATMAP = {
    "PROVIDER": "cloudflare",
    "CACHE_SECONDS": 300,      # server-side cache for 5 minutes
    "POINT_LIMIT": 20,         # max number of locations to render
    "AUTO_REFRESH_MS": 300000, # client refresh every 5 minutes
}


# ---------------------------------------------------------------------------
# Session / login behavior (A07: Session Management)
# ---------------------------------------------------------------------------
# Expire sessions when the browser closes (safer for shared machines).
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Maximum age (seconds) for a session cookie (8 hours).
SESSION_COOKIE_AGE = 28800

# Hardened defaults (Django already uses HTTPOnly for session cookies)
SESSION_COOKIE_HTTPONLY = True

# Login / logout redirects
LOGIN_REDIRECT_URL = "/"                  # or "/breaches/" if preferred
LOGOUT_REDIRECT_URL = "/accounts/login/"
