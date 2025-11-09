# security_ticker/apps.py
from django.apps import AppConfig

class SecurityTickerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "security_ticker"
    verbose_name = "Security Ticker"
