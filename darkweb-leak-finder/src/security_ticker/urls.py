# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project

from django.urls import path
from .views import ticker_feed

app_name = "security_ticker"

urlpatterns = [
    path("", ticker_feed, name="ticker-feed"),
]
