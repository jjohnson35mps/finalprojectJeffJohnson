# src/core/urls.py
# ----------------
# Routes the site root to the dashboard and wires the breaches app under /breaches/.
from django.urls import path, include

urlpatterns = [
    path("", include("dashboard.urls")),   # /  -> dashboard home
    path("breaches/", include("breaches.urls")),
]
