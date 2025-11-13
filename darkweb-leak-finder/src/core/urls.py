# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/core/urls.py

from django.urls import path, include

urlpatterns = [
    path("", include("dashboard.urls")),   # /  -> dashboard home
    path("breaches/", include("breaches.urls")),
]
