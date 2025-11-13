# src/threatmap/urls.py
from django.urls import path
from . import views

app_name = "threatmap"

urlpatterns = [
    path("api/points/", views.threat_points, name="threat_points"),
]
