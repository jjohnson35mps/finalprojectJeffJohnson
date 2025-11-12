# src/threatmap/urls.py
from django.urls import path
from .views import heat_points

app_name = "threatmap"

urlpatterns = [
    path("api/points/", heat_points, name="heat_points"),
]
