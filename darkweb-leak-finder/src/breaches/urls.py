# src/breaches/urls.py
# --------------------
# Wires the URL /breaches/add/ to add_identity in views.py.

from django.urls import path
from . import views

app_name = "breaches"

urlpatterns = [
    path("add/", views.add_identity, name="add"),
    path("<int:pk>/scan/", views.scan_identity, name="scan"),
]
