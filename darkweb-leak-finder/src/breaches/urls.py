# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/breaches/urls.py

from django.urls import path
from . import views

app_name = "breaches"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("add/", views.add_identity, name="add"),
    path("<int:pk>/scan/", views.scan_identity, name="scan"),
    path("scan/", views.scan_target, name="scan_target"),
    path("identity/<int:pk>/", views.identity_detail, name="identity_detail"),
    path("identity/<int:pk>/scan/", views.scan_identity, name="scan_identity"),
    path("identity/<int:pk>/delete/", views.delete_identity, name="delete_identity"),
    path("scan/<int:pk>/delete/", views.delete_scan, name="delete_scan"),
]
