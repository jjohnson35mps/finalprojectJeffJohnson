# src/dashboard/urls.py
# ---------------------
from django.urls import path
from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.home, name="home"),
    path("<int:pk>/", views.detail, name="detail"),
]
