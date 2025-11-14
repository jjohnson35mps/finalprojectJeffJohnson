# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project

from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from core import views as core_views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path("accounts/register/", core_views.register, name="register"),
    path("accounts/login/", auth_views.LoginView.as_view(template_name="registration/login.html"), name="login"),
    path("", include(("breaches.urls", "breaches"), namespace="breaches")),
    path("dashboard/", include(("dashboard.urls", "dashboard"), namespace="dashboard")),
    path("core/", include(("core.urls", "core"), namespace="core")),
    path("api/ticker/", include(("security_ticker.urls", "security_ticker"), namespace="security_ticker")),
    path("threatmap/", include("threatmap.urls")),
    path("logout/", auth_views.LogoutView.as_view(next_page="/"), name="logout"),
]
