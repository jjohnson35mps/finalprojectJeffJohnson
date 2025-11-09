# src/tests/test_project_includes_apps.py
# ------------------------------------------------------------
# Verifies the project-level URLConf includes each app’s urls module.
from __future__ import annotations
from typing import Iterable
from django.urls import URLResolver
from DarkWebLeakFinder import urls as project_urls

def _iter_resolvers(patterns: Iterable):
    for p in patterns:
        if isinstance(p, URLResolver):
            yield p

def test_project_includes_breaches_urls():
    includes = [r for r in _iter_resolvers(project_urls.urlpatterns)]
    targets = [r.urlconf_module for r in includes]
    assert any(getattr(m, "__name__", "").endswith("breaches.urls") for m in targets), \
        "Project urls.py should include breaches.urls via include(...)."

def test_project_includes_dashboard_urls():
    includes = [r for r in _iter_resolvers(project_urls.urlpatterns)]
    targets = [r.urlconf_module for r in includes]
    assert any(getattr(m, "__name__", "").endswith("dashboard.urls") for m in targets), \
        "Project urls.py should include dashboard.urls via include(...)."
