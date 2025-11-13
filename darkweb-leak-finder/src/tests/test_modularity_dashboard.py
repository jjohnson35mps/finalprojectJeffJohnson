# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/tests/test_modularity_dashboard.py
# ------------------------------------------------------------
# Jeff Johnson — INF 601 Advanced Python — Final Project
# Purpose: Assert that the "dashboard" app is modular using the same criteria:
# - AppConfig/migrations present
# - Namespaced templates/static
# - No hard project imports
# - Templates are loadable via loader

import re
from pathlib import Path
import pytest
from django.template.loader import get_template

APP_NAME = "dashboard"
SRC_ROOT = Path(__file__).resolve().parents[1]
APP_DIR = SRC_ROOT / APP_NAME

@pytest.mark.django_db
def test_app_has_basic_structure():
    assert (APP_DIR / "apps.py").exists(), "apps.py missing"
    assert (APP_DIR / "migrations" / "__init__.py").exists(), "migrations package missing"
    assert (APP_DIR / "urls.py").exists(), "urls.py missing"
    assert (APP_DIR / "templates" / APP_NAME).exists(), "templates/<appname> missing"
    assert (APP_DIR / "static" / APP_NAME).exists(), "static/<appname> missing"

def test_no_project_specific_imports():
    forbidden = re.compile(r"\bfrom\s+DarkWebLeakFinder\b|\bimport\s+DarkWebLeakFinder\b")
    offenders = []
    for py in APP_DIR.rglob("*.py"):
        text = py.read_text(encoding="utf-8", errors="ignore")
        if forbidden.search(text):
            offenders.append(str(py))
    assert not offenders, f"Project-specific imports found: {offenders}"

@pytest.mark.django_db
def test_templates_are_namespaced_and_loadable():
    # Your tree shows home.html and detail.html
    for name in ("home.html", "detail.html"):
        tpl = get_template(f"{APP_NAME}/{name}")
        assert tpl.origin.name.endswith(name)

def test_has_migrations_dir():
    migs = list((APP_DIR / "migrations").glob("*.py"))
    assert any(m.name.startswith("0") for m in migs) or len(migs) >= 1, (
        "Expected at least an initial migration (even if empty)."
    )

def test_static_subdirs_exist():
    for sub in ("css", "js", "img"):
        assert (APP_DIR / "static" / APP_NAME / sub).exists(), f"static/{APP_NAME}/{sub} missing"
