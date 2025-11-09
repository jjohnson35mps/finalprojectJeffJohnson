# src/tests/test_modularity_breaches.py
# ------------------------------------------------------------
# Jeff Johnson — INF 601 Advanced Python — Final Project
# Purpose: Assert that the "breaches" app is modular:
# - Has AppConfig and migrations
# - Namespaced templates/static paths
# - No hard imports from the project package (DarkWebLeakFinder)
# - Templates renderable via the loader (namespacing is correct)

import re
from pathlib import Path
import pytest
from django.template.loader import get_template

APP_NAME = "breaches"
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
    # Forbid imports like "from DarkWebLeakFinder.settings import ..."
    forbidden = re.compile(r"\bfrom\s+DarkWebLeakFinder\b|\bimport\s+DarkWebLeakFinder\b")
    offenders = []
    for py in APP_DIR.rglob("*.py"):
        text = py.read_text(encoding="utf-8", errors="ignore")
        if forbidden.search(text):
            offenders.append(str(py))
    assert not offenders, f"Project-specific imports found: {offenders}"

@pytest.mark.django_db
def test_templates_are_namespaced_and_loadable():
    # If the app ships templates correctly, the loader can resolve them by namespaced path
    # Note: we just verify the file listed in your tree.
    tmpl = f"{APP_NAME}/main_db.html"
    tpl = get_template(tmpl)
    assert tpl.origin.name.endswith("main_db.html")

def test_has_at_least_one_migration_file():
    migs = list((APP_DIR / "migrations").glob("0*.py"))
    assert migs, "No migrations found; app should define its own DB schema."

def test_services_package_present():
    assert (APP_DIR / "services").exists(), "services/ package missing (good practice for modularity)"

def test_static_subdirs_exist():
    # Not strictly required, but good modular hygiene
    for sub in ("css", "js", "img"):
        assert (APP_DIR / "static" / APP_NAME / sub).exists(), f"static/{APP_NAME}/{sub} missing"
