# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project

import re
from pathlib import Path

import pytest
from django.template.loader import get_template

APP_NAME = "security_ticker"
SRC_ROOT = Path(__file__).resolve().parents[1]
APP_DIR = SRC_ROOT / APP_NAME

FORBIDDEN_IMPORT = re.compile(r"\bfrom\s+DarkWebLeakFinder\b|\bimport\s+DarkWebLeakFinder\b")

@pytest.mark.django_db
def test_app_has_basic_structure():
    assert (APP_DIR / "apps.py").exists(), f"{APP_NAME}: apps.py missing"
    assert (APP_DIR / "urls.py").exists(), f"{APP_NAME}: urls.py missing"
    assert (APP_DIR / "services").exists(), f"{APP_NAME}: services/ folder missing (recommended)"
    assert (APP_DIR / "templates" / APP_NAME).exists(), f"{APP_NAME}: templates/{APP_NAME} missing"
    assert (APP_DIR / "static" / APP_NAME).exists(), f"{APP_NAME}: static/{APP_NAME} missing"

def test_no_project_specific_imports():
    offenders = []
    for py in APP_DIR.rglob("*.py"):
        text = py.read_text(encoding="utf-8", errors="ignore")
        if FORBIDDEN_IMPORT.search(text):
            offenders.append(str(py))
    assert not offenders, f"{APP_NAME}: Project-specific imports found: {offenders}"

@pytest.mark.django_db
def test_templates_are_namespaced_and_loadable():
    # At least one known template in the app; adjust filename if different
    tpl_name = f"{APP_NAME}/_ticker.html"
    tpl = get_template(tpl_name)
    assert tpl.origin.name.endswith("_ticker.html"), f"{APP_NAME}: Template {tpl_name} did not resolve correctly"

def test_has_migrations_dir_if_models_present():
    # If the app defines any models.py or similar, migrations folder should exist
    models_file = APP_DIR / "models.py"
    if models_file.exists() and models_file.read_text().strip():
        mig_init = APP_DIR / "migrations" / "__init__.py"
        assert mig_init.exists(), f"{APP_NAME}: migrations/__init__.py missing (models detected)"

def test_static_subdirs_exist():
    for sub in ("css", "js", "img"):
        assert (APP_DIR / "static" / APP_NAME / sub).exists(), \
            f"{APP_NAME}: static/{APP_NAME}/{sub} missing"
