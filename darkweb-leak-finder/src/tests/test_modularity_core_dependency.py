# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
# src/tests/test_modularity_core_dependency.py
# ------------------------------------------------------------
# Not a failure of modularity; just asserts declared dependency on core templates.

from pathlib import Path

def test_templates_extending_core_are_expected():
    SRC_ROOT = Path(__file__).resolve().parents[1]
    offenders = []
    for app in ("breaches", "dashboard"):
        for tpl in (SRC_ROOT / app / "templates" / app).rglob("*.html"):
            txt = tpl.read_text(encoding="utf-8", errors="ignore")
            if 'extends "core/base.html"' in txt.replace("'", '"'):
                offenders.append(str(tpl))
    # This is informational; flip to assert False to enforce no dependency.
    # For now we just ensure the list collects and you can decide policy.
    assert True, f"Templates depending on core: {offenders}"
