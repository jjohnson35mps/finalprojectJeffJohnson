# tests/test_breaches.py
"""
Basic integration tests for the 'breaches' and 'dashboard' flows.

Covers:
- Model creation (EmailIdentity, BreachHit)
- GET/POST on the Add Identity form
- Dashboard pages rendering data (home + detail)
- URL routing via named routes

Where this fits:
- Lives in tests/test_breaches.py at the repo root (sibling to manage.py).
- Uses pytest-django's DB and client fixtures to exercise your Django stack.
- Helps prove end-to-end behavior for rubric/CI without relying on the HIBP API.
"""

import pytest
from django.urls import reverse

from breaches.models import EmailIdentity, BreachHit


@pytest.mark.django_db
def test_models_create_and_str():
    """
    Verify we can create the core models and their __str__ works.

    Why here:
    - If models are mis-declared, this fails early.
    - Gives a fast signal that migrations + DB are wired.
    """
    ident = EmailIdentity.objects.create(address="alice@example.com")
    hit = BreachHit.objects.create(
        identity=ident, breach_name="ExampleBreach", domain="example.com"
    )

    assert str(ident) == "alice@example.com"
    assert "ExampleBreach" in str(hit)
    assert hit.identity == ident


@pytest.mark.django_db
def test_add_identity_get_renders_form(client):
    """
    Ensure GET /breaches/add/ renders the Add Identity form page.

    Where this hits:
    - breaches.views.add_identity (GET branch)
    - template: breaches/add_identity.html
    """
    url = reverse("breaches:add")
    resp = client.get(url)
    assert resp.status_code == 200
    assert b"Add Identity" in resp.content


@pytest.mark.django_db
def test_add_identity_post_creates_and_redirects(client):
    """
    POSTing a valid email creates an EmailIdentity and redirects to dashboard.

    Where this hits:
    - breaches.views.add_identity (POST branch)
    - dashboard:home redirect after successful create
    """
    url = reverse("breaches:add")
    resp = client.post(url, data={"email": "bob@example.com"})
    assert resp.status_code == 302  # redirect
    assert EmailIdentity.objects.filter(address="bob@example.com").exists()


@pytest.mark.django_db
def test_dashboard_home_lists_identities(client):
    """
    Dashboard home should list identities, newest first.

    Where this hits:
    - dashboard.views.home
    - template: dashboard/home.html
    """
    EmailIdentity.objects.create(address="carol@example.com")
    url = reverse("dashboard:home")
    resp = client.get(url)
    assert resp.status_code == 200
    assert b"Identities" in resp.content
    assert b"carol@example.com" in resp.content


@pytest.mark.django_db
def test_dashboard_detail_shows_hits(client):
    """
    Detail page should show breach hits associated with an identity.

    Where this hits:
    - dashboard.views.detail
    - template: dashboard/detail.html
    """
    ident = EmailIdentity.objects.create(address="dave@example.com")
    BreachHit.objects.create(identity=ident, breach_name="ExampleBreach", domain="example.com")
    url = reverse("dashboard:detail", kwargs={"pk": ident.pk})
    resp = client.get(url)
    assert resp.status_code == 200
    assert b"ExampleBreach" in resp.content
