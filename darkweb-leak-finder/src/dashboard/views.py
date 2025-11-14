# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404
from breaches.models import EmailIdentity

@login_required(login_url='login')
def home(request):
    """
    List page for identities being monitored.
    Renders: templates/dashboard/home.html
    """
    identities = EmailIdentity.objects.all().order_by("-created_at")
    return render(request, "dashboard/home.html", {"identities": identities})

@login_required(login_url='login')
def detail(request, pk: int):
    """
    Detail page for a single identity and its breach hits.
    Renders: templates/dashboard/detail.html
    """
    identity = get_object_or_404(EmailIdentity, pk=pk)
    hits = identity.hits.order_by("-occurred_on", "breach_name")  # newest first
    return render(request, "dashboard/detail.html", {"identity": identity, "hits": hits})
