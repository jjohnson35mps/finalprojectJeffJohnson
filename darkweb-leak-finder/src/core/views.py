# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project

from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from django.urls import reverse_lazy

def register(request):
    # If already logged in, don’t show register again
    if request.user.is_authenticated:
        return redirect("breaches:dashboard")

    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Option A: auto-login and send to dashboard
            login(request, user)
            return redirect("breaches:dashboard")
            # Option B: send them to login page instead:
            # return redirect("login")
    else:
        form = UserCreationForm()

    return render(request, "registration/register.html", {"form": form})

@login_required(login_url='login')
def register_view(request):
    # If the user is already authenticated, redirect them away
    if request.user.is_authenticated:
        return redirect(reverse_lazy('breaches:dashboard'))

    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Automatically log in the newly created user
            login(request, user)
            return redirect(reverse_lazy('breaches:dashboard'))
    else:
        form = UserCreationForm()

    return render(
        request,
        'registration/register.html',
        {'form': form}
    )
