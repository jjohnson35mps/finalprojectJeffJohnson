# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project
"""
WSGI config for DarkWebLeakFinder project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'DarkWebLeakFinder.settings')

application = get_wsgi_application()
