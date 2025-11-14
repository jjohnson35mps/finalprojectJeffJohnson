# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'DarkWebLeakFinder.settings')

application = get_asgi_application()
