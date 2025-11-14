# INF601 - Advanced Programming in Python
# Jeff Johnson
# Final Project

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'DarkWebLeakFinder.settings')

application = get_wsgi_application()
