"""
WSGI config for manager project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

from aica_django.microagents.offline_loader import initialize

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aica_django.settings")

application = get_wsgi_application()