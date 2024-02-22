"""
This module defines the views for the Django web frontend

Classes:
    None
Functions:
    modules(request): Listing of Django-enabled modules
    overview(request): "Heads-up-display" for operators
"""

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from aica_django.aica_celery import app


def modules(request: HttpRequest) -> HttpResponse:
    """
    Presents a listing of Django-activated modules, mainly for debugging

    @param request: Django request object
    @type request: HttpRequest
    @return: Django rendered HTTP response
    @rtype: HttpResponse
    """

    html = "<h1>AICA Manager</h1>"
    tasks = list(sorted(name for name in app.tasks if not name.startswith("celery.")))
    html += f"{tasks}"
    return HttpResponse(html)
