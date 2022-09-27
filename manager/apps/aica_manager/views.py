from django.shortcuts import render
from django.http import HttpResponse
from aica_django.aica_celery import app


def modules(request):
    html = "<h1>AICA Manager</h1>"
    tasks = list(sorted(name for name in app.tasks if not name.startswith("celery.")))
    html += f"{tasks}"
    return HttpResponse(html)


def index(request):
    return render(request, "index.html")
