import json2table  # type: ignore

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from aica_django.aica_celery import app
from apps.aica_manager.models import Host, Alert


def modules(request: HttpRequest) -> HttpResponse:
    html = "<h1>AICA Manager</h1>"
    tasks = list(sorted(name for name in app.tasks if not name.startswith("celery.")))
    html += f"{tasks}"
    return HttpResponse(html)


def overview(request: HttpRequest) -> HttpResponse:
    data = dict()

    host_list = Host.nodes.all()
    data["hosts"] = json2table.convert(
        {"Hosts": host_list},
        table_attributes={
            "id": "host_table",
            "class": "table table-dark table-striped table-hover table-responsive",
        },
    )

    # Recent Alerts
    alert_list = Alert.nodes.all()
    data["alerts"] = json2table.convert(
        {"Alerts": alert_list},
        table_attributes={
            "id": "alert_table",
            "class": "table table-dark table-striped table-hover table-responsive",
        },
    )

    return render(request, "index.html", data)
