"""
This module defines the views for the Django web frontend

Classes:
    None
Functions:
    modules(request): Listing of Django-enabled modules
    overview(request): "Heads-up-display" for operators
"""

import json2table  # type: ignore

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from aica_django.aica_celery import app
from apps.aica_manager.models import Host, Alert


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


def overview(request: HttpRequest) -> HttpResponse:
    """
    Presents a general dashboard "Heads up display" for human operators.

    @param request: Django request object
    @type request: HttpRequest
    @return: Django rendered HTTP response
    @rtype: HttpResponse
    """

    data = dict()

    host_list = Host.nodes.all()
    data["hosts"] = json2table.convert(
        {
            "Hosts": [
                {
                    "IP Address": ", ".join(
                        [
                            y.address
                            for y in (x.ipv4_address.all() + x.ipv6_address.all())
                        ]
                    ),
                    "Alert Count": len(x.alerts()),
                    "Last Seen": x.last_seen,
                    "Suspicious Source Ratio": round(x.suspicious_source_ratio(), 3),
                    "Suspicious Destination Ratio": round(
                        x.suspicious_destination_ratio(), 3
                    ),
                }
                for x in host_list
            ],
        },
        table_attributes={
            "id": "host_table",
            "class": "table table-dark table-striped table-hover table-responsive",
        },
    )

    # Recent Alerts
    alert_list = Alert.nodes.all()
    data["alerts"] = json2table.convert(
        {
            "Alerts": [
                {
                    "Severity": x.attack_signature.single().severity,
                    "Attack Signature": x.attack_signature.single().signature,
                    "Attack Signature Category": x.attack_signature.single()
                    .signature_category.single()
                    .category,
                    "Host": str(
                        x.triggered_by.single().communicates_from.single().ip_address
                    ),
                    "Times Tripped": x.time_tripped,
                }
                for x in alert_list
            ],
        },
        table_attributes={
            "id": "alert_table",
            "class": "table table-dark table-striped table-hover table-responsive",
        },
    )

    return render(request, "index.html", data)
