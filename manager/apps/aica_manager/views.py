# from django.shortcuts import render
from django.http import HttpResponse
from aica_django.aica_celery import app
from apps.aica_manager.models import Host, NetworkTraffic


def modules(request):
    html = "<h1>AICA Manager</h1>"
    tasks = list(sorted(name for name in app.tasks if not name.startswith("celery.")))
    html += f"{tasks}"
    return HttpResponse(html)


def overview(request):
    host_list = Host.nodes.all()
    html = "<h1>Hosts</h1>"
    html += ", ".join([str(x) for x in host_list])

    flow_list = NetworkTraffic.nodes.all()
    html += "<h1>Network Flows</h1>"
    html += ", ".join([str(x) for x in flow_list])

    return HttpResponse(html)

    # return render(request, "index.html")
