# This microagent is responsible for pulling in any external data relevant to decision
# making by the agent and loading/sending it to the knowledge base microagent.
#
# Per the NCIA SOW this is to include the following undefined capabilities:
#
# * World Description
# * Competence
# * Purpose
# * Behavior
#
# It is the initial script called when Celery is started and is responsible for
# launching other tasks.

import os
import time
import yaml

from celery.signals import worker_ready
from celery.utils.log import get_task_logger
from py2neo import ConnectionUnavailable

from aica_django.connectors.AicaMongo import AicaMongo
from aica_django.connectors.AicaNeo4j import AicaNeo4j
from aica_django.connectors.Netflow import network_flow_capture
from aica_django.connectors.Nginx import poll_nginx_accesslogs
from aica_django.connectors.Nmap import periodic_network_scan
from aica_django.connectors.Suricata import poll_suricata_alerts

logger = get_task_logger(__name__)


@worker_ready.connect
def initialize(**kwargs):
    logger.info(f"Running {__name__}: initialize")

    # Load data from static files into MongoDB
    mongo_client = AicaMongo()
    mongo_db = mongo_client.get_db_handle()

    with open("response_actions.yml", "r") as actions_file:
        alert_actions = yaml.safe_load(actions_file)["responseActions"]["alerts"]
        mongo_db["alert_response_actions"].insert_many(alert_actions)

    if os.environ.get("SKIP_TASKS"):
        return

    # Wait for graph to come up and then set uniqueness constraints
    neo_host = os.getenv("NEO4J_HOST")
    neo_user = os.getenv("NEO4J_USER")
    neo_password = os.getenv("NEO4J_PASSWORD")
    while True:
        try:
            graph = AicaNeo4j(host=neo_host, user=neo_user, password=neo_password)
            graph.create_constraints()
            break
        except ConnectionUnavailable:
            time.sleep(1)

    # Start netflow collector
    network_flow_capture.apply_async()

    # Start periodic network scans of local subnets in background
    periodic_network_scan.apply_async()

    # Start polling for Nginx access logs
    poll_nginx_accesslogs.apply_async()

    # Start polling for IDS alerts in background
    poll_suricata_alerts.apply_async()
