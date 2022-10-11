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

import logging
import os
import pandas as pd  # type: ignore
import requests
import time
import yaml

from celery.app import shared_task
from celery.signals import worker_ready
from celery.utils.log import get_task_logger
from io import StringIO
from py2neo import ConnectionUnavailable  # type: ignore

from aica_django.connectors.AicaMongo import AicaMongo
from aica_django.connectors.AicaNeo4j import AicaNeo4j
from aica_django.connectors.Netflow import network_flow_capture
from aica_django.connectors.Nginx import poll_nginx_accesslogs
from aica_django.connectors.Nmap import periodic_network_scan
from aica_django.connectors.Suricata import poll_suricata_alerts
from aica_django.connectors.Antivirus import poll_antivirus_alerts
from aica_django.converters.Knowledge import KnowledgeNode
from aica_django.microagents.knowledge_base import knowledge_to_neo

logger = get_task_logger(__name__)


@shared_task(name="ma-offline_loader-create_clamav")
def create_clamav():
    # https://docs.clamav.net/manual/Signatures/SignatureNames.html
    clamav_categories = [
        "Adware",
        "Backdoor",
        "Coinminer",
        "Countermeasure",
        "Downloader",
        "Dropper",
        "Exploit",
        "File",
        "Filetype",
        "Infostealer",
        "Ircbot",
        "Joke",
        "Keylogger",
        "Loader",
        "Macro",
        "Malware",
        "Packed",
        "Packer",
        "Phishing",
        "Proxy",
        "Ransomware",
        "Revoked",
        "Rootkit",
        "Spyware",
        "Test",
    ]
    class_objects = []
    for category in clamav_categories:
        class_object = KnowledgeNode(
            label="AttackSignatureCategory",
            name=category,
            values={
                "name": category,
                "source": "https://docs.clamav.net/manual/Signatures/SignatureNames.html",
            },
        )
        class_objects.append(class_object)

    knowledge_to_neo(class_objects)


@shared_task(name="ma-offline_loader-create_ports")
def create_ports():
    nmap_services_url = (
        "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
    )
    resp = requests.get(nmap_services_url)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        logging.error("Couldn't fetch nmap services data, skipping.")
    nmap_file = StringIO(resp.text)
    nmap_df = pd.read_csv(
        nmap_file,
        sep="\t",
        comment="#",
        header=None,
        names=["service", "port", "frequency", "comment"],
    )
    nmap_df[["port_number", "protocol"]] = nmap_df["port"].str.split("/", expand=True)
    nmap_df.drop(columns=["comment", "port"], axis=1, inplace=True)
    nmap_df.sort_values(by="frequency", inplace=True, ascending=False)
    port_objects = []
    for index, row in nmap_df.iterrows():
        rank = nmap_df.index.get_loc(key=index)
        port_object = KnowledgeNode(
            label="NetworkPort",
            name=f"{row['port_number']}/{row['protocol']}",
            values={
                "port": row["port_number"],
                "protocol": row["protocol"],
                "service": row["service"],
                "frequency": row["frequency"],
                "rank": rank,
                "top10": rank < 10,
                "top100": rank < 100,
                "top1000": rank < 1000,
                "source": nmap_services_url,
            },
        )
        port_objects.append(port_object)

    knowledge_to_neo(port_objects)


@shared_task(name="ma-offline_loader-create_suricata")
def create_suricata():
    suricata_classes_url = "https://rules.emergingthreats.net/open/suricata-5.0/rules/classification.config"
    resp = requests.get(suricata_classes_url)
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        logging.error("Couldn't fetch suricata class data, skipping.")
    suricata_file = StringIO(resp.text.replace("config classification: ", ""))
    suricata_df = pd.read_csv(
        suricata_file,
        sep=",",
        comment="#",
        header=None,
        names=["name", "description", "priority"],
    )
    class_objects = []
    for index, row in suricata_df.iterrows():
        class_object = KnowledgeNode(
            label="AttackSignatureCategory",
            name=row["name"],
            values={
                "name": row["name"],
                "description": row["description"],
                "priority": row["priority"],
                "source": suricata_classes_url,
            },
        )
        class_objects.append(class_object)

    knowledge_to_neo(class_objects)


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
        return True

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

    # Load ClamAV Categories into Graph
    create_clamav.apply_async()

    # Get nmap-services and load into Graph
    create_ports.apply_async()

    # Get Suricata rule classes and load into Graph
    create_suricata.apply_async()

    # Start netflow collector
    network_flow_capture.apply_async()

    # Start periodic network scans of local subnets in background
    periodic_network_scan.apply_async()

    # Start polling for Nginx access logs
    poll_nginx_accesslogs.apply_async()

    # Start polling for IDS alerts in background
    poll_suricata_alerts.apply_async()

    # Start polling for AV alerts in background
    poll_antivirus_alerts.apply_async()
