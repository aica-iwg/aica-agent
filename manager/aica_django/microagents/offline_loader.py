"""
This microagent is responsible for pulling in any external data relevant to
decision-making by the agent and loading/sending it to the knowledgebase microagent.

It is the initial script called when Celery is started and is responsible for
launching other tasks.

This should eventually include:
* World Description
* Competence
* Purpose
* Behavior

Functions:
    initialize: The function called in this module as soon as Celery says we're ready to start.
    create_clamav: Load a static list of ClamAV malware categories into the graph.
    create_ports: Load Nmap's list (from web) of port/service info into the graph.
    create_suricata: Load Suricata's list (from web) of alert categories into the graph.
"""

import json
import logging
import os
import pandas as pd
import requests
import time
import yaml

from celery.signals import worker_ready
from celery.utils.log import get_task_logger
from io import StringIO
from joblib import Parallel, delayed
from multiprocessing import cpu_count
from numpy import ndarray
from py2neo import ConnectionUnavailable  # type: ignore
from stix2 import AttackPattern, Note, Software  # type: ignore
from typing import Any, Dict

from aica_django.connectors.DNP3 import replay_pcap, capture_dnp3

from aica_django.connectors.DocumentDatabase import AicaMongo
from aica_django.connectors.GraphDatabase import AicaNeo4j, prune_netflow_data
from aica_django.connectors.Netflow import network_flow_capture
from aica_django.connectors.HTTPServer import poll_nginx_accesslogs
from aica_django.connectors.CaddyServer import poll_caddy_accesslogs
from aica_django.connectors.NetworkScan import periodic_network_scan
from aica_django.connectors.IntrusionDetection import poll_suricata_alerts
from aica_django.connectors.Antivirus import poll_clamav_alerts
from aica_django.connectors.WAF import poll_waf_alerts
from aica_django.converters.Knowledge import knowledge_to_neo

logger = get_task_logger(__name__)


def create_malware_categories() -> None:
    """
    Load a static list of ClamAV malware categories into the graph.

    @return: True once complete.
    @rtype: bool
    """

    # From: https://docs.clamav.net/manual/Signatures/SignatureNames.html
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

    logger.info("Creating malware categories from ClamAV data...")

    malware_categories = []
    for category in clamav_categories:
        malware_signature = AttackPattern(name=f"clamav:{category}")
        malware_categories.append(malware_signature)

    knowledge_to_neo(malware_categories)

    logger.info("Created malware categories from ClamAV data.")


def port_to_note(rank, row, port_root_id):
    if isinstance(rank, int):
        rank = int(rank)
    elif isinstance(rank, slice):
        rank = int(rank.start)
    elif isinstance(rank, ndarray):
        rank = int(rank[0])
    else:
        raise ValueError

    port_object = Note(
        abstract=f"{row['port_number']}/{row['protocol']}",
        content=json.dumps(
            {
                "port": row["port_number"],
                "protocol": row["protocol"],
                "service": row["service"],
                "frequency": row["frequency"],
                "rank": rank,
                "top10": rank < 10,
                "top100": rank < 100,
                "top1000": rank < 1000,
            }
        ),
        object_refs=[port_root_id],
    )

    return port_object


def create_port_info(num_ports: int = 10000) -> None:
    """
    Load Nmap's list (from web) of port/service info into the graph.

    @return: True once complete.
    @rtype: bool
    """
    nmap_services_url = (
        "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
    )

    logger.info("Creating port info from nmap data...")

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
        index_col=False,
    )
    nmap_df[["port_number", "protocol"]] = nmap_df["port"].str.split("/", expand=True)
    nmap_df.drop(columns=["comment", "port"], axis=1, inplace=True)
    nmap_df.sort_values(by="frequency", inplace=True, ascending=False)
    nmap_df = nmap_df.head(num_ports)
    nmap_df = nmap_df.reset_index(drop=True)

    port_objects = []

    port_root = Software(name="Generic Port Usage Info")
    port_objects.append(port_root)

    port_objects = Parallel(n_jobs=cpu_count() - 1 or 1)(
        delayed(port_to_note)(nmap_df.index.get_loc(key=index), row, port_root.id)
        for index, row in nmap_df.iterrows()
    )

    knowledge_to_neo(port_objects)

    logger.info("Created port info from nmap data.")


def create_suricata_categories() -> None:
    """
    Load Suricata's list (from web) of alert categories into the graph.

    @return: True once complete.
    @rtype: bool
    """
    suricata_classes_url = "https://rules.emergingthreats.net/open/suricata-5.0/rules/classification.config"

    logger.info("Creating Suricata alert classes...")

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

    attack_patterns = []
    for _, row in suricata_df.iterrows():
        attack_pattern = AttackPattern(
            type="attack-pattern",
            name=row["name"],
            description=row["description"],
            custom_properties={"severity": row["priority"]},
        )
        attack_patterns.append(attack_pattern)

    knowledge_to_neo(attack_patterns)

    logger.info("Created Suricata alert classes.")


@worker_ready.connect
def initialize(**kwargs: Dict[Any, Any]) -> None:
    """
    The function called in this module as soon as Celery says we're ready to start. It performs
    any initial setup needed to bootstrap the agent, and then fires any async/periodic jobs.

    @param kwargs: Currently unused, required by Celery.
    @type kwargs: dict
    @return: True once completed.
    @rtype: bool
    """
    logger.info(f"Running {__name__}: initialize")

    # Load data from static files into MongoDB
    mongo_client = AicaMongo()
    mongo_db = mongo_client.get_db_handle()

    with open("response_actions.yml", "r") as actions_file:
        alert_actions = yaml.safe_load(actions_file)["responseActions"]["alerts"]
        mongo_db["alert_response_actions"].insert_many(alert_actions)

    if os.environ.get("SKIP_TASKS"):
        return True

    # Wait for graph to be available
    while True:
        try:
            graph = AicaNeo4j()
            break
        except ConnectionUnavailable:
            time.sleep(1)

    ### Preload Contextual Data ###

    # Load ClamAV Categories into Graph
    create_malware_categories()

    # Get Suricata rule classes and load into Graph
    create_suricata_categories()

    # Get nmap-services and load into Graph
    create_port_info()

    ### Start Tasks ###

    # Start netflow collector
    network_flow_capture.delay()

    # Start periodic network scans of local subnets in background
    periodic_network_scan.delay()

    # Start polling for Nginx access logs
    poll_nginx_accesslogs.delay()

    # Start polling for Caddy access logs
    poll_caddy_accesslogs.delay()

    # Start polling for IDS alerts in background
    poll_suricata_alerts.delay()

    # Start polling for AV alerts in background
    poll_clamav_alerts.delay()

    # Start polling for WAF alerts in background
    poll_waf_alerts.delay()

    # Start the Netflow graph pruner in background
    prune_netflow_data.delay()

    ### TESTING ONLY ###

    # Switch to live capture later
    # replay_pcap.delay(
    #     kwargs={
    #         "pcap_file": "pcaps/20200514_DNP3_Disable_Unsolicited_Messages_Attack/DNP3 PCAP Files/20200514_DNP3_Disable_Unsolicited_Messages_Attack_UOWM_DNP3_Dataset_Master.pcap"
    #     }
    # )
    # capture_dnp3().delay(args=["eth2"])
