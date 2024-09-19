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

import os
import glob
import yaml
import glob

from celery.signals import worker_ready, celeryd_after_setup
from celery.utils.log import get_task_logger
from typing import Any, Dict

from aica_django.connectors.Antivirus import poll_clamav_alerts
from aica_django.connectors.DNP3 import capture_dnp3, replay_dnp3_pcap
from aica_django.connectors.DocumentDatabase import AicaMongo
from aica_django.connectors.GraphDatabase import (
    AicaNeo4j,
    prune_netflow_data,
)
from aica_django.connectors.HTTPServer import poll_nginx_accesslogs
from aica_django.connectors.IntrusionDetection import poll_suricata_alerts
from aica_django.connectors.Netflow import network_flow_capture
from aica_django.connectors.NetworkScan import periodic_network_scan
from aica_django.microagents.online_learning import periodic_predictor, periodic_trainer
from aica_django.microagents.util import (
    create_malware_categories,
    create_port_info,
    create_suricata_categories,
)
from django.conf import settings

logger = get_task_logger(__name__)


@celeryd_after_setup.connect
def capture_worker_name(sender: str, instance: Any, **kwargs: Any) -> None:
    os.environ["WORKER_NAME"] = f"{sender}"


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

    # Only run this for the default queue worker (because it only needs to run once)
    if not os.environ["WORKER_NAME"].endswith("@default"):
        return

    logger.error(f"Running {__name__}: initialize in {os.environ['WORKER_NAME']}")

    # Load data from static files into MongoDB
    mongo_client = AicaMongo()
    mongo_db = mongo_client.get_db_handle()

    graph = AicaNeo4j(initialize_graph=True, poll_graph=True)

    with open("response_actions.yml", "r") as actions_file:
        alert_actions = yaml.safe_load(actions_file)["responseActions"]["alerts"]
        mongo_db["alert_response_actions"].insert_many(alert_actions)

    if os.environ.get("SKIP_TASKS"):
        return

    ### Preload Contextual Data ###
    # To update this data, run each of these functions without import_file and export with APOC to an updated file, like:
    #     CALL apoc.export.json.all("aica-suricata_categories-20240815.json", {useTypes:true})
    # Although this is a bit clunky, creating this data from scratch (esp nmap port info) takes a while, so we don't
    # want to do it on each start of the agent if we can avoid it.

    # Load ClamAV Categories into Graph
    create_malware_categories(
        import_file="/graph_data/aica-malware_categories-20240815.json"
    )
    logger.info("Loaded ClamAV Categories.")

    # Get Suricata rule classes and load into Graph
    create_suricata_categories(
        import_file="/graph_data/aica-suricata_categories-20240815.json"
    )
    logger.info("Loaded Suricata Categories.")

    # Get nmap-services and load into Graph
    create_port_info(
        import_file="/graph_data/aica-nmap_port_info-20240815.json",
    )
    logger.info("Loaded Port Info.")

    ### Start Tasks ###

    # Start netflow collector
    network_flow_capture.apply_async()

    # Start periodic network scans of local subnets in background
    # If HOME_NET isn't specified, this will fallback to scanning local nets based on interface configs
    periodic_network_scan.apply_async(kwargs={"nmap_target": os.getenv("HOME_NET")})

    # Start polling for Nginx access logs
    poll_nginx_accesslogs.apply_async()

    # Start polling for IDS alerts in background
    poll_suricata_alerts.apply_async()

    # Start polling for AV alerts in background
    poll_clamav_alerts.apply_async()

    # Start the DNP3 capture in background
    capture_dnp3.apply_async(kwargs={"interface": os.getenv("SURICATA_IF")})

    # Start the Netflow graph pruner in background
    prune_netflow_data.apply_async()

    # Start periodic training task
    periodic_trainer.apply_async(kwargs={"period_seconds": 300})

    # Start periodic prediction task
    periodic_predictor.apply_async(kwargs={"period_seconds": 300})

    # Replay DNP3 files if requested
    if getattr(settings, "REPLAY_PCAP", None):
        pcap_files = list(glob.glob("pcaps/*/DNP3 PCAP Files/*.pcap"))
        if len(pcap_files) == 0:
            logger.error("Requested to replay PCAPs, but none found.")
        else:
            for pcap_file in pcap_files:
                logger.info(f"Replaying DNP3 PCAP file: {pcap_file}")
                replay_dnp3_pcap.apply_async(
                    kwargs={"pcap_file": pcap_file, "sample": 0.1, "sample_min": 1000},
                    queue="pcap_replay",
                )
