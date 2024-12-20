"""
This microagent is responsible for storing facts about external data, past
observations, possible actions, and other information necessary for the decisioning
engine to determine the best course of action in response to an observed event. Much
of this will be loaded by the offline loader at startup from static configuration,
periodically by the offline loader, or by the online learning microagent.

This should eventually include:
* World model
* World state & history
* World dynamics model
* Actions & effects repertoire
* Goals (missions & limits)
* Agent states, priorities, rules, plans, and configurations

Functions:
    query_action:
    record_antivirus_alert:
    record_netflow:
    record_nginx_accesslog:
    record_nmap_scan:
    record_suricata_alert:
"""

from celery.app import shared_task
from celery.utils.log import get_task_logger
from typing import Any, Dict, List

from aica_django.connectors.DocumentDatabase import AicaMongo
from aica_django.converters.Knowledge import (
    netflow_to_knowledge,
    nginx_accesslog_to_knowledge,
    nmap_scan_to_knowledge,
    suricata_alert_to_knowledge,
    clamav_alert_to_knowledge,
    dnp3_to_knowledge,
    knowledge_to_neo,
)

logger = get_task_logger(__name__)


def query_action(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Query for possible actions to respond to given alert.

    @param alert: Alert as passed by the DME.
    @type alert: dict
    @return: List of possible response actions
    @rtype: List[dict]
    """

    logger.info(f"Running {__name__}: query_action")
    mongo_client = AicaMongo()
    mongo_db = mongo_client.get_db_handle()

    recommended_actions: List[Dict[str, Any]] = []
    if alert["event_type"] == "alert":
        query = {
            "$and": [
                {"event_type": "alert"},
                {
                    "$or": [
                        {"signature_id": alert["alert"]["signature_id"]},
                        {"signature_id": "*"},
                    ]
                },
            ]
        }
        recommended_actions = [
            dict(x) for x in mongo_db["alert_response_actions"].find(query)
        ]

    return recommended_actions


@shared_task(name="ma-knowledge_base-record_netflow")
def record_netflow(flow: Dict[str, Any]) -> None:
    """
    Convert a flow dictionary to Knowledge objects and store in the knowledge graph database.

    @param flow: The flow to be recorded.
    @type flow: dict
    @return: Return status of the attempt to add items to graph database.
    @rtype: bool
    """

    logger.info(f"Running {__name__}: record_netflow")
    nodes = netflow_to_knowledge(flow)

    knowledge_to_neo(nodes)


@shared_task(name="ma-knowledge_base-record_nmap_scan")
def record_nmap_scan(scan_result: Dict[str, Any]) -> None:
    """
    Convert an nmap scan result to Knowledge objects and store in the knowledge graph database.

    @param scan_result: The scan result to be recorded.
    @type scan_result: dict
    @return: Return status of the attempt to add items to graph database.
    @rtype: bool
    """

    logger.info(f"Running {__name__}: record_nmap_scan")
    nodes = nmap_scan_to_knowledge(scan_result)
    logger.debug(
        f"record_nmap_scan knowledge_to_neo: number of nodes: {str(len(nodes))}"
    )

    knowledge_to_neo(nodes)


@shared_task(name="ma-knowledge_base-record_suricata_alert")
def record_suricata_alert(alert: Dict[str, Any]) -> None:
    """
    Convert a Suricata alert to Knowledge objects and store in the knowledge graph database.

    @param alert: The alert to be recorded.
    @type alert: dict
    @return: Return status of the attempt to add items to graph database.
    @rtype: bool
    """

    logger.info(f"Running {__name__}: record_alert")
    nodes = suricata_alert_to_knowledge(alert)

    knowledge_to_neo(nodes)


@shared_task(name="ma-knowledge_base-record_antivirus_alert")
def record_antivirus_alert(alert: Dict[str, str]) -> None:
    """
    Convert an Antivirus alert to Knowledge objects and store in the knowledge graph database.

    @param alert: The alert to be recorded.
    @type alert: dict
    @return: Return status of the attempt to add items to graph database.
    @rtype: bool
    """

    logger.info(f"Running{__name__}: record_alert")
    nodes = clamav_alert_to_knowledge(alert)

    knowledge_to_neo(nodes)


@shared_task(name="ma-knowledge_base-record_nginx_accesslog")
def record_nginx_accesslog(log_entry: Dict[str, str]) -> None:
    """
    Convert an HTTP access log entry to Knowledge objects and store in the knowledge graph database.

    @param log_entry: The log entry to be recorded.
    @type log_entry: dict
    @return: Return status of the attempt to add items to graph database.
    @rtype: bool
    """
    logger.info(f"Running {__name__}: record_nginx_accesslog")
    nodes = nginx_accesslog_to_knowledge(log_entry)

    knowledge_to_neo(nodes)


@shared_task(name="ma-knowledge_base-record_dnp3")
def record_dnp3(log_entry: Dict[str, str]) -> None:
    """
    Convert a DNP3 message to Knowledge objects and store in the knowledge graph database.

    @param log_entry: The log entry to be recorded.
    @type log_entry: dict
    @return: Return status of the attempt to add items to graph database.
    @rtype: bool
    """
    logger.info(f"Running {__name__}: record_dnp3")
    nodes = dnp3_to_knowledge(log_entry)

    knowledge_to_neo(nodes)
