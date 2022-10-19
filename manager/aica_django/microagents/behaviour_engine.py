"""
This microagent is responsible for querying the knowledge base for relevant facts
when invoked by the decision-making engine and returning any relevant parameters or
limitations needed in determining a course of action.

This should eventually include:
* Stealth & Security
* Self-control
* Collaboration control

Functions:
    get_manager_ips: Get any IP addresses used by the Manager agent.
    query_rules: Query the knowledge base for any rules and scoring pertaining
    to a proposed action given a specific alert.
"""

from celery.app import shared_task
from celery.utils.log import get_task_logger
from netifaces import interfaces, ifaddresses, AF_INET  # type: ignore
from typing import Any, Dict, List, Union

logger = get_task_logger(__name__)


def get_manager_ips() -> List[str]:
    """
    Get any IP addresses used by the Manager agent.

    @return: List of IP address strings
    @rtype: list
    """

    ip_list = []
    for interface in interfaces():
        if AF_INET not in ifaddresses(interface):
            continue
        for link in ifaddresses(interface)[AF_INET]:
            ip_list.append(link["addr"])
    return ip_list


@shared_task(name="ma-behavior_engine-query_rules")
def query_rules(alert_dict: Dict[str, Any], candidate_action: Dict[str, Any]) -> float:
    """
    Query the knowledge base for any rules and scoring pertaining to a proposed action given a specific alert.

    @param alert_dict: An observed alert as returned by aica_django.connectors.Suricata.poll_suricata_alerts
    @type alert_dict: dict
    @param candidate_action: A proposed action as specified in response_actions.yml and selected by the DME
    @type candidate_action: dict
    @return: A value indicating the preference for this action, negative values being preference to avoid
    @rtype: float
    """

    logger.info(f"Running {__name__}: query_rules for {candidate_action['action']}")

    alert_details = alert_dict["alert"]

    # This is stubbed out for initial demonstration purposes
    if candidate_action["action"] == "honeypot":
        if (
            alert_dict["event_type"] == "alert"
            and int(alert_details["severity"]) >= 2
            and alert_dict["src_ip"] not in get_manager_ips()
        ):
            return 1.0
    elif candidate_action["action"] == "scan_source":
        if (
            alert_dict["event_type"] == "alert"
            and int(alert_details["severity"]) >= 2
            and alert_dict["src_ip"] not in get_manager_ips()
        ):
            return 1.0
    elif candidate_action["action"] == "scan_target":
        if (
            alert_dict["event_type"] == "alert"
            and int(alert_details["severity"]) >= 2
            and alert_dict["dest_ip"] not in get_manager_ips()
        ):
            return 1.0

    return -1.0
