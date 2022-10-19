"""
This microagent is responsible for monitoring the environment and determining the
best course of action to take when potentially interest events are observed. It may
invoke the behavior engine microagent for adjudication on acceptable courses of
action, the knowledge base microagent to enrich its understanding of an observed
event, the online learning microagent to apply ML-based methods to evaluating
observations, or the collaboration microagent to send commands to external devices
for the purposes of response. It is invoked by the offline loader after
initialization.

This should eventually include:
* Situational awareness
* Action planning
* Action selection
* Action activation

Functions:
    handle_suricata_alert: Receive an alert from Suricata and determine/enact a response
    handle_antivirus_alert: Receive an alert from ClamAV and determine/enact a response
"""

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger
from typing import Any, Dict, List, Union

from aica_django.connectors.Honeypot import redirect_to_honeypot_iptables  # noqa: F401
from aica_django.connectors.NetworkScan import network_scan  # noqa: F401
from aica_django.microagents.knowledge_base import query_action
from aica_django.microagents.behaviour_engine import query_rules

logger = get_task_logger(__name__)


@shared_task(name="ma-decision_making_engine-handle_suricata_alert")
def handle_suricata_alert(alert: Dict[str, Union[str, Dict[str, Any]]]) -> bool:
    """
    Ingest an alert from Suricata, evaluate potential options, and decide what to do.

    @param alert: The alert dictionary as provided by the Suricata connector.
    @type alert: dict
    @return: Boolean indication of whether an action was selected or not.
    @rtype: bool
    """

    logger.info(f"Running {__name__}: handle_suricata_alert")

    # Query for recommendation from knowledge base
    recommended_actions: List[Dict[str, Any]] = query_action(alert)

    # Check with behavior engine
    approved_actions = list()
    for action in recommended_actions:
        action["score"] = query_rules(alert, action)
        if action["score"] >= 0:
            approved_actions.append(action)

    # Here we would apply some dynamic scoring as to the best action, using information
    # about goals and world state. For now, we just statically evaluate scores.
    if len(approved_actions) > 0:
        max_score = max([x["score"] for x in approved_actions])
        actions_to_take = [x for x in approved_actions if x["score"] == max_score]

        for action in actions_to_take:
            if action["action"] == "honeypot":
                logger.info(
                    f"Redirecting traffic from {alert['src_ip']} to "
                    f"{alert['dest_ip']} to honeypot."
                )
                current_app.send_task(
                    "redirect_to_honeypot_iptables",
                    [alert["src_ip"], alert["dest_ip"]],
                )
                return True
            elif action["action"] == "scan_src":
                logger.info(f"Initiating return scan to {alert['src_ip']}")
                current_app.send_task("network-scan", nmap_target=alert["src_ip"])
                return True
            elif action["action"] == "scan_target":
                logger.info(f"Initiating scan of target at {alert['dest_ip']}")
                current_app.send_task("network-scan", nmap_target=alert["dest_ip"])
                return True

    return False


@shared_task(name="ma-decision_making_engine-handle_antivirus_alert")
def handle_antivirus_alert(alert: Dict[str, str]) -> bool:
    """
    Ingest an alert from Antivirus (ClamAV), evaluate potential options, and decide what to do.

    @param alert: The alert dictionary as provided by the Suricata connector.
    @type alert: dict
    @return: Boolean indication of whether an action was selected or not.
    @rtype: bool
    """
    logger.info(f"Running {__name__}: handle_antivirus_alert")

    # TODO: Implement some response
    logger.info(alert)

    return False
