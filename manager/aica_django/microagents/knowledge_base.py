# This microagent is responsible for storing facts about external data, past
# observations, possible actions, and other information necessary for the decisioning
# engine to determine the best course of action in response to an observed event. Much
# of this will be loaded by the offline loader at startup from static configuration,
# periodically by the offline loader, or by the online learning microagent.
#
# Per the NCIA SOW, knowledge could include:
#
# * World model
# * World state & history
# * World dynamics model
# * Actions & effects repertoire
# * Goals (missions & limits)
# * Agent states, priorities, rules, plans, and configurations
#
# This information is intended to be stored in the Postgresql Database server attached
# to the manager, which will require tables to be defined and created for each of the
# above.

from celery.app import shared_task
from celery.utils.log import get_task_logger

from aica_django.connectors.AicaMongo import AicaMongo
from aica_django.converters.Knowledge import (
    netflow_to_knowledge,
    nmap_scan_to_knowledge,
    suricata_alert_to_knowledge,
    knowledge_to_neo,
)

logger = get_task_logger(__name__)


def query_action(alert_dict):
    print(f"Running {__name__}: query_action")
    mongo_client = AicaMongo()
    mongo_db = mongo_client.get_db_handle()

    recommended_actions = []
    if alert_dict["event_type"] == "alert":
        query = {
            "$and": [
                {"event_type": "alert"},
                {
                    "$or": [
                        {"signature_id": alert_dict["alert"]["signature_id"]},
                        {"signature_id": "*"},
                    ]
                },
            ]
        }
        recommended_actions = mongo_db["alert_response_actions"].find(query)

    return recommended_actions


@shared_task(name="ma-knowledge_base-record_netflow")
def record_netflow(flow_dict):
    logger.info(f"Running {__name__}: record_netflow")
    nodes, relations = netflow_to_knowledge(flow_dict)
    knowledge_to_neo(nodes=nodes, relations=relations)


@shared_task(name="ma-knowledge_base-record_nmap_scan")
def record_nmap_scan(scan_dict):
    logger.info(f"Running {__name__}: record_nmap_scan")
    nodes, relations = nmap_scan_to_knowledge(scan_dict)
    knowledge_to_neo(nodes=nodes, relations=relations)


@shared_task(name="ma-knowledge_base-record_suricata_alert")
def record_suricata_alert(alert_dict):
    logger.info(f"Running {__name__}: record_alert")
    nodes, relations = suricata_alert_to_knowledge(alert_dict)
    knowledge_to_neo(nodes=nodes, relations=relations)
