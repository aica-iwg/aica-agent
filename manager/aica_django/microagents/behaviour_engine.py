# This microagent is responsible for querying the knowledge base for relevant facts
# when invoked by the decision-making engine and returning any relevant parameters or
# limitations needed in determining a course of action.
#
# Per the NCIA SOW, this could include:
#
# * Stealth & Security
# * Self-control
# * Collaboration control

from celery.app import shared_task
from celery.utils.log import get_task_logger
from netifaces import interfaces, ifaddresses, AF_INET  # type: ignore

logger = get_task_logger(__name__)


def get_manager_ips() -> list:
    ip_list = []
    for interface in interfaces():
        if AF_INET not in ifaddresses(interface):
            continue
        for link in ifaddresses(interface)[AF_INET]:
            ip_list.append(link["addr"])
    return ip_list


@shared_task(name="ma-behavior_engine-query_rules")
def query_rules(alert_dict: dict, candidate_action: dict) -> str:
    print(f"Running {__name__}: query_rules")

    # TODO: This is stubbed out for initial demonstration purposes,
    #  eventually would query other MAs
    if (
        candidate_action["action"] == "honeypot"
        and alert_dict["event_type"] == "alert"
        and alert_dict["alert"]["severity"] >= 2
        and alert_dict["src_ip"] not in get_manager_ips()
    ):
        return "proceed"
    else:
        return "abort"
