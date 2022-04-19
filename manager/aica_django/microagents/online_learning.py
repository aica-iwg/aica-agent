# This microagent is responsible for pulling in any external data relevant to decision-
# making by the agent and loading/sending it to the knowledge base microagent during
# runtime. Per the NCIA SOW this is to include the following information:
#
# * World Description
# * Competence
# * Purpose
# * Behavior
#
# It is scheduled to run on a periodic basis via the main celery app.

import fcntl
import logging

from connectors.AicaNeo4j import AicaNeo4j
from celery.app import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(name="ma-online-learning-load")
def load():
    # TODO
    print(f"Running {__name__}: load")


@shared_task(name="ma-online_learning-nmap-to-stix")
def nmap_to_stix(nmap_target, **nmap_args):
    with open("/var/lock/aica-nmap-scan", "rw") as lockfile:
        try:
            fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            logging.warning(
                "Couldn't obtain lock to run nmap scan, existing scan in-progress?"
            )
            return False

    graph_conn = AicaNeo4j()  # noqa: F841 (Temp until used)

    return None
