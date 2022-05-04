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

import nmap3

from aica_django.converters.Knowledge import (  # noqa: F401
    nmap_scan_to_knowledge,
    knowledge_to_neo,
)
from celery.app import shared_task
from celery.utils.log import get_task_logger
from hashlib import sha256

logger = get_task_logger(__name__)


@shared_task(name="ma-online_learning-network_scan")
def network_scan(nmap_target, nmap_args="-O -Pn --osscan-limit --host-timeout=60"):
    hasher = sha256()
    hasher.update(nmap_target.encode("utf-8"))
    host_hash = hasher.hexdigest()
    with open(f"/var/lock/aica-nmap-scan-{host_hash}", "w") as lockfile:
        try:
            fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            logging.warning(
                "Couldn't obtain lock to run nmap scan of target, "
                "existing scan in-progress?"
            )
            return False

    nmap = nmap3.Nmap()
    return nmap.scan_top_ports(nmap_target, args=nmap_args)
