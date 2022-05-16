import os
import json
import subprocess

from aica_django.microagents.knowledge_base import (  # noqa: F401
    record_suricata_alert,
)
from aica_django.microagents.decision_making_engine import (  # noqa: F401
    handle_suricata_alert,
)
from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(name="poll-suricata-alerts")
def poll_suricata_alerts():
    logger.info(f"Running {__name__}: poll_dbs")
    mode = os.getenv("MODE")

    # For now this is polling a file for demonstration purposes, can be extended later
    if mode == "sim" or mode == "emu":
        file_path = "/var/log/suricata/eve.json"
        f = subprocess.Popen(
            ["tail", "-F", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        while True:
            line = f.stdout.readline()
            event_dict = json.loads(line)
            if event_dict["event_type"] == "alert":
                current_app.send_task(
                    "ma-knowledge_base-record_suricata_alert",
                    [event_dict],
                )
                current_app.send_task(
                    "ma-decision_making_engine-handle_suricata_alert",
                    [event_dict],
                )
            else:
                logger.debug("Non-alert event ignored")
    elif mode == "virt":
        # TODO: Insert polling code for external DB in virtual environment
        raise NotImplementedError("Virtualized mode has not yet been implemented")
    else:
        raise ValueError(f"Illegal mode value: {mode}")
