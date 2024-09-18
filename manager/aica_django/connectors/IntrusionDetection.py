"""
This module contains all code relevant to interacting with Suricata IDS deployments.

Functions:
    poll_suricata_alerts: Periodically queries Graylog for IDS-related alerts of interest.
"""

import datetime
import json
import logging
import re2 as re  # type: ignore
import requests
import time

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger
from typing import Dict, List, Union

from aica_django.connectors.SIEM import SIEM

logger = get_task_logger(__name__)


@shared_task(name="poll-suricata-alerts")
def poll_suricata_alerts(frequency: int = 30) -> None:
    """
    Periodically query Graylog for Suricata alerts and add to Knowledge Graph.

    @param frequency: How often to query for alerts
    @type frequency: int
    """

    logger.info(f"Running {__name__}: poll_dbs")

    siem = SIEM()

    while True:
        to_time = int(datetime.datetime.now().timestamp())
        from_time = to_time - frequency

        response = siem.query_siem(
            queries={"type": "SuricataIDS", "event_type": "alert"},
            antiqueries={
                "alert.category": "Not Suspicious Traffic",
                "alert.category": "Misc activity",
            },
            from_timestamp=from_time,
            to_timestamp=to_time,
        )

        try:
            response.raise_for_status()
            for message in response.json()["hits"]["hits"]:
                event_dict = message["_source"]
                current_app.send_task(
                    "ma-knowledge_base-record_suricata_alert",
                    [event_dict],
                )
                current_app.send_task(
                    "ma-decision_making_engine-handle_suricata_alert",
                    [event_dict],
                )
        except requests.exceptions.HTTPError as e:
            logging.error(f"{e}\n{response.text}")

        execution_time = to_time - int(datetime.datetime.now().timestamp())
        time.sleep(frequency - execution_time)
