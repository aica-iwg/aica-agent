"""
This module contains all code relevant to interacting with antivirus agents.

Functions:
    poll_antivirus_alerts: Periodically queries Graylog for A/V-related alerts of interest.
    parse_clamav_alert: Extracts fields from a ClamAV "FOUND" alert.
"""

import datetime
import ipaddress
import json
import logging
import re2 as re  # type: ignore
import requests
import time

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger
from typing import Any, Dict, List, Union

from aica_django.connectors.SIEM import SIEM

logger = get_task_logger(__name__)


clam_parser = re.compile(
    r"^(\S+)\s+clamav\: ([^-]+) -> ([^:]+): ([^-]+)-([^-]+)-([^(]+)\(([a-f0-9]+):(\d+)\) FOUND"
)


# ClamAV logs are not in json, so we need to format them into something like that
def parse_clamav_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract fields from ClamAV "FOUND" alert into a dictionary.

    @param message: The log event to parse
    @type message: str
    @return: The extracted fields as a dictionary
    @rtype: dict or bool
    @raise: ValueError: if the FOUND message cannot be parsed
    """
    alert_dict: Dict[str, Any] = dict()

    try:
        ipaddress.ip_address(alert["source_ip"])
    except ValueError:
        raise ValueError("Invalid IP address given for antivirus alert")

    if "FOUND" in alert["message"]:
        alert_dict["event_type"] = "alert"

        alert_dict["source_ip"] = alert["source_ip"]
        matcher = clam_parser.fullmatch(alert["message"])
        if matcher is None:
            raise ValueError("Invalid ClamAV line encountered")

        alert_dict["hostname"] = matcher.group(1)
        alert_dict["date"] = matcher.group(2)
        alert_dict["path"] = matcher.group(3)
        alert_dict["platform"] = matcher.group(4)
        alert_dict["category"] = matcher.group(5)
        alert_dict["name"] = matcher.group(6)
        alert_dict["signature"] = matcher.group(7)
        alert_dict["revision"] = matcher.group(8)

        return alert_dict

    else:
        raise ValueError("Invalid ClamAV line encountered")


@shared_task(name="poll-antivirus-alerts")
def poll_clamav_alerts(frequency: int = 30, single: bool = False) -> None:
    """
    Periodically query Graylog for ClamAV "FOUND" alerts, and add to the knowledge graph.

    @param frequency: How often to query Graylog (default, 30 seconds)
    @type frequency: int
    @param single: Run a single poll only, without looping
    @type single: bool
    """

    logger.info(f"Running {__name__}: poll_dbs")

    siem = SIEM()

    while True:
        to_time = int(datetime.datetime.now().timestamp())
        from_time = to_time - frequency

        query_str = r"clamav\: FOUND"  # Required
        response = siem.query_siem(
            queries={"_all": query_str},
            from_timestamp=from_time,
            to_timestamp=to_time,
        )

        try:
            response.raise_for_status()
            if response.json()["total_results"] > 0:
                for message in response.json()["hits"]["hits"]:
                    message = json.loads(message["_source"]["event"]["original"])
                    event = {
                        "message": message["message"]["message"],
                        "source_ip": message["message"]["gl2_remote_ip"],
                    }
                    alert_dict = parse_clamav_alert(event)
                    if alert_dict:
                        alert_dict = json.loads(json.dumps(alert_dict))
                        current_app.send_task(
                            "ma-knowledge_base-record_antivirus_alert",
                            [alert_dict],
                        )
                        current_app.send_task(
                            "ma-decision_making_engine-handle_antivirus_alert",
                            [alert_dict],
                        )
        except requests.exceptions.HTTPError as e:
            logging.error(f"{e}\n{response.text}")

        if single:
            break

        execution_time = to_time - int(datetime.datetime.now().timestamp())
        time.sleep(frequency - execution_time)
