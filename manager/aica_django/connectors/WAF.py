"""
This module contains all code relevant to interacting with Nginx daemons.

Functions:
    poll_coraza_alerts: Periodically queries Graylog for WAF-related alerts of interest.
"""

import datetime
import logging
import re2 as re
import requests
import time
import json

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger
from typing import Dict, List, Union

from aica_django.connectors.SIEM import Graylog

logger = get_task_logger(__name__)


def parse_coraza_alert(
    event_dict: dict[str, Union[str, List[str]]]
) -> dict[str, Union[str, List[str]]]:
    msg = str(event_dict["msg"])
    bracket_data = re.findall(r"\[(.*?)\]", msg)

    tags = []
    for val in bracket_data:
        split = val.split(" ")
        key, value = split[0], "".join(split[1:]).strip()
        if key == "tag" and value != '"OWASP_CRS"':
            tags.append(value.replace('"', ""))
        else:
            event_dict[key] = value.replace('"', "")

    event_dict["tags"] = tags
    return event_dict


@shared_task(name="poll-waf-alerts")
def poll_waf_alerts(frequency: int = 30) -> None:
    """
    Periodically query Graylog for Coraza waf allerts, and insert into the knowledge graph.

    @param frequency: How often to query graylog (default 30 seconds)
    @type frequency:  int
    """

    logger.info(f"Running {__name__}: poll_waf_alerts")

    gl = Graylog("coraza")

    while True:
        to_time = datetime.datetime.now()
        from_time = to_time - datetime.timedelta(seconds=frequency)

        query_params: Dict[str, Union[str, int, List[str]]] = {
            "query": r"coraza\: AND http.handlers.waf",  # Required
            "from": from_time.strftime("%Y-%m-%d %H:%M:%S"),  # Required
            "to": to_time.strftime("%Y-%m-%d %H:%M:%S"),  # Required
            "fields": ["message"],  # Required
            "limit": 150,  # Optional: Default limit is 150 in Graylog
        }

        response = gl.query_graylog(query_params)

        try:
            response.raise_for_status()
            if response.json()["total_results"] > 0:
                for message in response.json()["messages"]:
                    event = message["message"]["message"]
                    event = re.sub(r"^\S+ coraza: ", "", event)

                    log_dict = json.loads(event)
                    log_dict = parse_coraza_alert(log_dict)
                    if log_dict and log_dict.get("logger", None) == "http.handlers.waf":
                        current_app.send_task(
                            "ma-knowledge_base-record_waf_alert",
                            [log_dict],
                        )
        except requests.exceptions.HTTPError as e:
            logging.error(f"{e}\n{response.text}")

        execution_time = (to_time - datetime.datetime.now()).total_seconds()
        time.sleep(frequency - execution_time)
