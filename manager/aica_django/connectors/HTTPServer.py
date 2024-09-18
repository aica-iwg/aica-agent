"""
This module contains all code relevant to interacting with Nginx daemons.

Functions:
    poll_nginx_accesslogs: Periodically queries SIEM for Nginx-related access log entries.
"""

import datetime
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

nginx_regex = (
    r"(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - "
    r"\[(?P<dateandtime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} "
    r"(\+|\-)\d{4})\] ((\"(?P<method>(GET|POST)) )(?P<url>.+)"
    r"(HTTP\/1\.1\")) (?P<status>\d{3}) (?P<bytes_sent>\d+) "
    r"(\"(?P<referer>(\-)|(.+))\") (\"(?P<useragent>[^\"]+)\")"
)


@shared_task(name="poll-nginx-accesslogs")
def poll_nginx_accesslogs(frequency: int = 30) -> None:
    """
    Periodically query SIEM for Nginx accesslogs, and insert into the knowledge graph.

    @param frequency: How often to query SIEM (default 30 seconds)
    @type frequency:  int
    """

    logger.info(f"Running {__name__}: poll_nginx_accesslogs")
    matcher = re.compile(nginx_regex)

    siem = SIEM()

    while True:
        to_time = int(datetime.datetime.now().timestamp())
        from_time = to_time - frequency
        query_str = r"nginx\: HTTP"

        response = siem.query_siem(
            queries={"_all": query_str},
            from_timestamp=from_time,
            to_timestamp=to_time,
        )

        try:
            response.raise_for_status()
            for message in response.json()["hits"]["hits"]:
                event = message["_source"]["event"]["original"]
                event = re.sub(r"^\S+ nginx: ", "", event)
                match = matcher.match(event)
                if match:
                    log_dict = match.groupdict()
                    log_dict["server_ip"] = message["_all"]["gl2_remote_ip"]
                    current_app.send_task(
                        "ma-knowledge_base-record_nginx_accesslog",
                        [log_dict],
                    )
        except requests.exceptions.HTTPError as e:
            logging.error(f"{e}\n{response.text}")

        execution_time = to_time - int(datetime.datetime.now().timestamp())
        time.sleep(frequency - execution_time)
