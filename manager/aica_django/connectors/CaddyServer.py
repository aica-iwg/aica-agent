"""
This module contains all code relevant to interacting with Nginx daemons.

Functions:
    poll_caddy_accesslogs: Periodically queries Graylog for Nginx-related access log entries.
"""

import datetime
import logging
import re
import requests
import time
import json

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger
from typing import Dict, List, Union

from aica_django.connectors.SIEM import Graylog

logger = get_task_logger(__name__)


@shared_task(name="poll-caddy-accesslogs")
def poll_caddy_accesslogs(frequency: int = 30) -> None:
    """
    Periodically query Graylog for Caddy accesslogs, and insert into the knowledge graph.

    @param frequency: How often to query graylog (default 30 seconds)
    @type frequency:  int
    """

    logger.info(f"Running {__name__}: poll_caddy_accesslogs")
    # matcher = re.compile(nginx_regex)

    gl = Graylog("caddy")

    while True:
        to_time = datetime.datetime.now()
        from_time = to_time - datetime.timedelta(seconds=frequency)

        query_params: Dict[str, Union[str, int, List[str]]] = {
            "query": r"(caddy\: AND http) OR (caddy\: AND OWASP_CRS)",  # Required
            "from": from_time.strftime("%Y-%m-%d %H:%M:%S"),  # Required
            "to": to_time.strftime("%Y-%m-%d %H:%M:%S"),  # Required
            "fields": ["message"],  # Required
            "limit": 150,  # Optional: Default limit is 150 in Graylog
        }

        response = gl.query_graylog(query_params)

        """
            TODO: See if it's possible to send data from Caddy's access.log
            and Coraza's audit.log together to represent one request, instead
            of having to manage two Graylog entries per HTTP request. This will
            make everything else way cleaner. (the key is getting the unique id
            from the audit log into the access log, don't know how to do this)
            

            The current solution is to assume the graylog entries are going to come
            back chronologically and in pairs, we're risking a lot of timing-based issues
            here, but it's way easier.
        """
        try:
            response.raise_for_status()
            if response.json()["total_results"] > 0:
                # group requests into pairs
                msg_pairs = [
                    response.json()["messages"][i : i + 2]
                    for i in range(0, len(response.json()["messages"]), 2)
                ]
                for message in msg_pairs:
                    # parse the graylog entry for both the access.log and audit.log events
                    event1, event2 = (
                        message[0]["message"]["message"],
                        message[1]["message"]["message"],
                    )
                    event1, event2 = [
                        re.sub(r"^\S+ caddy: ", "", event) for event in [event1, event2]
                    ]

                    # load both entries as json objects
                    event1_dict, event2_dict = json.loads(event1), json.loads(event2)
                    # check if the first event is the access and the second is audit
                    if (
                        event1_dict.get("logger", "") == "http.log.access.log0"
                        and event2_dict.get("transaction", None) is not None
                    ):
                        log_dict = event1_dict
                        log_dict["unique_id"] = event2_dict["transaction"]["id"]
                    # in the case that vice versa is true
                    elif (
                        event2_dict.get("logger", "") == "http.log.access.log0"
                        and event1_dict.get("transaction", None) is not None
                    ):
                        log_dict = event2_dict
                        log_dict["unique_id"] = event1_dict["transaction"]["id"]
                    # otherwise just drop the request
                    else:
                        log_dict = None

                    if log_dict:
                        current_app.send_task(
                            "ma-knowledge_base-record_caddy_accesslog",
                            [log_dict],
                        )
        except requests.exceptions.HTTPError as e:
            logging.error(f"{e}\n{response.text}")

        execution_time = (to_time - datetime.datetime.now()).total_seconds()
        time.sleep(frequency - execution_time)
