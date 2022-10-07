import datetime
import logging
import re
import requests
import time

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger

from aica_django.connectors.Graylog import Graylog

logger = get_task_logger(__name__)

nginx_regex = (
    r"(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - "
    r"\[(?P<dateandtime>\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} "
    r"(\+|\-)\d{4})\] ((\"(?P<method>(GET|POST)) )(?P<url>.+)"
    r"(HTTP\/1\.1\")) (?P<statuscode>\d{3}) (?P<bytes_sent>\d+) "
    r"(\"(?P<referer>(\-)|(.+))\") (\"(?P<useragent>[^\"]+)\")"
)


@shared_task(name="poll-nginx-accesslogs")
def poll_nginx_accesslogs(frequency=30):
    logger.info(f"Running {__name__}: poll_nginx_accesslogs")
    matcher = re.compile(nginx_regex)

    gl = Graylog("nginx")

    while True:
        to_time = datetime.datetime.now()
        from_time = to_time - datetime.timedelta(seconds=frequency)

        query_params = {
            "query": r"nginx\: AND HTTP",  # Required
            "from": from_time.strftime("%Y-%m-%d %H:%M:%S"),  # Required
            "to": to_time.strftime("%Y-%m-%d %H:%M:%S"),  # Required
            "fields": ["message"],  # Required
            "limit": 150,  # Optional: Default limit is 150 in Graylog
        }

        response = gl.query(query_params)

        try:
            response.raise_for_status()
            if response.json()["total_results"] > 0:
                for message in response.json()["messages"]:
                    event = message["message"]["message"]
                    event = re.sub(r"^\S+ nginx: ", "", event)
                    log_dict = matcher.match(event)
                    if log_dict:
                        current_app.send_task(
                            "ma-knowledge_base-record_nginx_accesslog",
                            [log_dict.groupdict()],
                        )
        except requests.exceptions.HTTPError as e:
            logging.error(f"{e}\n{response.text}")

        execution_time = (to_time - datetime.datetime.now()).total_seconds()
        time.sleep(frequency - execution_time)
