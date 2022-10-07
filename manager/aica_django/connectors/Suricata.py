import datetime
import json
import logging
import re
import requests
import time

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger

from aica_django.connectors.Graylog import Graylog

logger = get_task_logger(__name__)


@shared_task(name="poll-suricata-alerts")
def poll_suricata_alerts(frequency=30):
    logger.info(f"Running {__name__}: poll_dbs")

    gl = Graylog("suricata")

    while True:
        to_time = datetime.datetime.now()
        from_time = to_time - datetime.timedelta(seconds=frequency)

        query_params = {
            "query": r"suricata\: AND event_type",  # Required
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
                    event = re.sub(r"^\S+ suricata: ", "", event, count=1)
                    event_dict = json.loads(event)
                    if event_dict["event_type"] == "alert":
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

        execution_time = (to_time - datetime.datetime.now()).total_seconds()
        time.sleep(frequency - execution_time)
