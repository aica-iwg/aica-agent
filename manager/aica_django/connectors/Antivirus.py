import datetime
import json
import logging
import os
import re
import requests
import time
import vt

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger

from aica_django.connectors.Graylog import Graylog

logger = get_task_logger(__name__)


def malicious_confidence(vt_results):
    """Determine malicious confidence from a VT API Report"""
    # Credit: HuskyHacks and mttaggart
    # (https://github.com/mttaggart/blue-jupyter/blob/main/utils/malware.py)
    try:
        dispositions = [r["result"] for r in vt_results.values()]
        malicious = list(filter(lambda d: d is not None, dispositions))
        return round(len(malicious) / len(dispositions) * 100, 2)
    except KeyError:
        return None


def get_vt_report(md5: str):
    vt_api_key = os.getenv("VT_API_KEY")
    if not vt_api_key:
        logging.error(
            "Missing VT_API_KEY environment variable, not able to lookup VirusTotal information"
        )
        return "Not Available", None
    else:
        client = vt.Client(vt_api_key)
        file = client.get_object(f"/files/{md5}")
        conf = malicious_confidence(file.last_analysis_results)

        return conf, file


# ClamAV logs are not in json, so we'll need to format them into something like that
def parse_line(line):
    event_dict = {}

    if "FOUND" in line:
        event_dict["hostname"] = re.search(r"^\S+", line).group(0).strip()
        md5sum = re.search(r"(([a-f0-9]{32}))(?=:)", line).group(0).strip()
        info = line.split("->")[1].strip().split(": ")
        event_dict["event_type"] = "alert"
        event_dict["date"] = re.search(r"^[^->]*", line).group(0).strip()
        event_dict["path"] = info[0].strip()
        event_dict["sig"] = re.search(r"^[^\(]*", info[1]).group(0).strip()
        event_dict["md5sum"] = md5sum

        # Processing VirusTotal info
        vt_crit, report = get_vt_report(md5sum)
        event_dict["vt_crit"] = vt_crit
        if report:
            event_dict["vt_sig"] = report.popular_threat_classification[
                "suggested_threat_label"
            ]
            event_dict["ssdeep"] = report.ssdeep
        else:
            event_dict["vt_sig"] = None
            event_dict["ssdeep"] = None

        return event_dict

    else:
        return None


@shared_task(name="poll-antivirus-alerts")
def poll_antivirus_alerts(frequency=30):
    logger.info(f"Running {__name__}: poll_dbs")

    gl = Graylog("antivirus")

    while True:
        to_time = datetime.datetime.now()
        from_time = to_time - datetime.timedelta(seconds=frequency)

        query_params = {
            "query": r"clamav\: AND FOUND",  # Required
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
                    alert_dict = parse_line(event)
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

        execution_time = (to_time - datetime.datetime.now()).total_seconds()
        time.sleep(frequency - execution_time)
