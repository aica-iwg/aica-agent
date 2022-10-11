import datetime
import json
import logging
import os
import re
import requests
import time
import vt  # type: ignore

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger
from typing import Tuple, NamedTuple, Dict, Any

from aica_django.connectors.Graylog import Graylog

logger = get_task_logger(__name__)


clam_parser = re.compile(
    r"^(\S+)\s+clamav\:([^-]+) -> ([^:]+): ([^(]+)\(([a-f0-9]+):\d+\) FOUND"
)


class VTTuple(NamedTuple):
    popular_threat_classification: dict
    ssdeep: str


def malicious_confidence(vt_results: dict) -> float:
    """Determine malicious confidence from a VT API Report"""
    # Credit: HuskyHacks and mttaggart
    # (https://github.com/mttaggart/blue-jupyter/blob/main/utils/malware.py)
    try:
        dispositions = [r["result"] for r in vt_results.values()]
        malicious = list(filter(lambda d: d is not None, dispositions))
        return round(len(malicious) / len(dispositions) * 100, 2)
    except KeyError:
        return 0


def get_vt_report(md5: str) -> Tuple[float, VTTuple]:
    vt_api_key = os.getenv("VT_API_KEY")
    if not vt_api_key:
        logging.error(
            "Missing VT_API_KEY environment variable, not able to lookup VirusTotal information"
        )
        return -1, VTTuple(popular_threat_classification={}, ssdeep="")
    else:
        client = vt.Client(vt_api_key)
        file = client.get_object(f"/files/{md5}")
        conf = malicious_confidence(file.last_analysis_results)

        return conf, file


# ClamAV logs are not in json, so we need to format them into something like that
def parse_line(line: str) -> dict:
    event_dict: Dict[str, Any] = dict()

    if "FOUND" in line:
        event_dict["event_type"] = "alert"
        matcher = clam_parser.fullmatch(line)
        assert matcher is not None

        event_dict["hostname"] = matcher.group(1)
        event_dict["date"] = matcher.group(2)
        event_dict["path"] = matcher.group(3)
        event_dict["sig"] = matcher.group(4)
        event_dict["md5sum"] = matcher.group(5)

        # Processing VirusTotal info
        vt_crit, report = get_vt_report(event_dict["md5sum"])
        event_dict["vt_crit"] = vt_crit
        if vt_crit >= 0:
            event_dict["vt_sig"] = report.popular_threat_classification[
                "suggested_threat_label"
            ]
            event_dict["ssdeep"] = report.ssdeep
        else:
            event_dict["vt_sig"] = ""
            event_dict["ssdeep"] = ""

        return event_dict

    else:
        return {}


@shared_task(name="poll-antivirus-alerts")
def poll_antivirus_alerts(frequency: int = 30) -> None:
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
