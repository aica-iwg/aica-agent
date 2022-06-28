import os
import json
import re
import subprocess
import vt

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger
from dotenv import dotenv_values

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
    try:
        VT_API_KEY = dotenv_values(".env.secret")["VT_API_KEY"]
        client = vt.Client(VT_API_KEY)
        file = client.get_object(f"/files/{md5}")
        conf = malicious_confidence(file.last_analysis_results)
        return conf, file.last_analysis_results
    except Exception:
        return "Not Available", None


# ClamAV logs are not in json, so we'll need to format them into something like that
def parse_line(line):
    event_dict = {}
    line = line.decode('utf-8')
    if "FOUND" in line:
        md5sum = re.search(r"\([^:]*", line).group(0).strip().replace("(", "")
        info = line.split("->")[1].strip().split(": ")
        event_dict["event_type"] = "alert"
        event_dict["date"] = re.search(r"^[^->]*", line).group(0).strip()
        event_dict["path"] = info[0].strip()
        event_dict["sig"] = re.search(r"^[^\(]*", info[1]).group(0).strip()
        event_dict["md5sum"] = md5sum
        vt_crit, report = get_vt_report(md5sum)

        event_dict["vt_crit"] = vt_crit

    else:
        event_dict["event_type"] = "non-alert"
        event_dict["date"] = re.search(r"^[^->]*", line).group(0).strip()
        event_dict["info"] = line.split("->")[1].strip().split(": ")

    return event_dict


@shared_task(name="poll-antivirus-alerts")
def poll_antivirus_alerts():
    logger.info(f"Running {__name__}: poll_dbs")
    mode = os.getenv("MODE")

    # For now this is polling a file for demonstration purposes, can be extended later
    if mode == "sim" or mode == "emu":
        file_path = "/var/log/clamav/clamd.log"
        f = subprocess.Popen(
            ["tail", "-F", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        # Current janky solution to try and get the ip address from the target
        # TODO: Make this better
        try:
            with open('/var/log/clamav/hostinfo.txt', 'r') as filp:
                ip_address, hostname = filp.read().strip().split(',')
        except FileNotFoundError:
            ip_address, hostname = "Error"

        while True:
            line = f.stdout.readline()
            event_dict = parse_line(line)
            event_dict['ip_addr'], event_dict['hostname'] = ip_address, hostname
            event_dict = json.loads(json.dumps(event_dict))
            if event_dict["event_type"] == "alert":
                current_app.send_task(
                    "ma-knowledge_base-record_antivirus_alert",
                    [event_dict],
                )
                current_app.send_task(
                    "ma-decision_making_engine-handle_antivirus_alert",
                    [event_dict],
                )
            else:
                logger.debug("Non-alert event ignored")
    elif mode == "virt":
        # TODO: Insert polling code for external DB in virtual environment
        raise NotImplementedError("Virtualized mode has not yet been implemented")
    else:
        raise ValueError(f"Illegal mode value: {mode}")
