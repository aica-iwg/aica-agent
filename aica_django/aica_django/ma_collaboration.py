# This microagent is responsible for coordinating external inputs and outputs such
# as communication with other agents, command and control, or human operators. As
# such, the input tasks here will likely consist of either polling of shared
# database tables, or tasks called by Django REST endpoints. Outputs are likely to
# be called by the decision making engine microagent.

import os
import json
import subprocess

from paramiko import SSHClient, AutoAddPolicy
from celery.decorators import task
from celery.execute import send_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@task(name="ma_collaboration-poll_dbs")
def poll_dbs():
    logger.info(f"Running {__name__}: poll_dbs")
    mode = os.getenv("MODE")

    # For now this is polling a file for demonstration purposes, can be extended later
    if mode == "sim" or mode == "emu":
        file_path = "/var/log/suricata/eve.json"
        f = subprocess.Popen(
            ["tail", "-F", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        while True:
            line = f.stdout.readline()
            event_dict = json.loads(line)
            if event_dict["event_type"] == "alert":
                send_task("ma_decision_making_engine-handle_alert", [event_dict])
            else:
                logger.debug("Non-alert event ignored")
    elif mode == "virt":
        # TODO: Insert polling code for external DB in virtual environment
        raise NotImplementedError("Virtualized mode has not yet been implemented")
    else:
        raise ValueError(f"Illegal mode value: {mode}")


@task(name="ma_collaboration-redirect_to_honeypot_iptables")
def redirect_to_honeypot_iptables(attacker, target, timeout=300):
    mode = os.getenv("MODE")
    logger.info(f"Running {__name__}: redirect_to_honeypot_iptables")

    if mode == "emu":
        client = SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(target, username="root")

        command = f"ipset add honeypot [{attacker}] timeout {timeout}"
        logger.debug(f"Sending command: {command}")

        # The following line has nosec as we've validated the input parameters above
        stdin, stdout, stderr = client.exec_command(command)  # nosec

        output = stdout.readlines()
        output = "".join(output)
        logger.info(output)

        output = stderr.readlines()
        output = "".join(output)
        logger.error(output)

        client.close()
    elif mode == "sim":
        # This is a rather crude mechanism, but we can afford it, because
        # in the prototype demonstration, everything is sequential
        file_path = "/var/log/suricata/response.json"
        f = open(file_path, "w")
        f.write("honeypot")
        f.close()
        logger.info("Honeypot redirect request to simulation written.")
