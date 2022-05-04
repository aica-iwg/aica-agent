import os

from paramiko import SSHClient, AutoAddPolicy
from celery.app import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(name="redirect_to_honeypot_iptables")
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
