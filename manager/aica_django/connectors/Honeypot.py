import os

from paramiko import SSHClient, AutoAddPolicy
from paramiko.ssh_exception import NoValidConnectionsError
from celery.app import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(name="redirect_to_honeypot_iptables")
def redirect_to_honeypot_iptables(
    attacker: str, target: str, timeout: int = 300
) -> None:
    mode = os.getenv("MODE")
    logger.info(f"Running {__name__}: redirect_to_honeypot_iptables")

    if mode == "emu":
        client = SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(AutoAddPolicy())
        try:
            client.connect(target, username="root")
        except NoValidConnectionsError:
            logger.warning(
                f"Couldn't connect to {target} to redirect attacker to honeypot"
            )

        command = f"ipset add honeypot [{attacker}] timeout {timeout}"
        logger.debug(f"Sending command: {command}")

        # The following line has nosec as we've validated the input parameters above
        stdin, stdout, stderr = client.exec_command(command)  # nosec

        output = "".join(stdout.readlines())
        logger.info(output)

        output = "".join(stderr.readlines())
        logger.error(output)

        client.close()
