"""
This module contains any code necessary to perform attacker redirection to Honeypot(s).

Functions:
    redirect_to_honeypot_iptables: Uses SSH to add attacker IP to an IPset list that will be redirected.
"""

import ipaddress
import os

from paramiko import SSHClient, AutoAddPolicy
from paramiko.ssh_exception import NoValidConnectionsError
from celery.app import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(name="redirect_to_honeypot_iptables")
def redirect_to_honeypot_iptables(
    attacker: str, target: str, timeout: int = 300
) -> bool:
    """
    Uses SSH to add attacker IP to an IPset list that will be redirected.

    @param attacker: The attack from which traffic should be redirected. Valid IP address.
    @type attacker: str
    @param target: The target that should redirect traffic, must be appropriately configured. Valid IP address.
    @type target: str
    @param timeout: How long the attacker should persist on the blocklist (default 300s, 5m)
    @type timeout: int
    @return: True once complete
    @rtype: bool
    @raise: NoValidConnectionsError: if the connection cannot be completed to the target
    @raise: ValueError: if attacker or target IP are invalid
    """

    mode = os.getenv("MODE")
    logger.info(f"Running {__name__}: redirect_to_honeypot_iptables")

    try:
        ipaddress.ip_address(attacker)
    except ValueError:
        raise ValueError(f"Invalid IP for attacker: {attacker}")

    try:
        ipaddress.ip_address(target)
    except ValueError:
        raise ValueError(f"Invalid IP for target: {attacker}")

    if mode == "emu":
        command = f"ipset add honeypot [{attacker}] timeout {timeout}"

        client = SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(AutoAddPolicy())
        try:
            client.connect(target, username="root")
            logger.debug(f"Sending command: {command}")
            # The following line has nosec as we've validated the input parameters above
            stdin, stdout, stderr = client.exec_command(command)  # nosec

            output = "".join(stdout.readlines())
            logger.info(output)

            output = "".join(stderr.readlines())
            logger.error(output)

            output = "".join(stderr.readlines())
            logger.error(output)
        except NoValidConnectionsError:
            logger.warning(
                f"Couldn't connect to {target} to redirect attacker to honeypot"
            )

    return True
