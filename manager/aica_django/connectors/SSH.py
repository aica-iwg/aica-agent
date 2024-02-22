"""
This module contains any code necessary to perform attacker redirection to Honeypot(s).

Functions:
    redirect_to_honeypot_iptables: Uses SSH to add attacker IP to an IPset list that will be redirected.
"""

import ipaddress
import os
import socket
from typing import Tuple

from paramiko import SSHClient, AutoAddPolicy
from paramiko.ssh_exception import NoValidConnectionsError
from celery.app import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def send_ssh_command(target: str, command: str) -> Tuple[int, str, str]:
    """
    Sends a single SSH command to a target and collects output

    @param target:
    @type target:
    @param command:
    @type command:
    @return: The return value, stdout, and stderr output resulting from the executed command
    @rtype: (int, str, str)
    @raise: NoValidConnectionsError: if cannot connect to the specified target
    """
    client = SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(AutoAddPolicy())  # nosec

    client.connect(target, username="root")
    logger.debug(f"Sending command: {command}")

    _, stdout, stderr = client.exec_command(command)  # nosec
    retval = stdout.channel.recv_exit_status()

    return retval, "".join(stdout.readlines()), "".join(stderr.readlines())


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
        try:
            ip_resolutions = [str(x[4][0]) for x in socket.getaddrinfo(target, 0)]
            target = ip_resolutions[0]
        except socket.gaierror:
            raise ValueError(f"Invalid IP/hostname for target: {target}")

    if mode == "emu":
        command = f"ipset add honeypot [{attacker}] timeout {timeout}"
        try:
            retval, _, stderr = send_ssh_command(target, command)
            if retval:
                logger.error(stderr)
                return False
        except NoValidConnectionsError as e:
            logger.warning(f"Unable to complete SSH command: {e}")

    return True
