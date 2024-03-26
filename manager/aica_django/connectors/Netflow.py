"""
This module contains all code relevant to capturing and parsing Netflow logs

Functions:
    network_flow_capture: Start a Netflow listener and handoff inbound flows as they arrive.
"""

import netflow  # type: ignore
import socket

from aica_django.microagents.knowledge_base import record_netflow
from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(name="network-flow-capture")
def network_flow_capture() -> None:
    """
    Start a listener for receiving and handling Netflow logs from remote senders.
    """

    logger.info(f"Running {__name__}: network_flow_capture")
    # Create listener for Netflow exports on port 2055
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 2055))
    while True:
        payload = sock.recv(4096)
        p = netflow.parse_packet(payload)
        offset = p.header.timestamp - p.header.uptime
        for flow in p.flows:
            data = flow.data
            data["FIRST_SWITCHED"] = data["FIRST_SWITCHED"] + offset
            data["LAST_SWITCHED"] = data["LAST_SWITCHED"] + offset
            record_netflow.apply_async(args=(data,))
