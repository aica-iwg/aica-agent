import netflow  # type: ignore
import socket

from aica_django.microagents.knowledge_base import record_netflow
from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(name="network-flow-capture")
def network_flow_capture() -> None:
    logger.info(f"Running {__name__}: network_flow_capture")
    # Create listener for Netflow exports on port 2055
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 2055))
    while True:
        payload = sock.recv(4096)
        p = netflow.parse_packet(payload)
        flow_data = [flow.data for flow in p.flows]
        for flow in flow_data:
            record_netflow.apply_async(args=tuple(flow))
