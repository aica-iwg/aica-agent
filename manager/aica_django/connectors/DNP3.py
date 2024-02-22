"""
This module contains all code relevant to interacting with DNP3 traffic/commands 

Functions:
    replay_pcap: Tell pyshark to parse a PCAP file and handle any DNP3 traffic it finds
    capture_dnp3: Tell pyshark to capture live on a network interface and handle any dnp3 traffic it finds
    parse_dnp3_packet: Handle a DNP3 packet and send to the knowledge base
    send_dnp3_command: (Not yet implemented) Send a DNP3 command to the network
"""

import pandas as pd
import pyshark  # type: ignore

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(name="replay_dnp3_pcap")
def replay_pcap(pcap_file: str) -> None:
    cap = pyshark.FileCapture(pcap_file, display_filter="dnp3")

    # Testing only
    packets = [parse_dnp3_packet(x) for x in cap]
    df = pd.DataFrame(packets)
    df.to_csv("packets.csv")

    for packet in cap:
        print(parse_dnp3_packet(packet))


@shared_task(name="capture_dnp3")
def capture_dnp3(interface: str) -> None:
    cap = pyshark.LiveRingCapture(interface=interface, display_filter="dnp3")
    cap.sniff(timeout=50)
    for packet in cap.sniff_continuously(packet_count=5):
        parse_dnp3_packet(packet)


def parse_dnp3_packet(packet: pyshark.packet.packet.Packet) -> dict[str, str]:
    # See also: https://www.wireshark.org/docs/dfref/d/dnp3.html
    log_dict: dict[str, str] = {}
    # IP src/dst address
    # DNP3 src/dst address (Only unique on serial link, need serial channel or IP to uniquely identify)
    # Master to Outstation associations
    # Event data...
    # Object groups: https://s3.wp.wsu.edu/uploads/sites/2217/2020/03/PEAC-2020-Fundamentals-DNP3-A-West.pdf
    return {
        k: str(getattr(packet.dnp3, k))
        for k in dir(packet.dnp3)
        if not k.startswith("_")
    }

    # Handle Commands

    # Handle Metrics

    # current_app.send_task(
    #     "ma-knowledge_base-record_dnp3",
    #     [log_dict],
    # )


@shared_task(name="send_dnp3_command")
def send_dnp3_command() -> None:
    raise NotImplementedError


# Testing, remove later

replay_pcap(
    "/Users/bblakely/Downloads/DNP3_Intrusion_Detection_Dataset_Final/20200514_DNP3_Disable_Unsolicited_Messages_Attack/DNP3 PCAP Files/20200514_DNP3_Disable_Unsolicited_Messages_Attack_UOWM_DNP3_Dataset_Slave_08.pcap"
)
