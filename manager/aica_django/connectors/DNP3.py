"""
This module contains all code relevant to interacting with DNP3 traffic/commands 

Functions:
    replay_pcap: Tell pyshark to parse a PCAP file and handle any DNP3 traffic it finds
    capture_dnp3: Tell pyshark to capture live on a network interface and handle any dnp3 traffic it finds
    parse_dnp3_packet: Handle a DNP3 packet and send to the knowledge base
    send_dnp3_command: (Not yet implemented) Send a DNP3 command to the network
"""

import pyshark  # type: ignore

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(name="replay_dnp3_pcap")
def replay_pcap(pcap_file: str) -> None:
    cap = pyshark.FileCapture(pcap_file, display_filter="dnp3")

    for packet in cap:
        packet_dict = parse_dnp3_packet(packet)
        if "al_func" not in packet_dict:
            logger.warning("Ignoring unknown DNP3 packet type")
        else:
            current_app.send_task(
                "ma-knowledge_base-record_dnp3",
                [packet_dict],
            )


@shared_task(name="capture_dnp3")
def capture_dnp3(interface: str) -> None:
    cap = pyshark.LiveRingCapture(interface=interface, display_filter="dnp3")
    cap.sniff(timeout=50)
    for packet in cap.sniff_continuously(packet_count=5):
        packet_dict = parse_dnp3_packet(packet)
        if "al_func" not in packet_dict:
            logger.warning("Ignoring unknown DNP3 packet type")
        else:
            current_app.send_task(
                "ma-knowledge_base-record_dnp3",
                [packet_dict],
            )


def parse_dnp3_packet(packet: pyshark.packet.packet.Packet) -> dict[str, str]:
    # See also: https://www.wireshark.org/docs/dfref/d/dnp3.html
    log_dict = {
        k: str(getattr(packet.dnp3, k))
        for k in dir(packet.dnp3)
        if k.startswith("al_iin_")
        or k.startswith("al_objq_")
        or k in ["src", "dst", "ctl_dir", "ctl_prm", "ctl_prifunc", "al_func", "al_uns"]
    }

    log_dict["sniff_timestamp"] = packet.sniff_timestamp
    log_dict["src_host"] = packet.ip.src_host
    log_dict["dst_host"] = packet.ip.dst_host
    log_dict["srcport"] = packet.tcp.srcport
    log_dict["dstport"] = packet.tcp.dstport


@shared_task(name="send_dnp3_command")
def send_dnp3_command() -> None:
    raise NotImplementedError
