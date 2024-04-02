"""
This module contains all code relevant to interacting with DNP3 traffic/commands 

Functions:
    replay_pcap: Tell pyshark to parse a PCAP file and handle any DNP3 traffic it finds
    capture_dnp3: Tell pyshark to capture live on a network interface and handle any dnp3 traffic it finds
    parse_dnp3_packet: Handle a DNP3 packet and send to the knowledge base
    send_dnp3_command: (Not yet implemented) Send a DNP3 command to the network
"""

import argparse
import functools
import glob
import hashlib
import json
import pyshark  # type: ignore

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger
from typing import Any


logger = get_task_logger(__name__)


# Thanks: https://stackoverflow.com/a/31174427
def rgetattr(obj: object, attr: str) -> object:
    def _getattr(obj: object, attr: object) -> object:
        return getattr(obj, str(attr))

    return functools.reduce(_getattr, [obj] + attr.split("."))


def object_try_get(
    source_obj: dict[str, Any],
    destination_dict: dict[str, Any],
    source_attr: str,
    destination_key: str,
) -> dict[str, Any]:
    try:
        destination_dict[destination_key] = rgetattr(source_obj, source_attr)
    except AttributeError:
        pass

    return destination_dict


@shared_task(name="replay_dnp3_pcap")
def replay_pcap(pcap_file: str, send_task: bool = True) -> None:
    with pyshark.FileCapture(pcap_file, display_filter="dnp3") as cap:
        for packet in cap:
            packet_dict = parse_dnp3_packet(packet)
            if send_task:
                current_app.send_task(
                    "ma-knowledge_base-record_dnp3",
                    [packet_dict],
                )
            else:
                print(packet_dict)


@shared_task(name="capture_dnp3")
def capture_dnp3(interface: str) -> None:
    cap = pyshark.LiveRingCapture(interface=interface, display_filter="dnp3")
    cap.sniff(timeout=50)
    for packet in cap.sniff_continuously(packet_count=5):
        packet_dict = parse_dnp3_packet(packet)
        current_app.send_task(
            "ma-knowledge_base-record_dnp3",
            [packet_dict],
        )


def parse_dnp3_packet(packet: pyshark.packet.packet.Packet) -> dict[str, str]:
    # See also:
    # https://www.wireshark.org/docs/dfref/d/dnp3.html
    # https://cdn.chipkin.com/assets/uploads/imports/resources/DNP3QuickReference.pdf
    # https://research-repository.griffith.edu.au/bitstream/handle/10072/392608/Foo229955-Accepted.pdf?sequence=2

    return_dict = dict()

    # Non-DNP3 context
    return_dict["sniff_timestamp"] = packet.sniff_timestamp
    return_dict["ip_src"] = packet.ip.src_host
    return_dict["ip_dst"] = packet.ip.dst_host
    return_dict["tcp_src"] = packet.tcp.srcport
    return_dict["tcp_dst"] = packet.tcp.dstport

    # DNP3 Datalink Header
    dnp3_dict = dict()
    dnp3_dict["dnp3_datalink_from_master"] = packet.dnp3.ctl_dir
    dnp3_dict["dnp3_datalink_from_primary"] = packet.dnp3.ctl_prm
    if packet.dnp3.ctl_prm:
        dnp3_dict["dnp3_datalink_function"] = packet.dnp3.ctl_prifunc
    else:
        dnp3_dict["dnp3_datalink_function"] = packet.dnp3.ctl_secfunc

    dnp3_dict["dnp3_datalink_dst"] = (
        packet.dnp3.dst
    )  # Note: there may be multiple DNP3 dsts/srcs per IP!
    dnp3_dict["dnp3_datalink_src"] = packet.dnp3.src

    # DNP3 Application Header
    dnp3_dict = object_try_get(
        packet, dnp3_dict, "dnp3.al_uns", "dnp3_application_unsolicited_from_slave"
    )
    dnp3_dict = object_try_get(
        packet, dnp3_dict, "dnp3.al_func", "dnp3_application_function"
    )
    dnp3_dict = object_try_get(packet, dnp3_dict, "dnp3.al_iin", "dnp3_application_iin")
    dnp3_dict = object_try_get(packet, dnp3_dict, "dnp3.al_obj", "dnp3_application_obj")
    dnp3_dict = object_try_get(
        packet, dnp3_dict, "dnp3.al_objq_code", "dnp3_application_objq_code"
    )
    dnp3_dict = object_try_get(
        packet, dnp3_dict, "dnp3.al_objq_index", "dnp3_application_objq_index"
    )
    dnp3_dict = object_try_get(
        packet, dnp3_dict, "dnp3.al_objq_prefix", "dnp3_application_objq_prefix"
    )
    dnp3_dict = object_try_get(
        packet, dnp3_dict, "dnp3.al_objq_range", "dnp3_application_objq_range"
    )

    # TODO: Determine the best way to incorporate object values into this without making the fingerprints too volatile

    # Create a global identifier to represent the "type" of this message
    fingerprint = hashlib.sha1(
        json.dumps(dnp3_dict).encode("utf-8"), usedforsecurity=False
    ).hexdigest()
    return_dict["dnp3_fingerprint"] = fingerprint

    return return_dict


@shared_task(name="send_dnp3_command")
def send_dnp3_command() -> None:
    raise NotImplementedError


# For testing and inspection of DNP3 PCAPs
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f", "--pcap-file", dest="pcap_file", nargs="+", type=str, required=True
    )
    args = parser.parse_args()

    for pcap_file_expr in args.pcap_file:
        for pcap_file in glob.glob(pcap_file_expr):
            replay_pcap(pcap_file, send_task=False)
