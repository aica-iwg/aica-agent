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
import pyshark  # type: ignore
import random

from celery.app import shared_task
from celery.utils.log import get_task_logger
from typing import Any, Optional

from aica_django.microagents.knowledge_base import record_dnp3


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
        destination_dict[destination_key] = None

    return destination_dict


@shared_task(name="replay_dnp3_pcap")
def replay_dnp3_pcap(
    pcap_file: str, sample: Optional[float] = None, sample_min: Optional[int] = None
) -> None:
    with pyshark.FileCapture(
        input_file=pcap_file, display_filter="dnp3", keep_packets=False
    ) as cap:
        packets = [packet for packet in cap]

        # If sample would be fewer than our minimum specified
        override_sample = sample_min and len(packets) * sample < sample_min

        for packet in cap:
            if sample is None or override_sample or random.random() <= sample:
                packet_dict = parse_dnp3_packet(packet, filename=pcap_file)
                record_dnp3.apply_async(
                    kwargs={"log_entry": packet_dict},
                    queue="pcap_record",
                )


@shared_task(name="capture_dnp3")
def capture_dnp3(interface: str) -> None:
    cap = pyshark.LiveRingCapture(interface=interface, bpf_filter="dnp3")
    cap.sniff(timeout=50)
    for packet in cap.sniff_continuously(packet_count=5):
        packet_dict = parse_dnp3_packet(packet)
        record_dnp3.apply_async(
            kwargs={"log_entry": packet_dict},
            queue="pcap_record",
        )


def parse_dnp3_packet(
    packet: pyshark.packet.packet.Packet,
    filename: Optional[str] = None,
) -> dict[str, str]:
    # See also:
    # https://www.wireshark.org/docs/dfref/d/dnp3.html
    # https://cdn.chipkin.com/assets/uploads/imports/resources/DNP3QuickReference.pdf
    # https://research-repository.griffith.edu.au/bitstream/handle/10072/392608/Foo229955-Accepted.pdf?sequence=2

    return_dict = dict()

    # Non-DNP3 context
    return_dict["sniff_timestamp"] = getattr(packet, "sniff_timestamp", None)
    return_dict["src_mac"] = getattr(packet.eth, "src", None)
    return_dict["dst_mac"] = getattr(packet.eth, "dst", None)
    return_dict["src_ip"] = getattr(packet.ip, "src_host", None)
    return_dict["dst_ip"] = getattr(packet.ip, "dst_host", None)
    return_dict["src_port"] = getattr(packet.tcp, "srcport", None)
    return_dict["dst_port"] = getattr(packet.tcp, "dstport", None)

    # DNP3 Datalink Header
    return_dict["dnp3_datalink_from_master"] = getattr(packet.dnp3, "ctl_dir", None)
    return_dict["dnp3_datalink_from_primary"] = getattr(packet.dnp3, "ctl_prm", None)
    if packet.dnp3.ctl_prm:
        return_dict["dnp3_datalink_function"] = getattr(
            packet.dnp3, "ctl_prifunc", None
        )
    else:
        return_dict["dnp3_datalink_function"] = getattr(
            packet.dnp3, "ctl_secfunc", None
        )

    # Note: there may be multiple DNP3 dsts/srcs per IP!
    return_dict["dnp3_datalink_dst"] = getattr(packet.dnp3, "dst", None)
    return_dict["dnp3_datalink_src"] = getattr(packet.dnp3, "src", None)

    # DNP3 Application Header
    return_dict = object_try_get(
        packet, return_dict, "dnp3.al_uns", "dnp3_application_unsolicited_from_slave"
    )
    return_dict = object_try_get(
        packet, return_dict, "dnp3.al_func", "dnp3_application_function"
    )
    return_dict = object_try_get(
        packet, return_dict, "dnp3.al_iin", "dnp3_application_iin"
    )
    return_dict = object_try_get(
        packet, return_dict, "dnp3.al_obj", "dnp3_application_obj"
    )
    return_dict = object_try_get(
        packet, return_dict, "dnp3.al_objq_code", "dnp3_application_objq_code"
    )
    return_dict = object_try_get(
        packet, return_dict, "dnp3.al_objq_index", "dnp3_application_objq_index"
    )
    return_dict = object_try_get(
        packet, return_dict, "dnp3.al_objq_prefix", "dnp3_application_objq_prefix"
    )
    return_dict = object_try_get(
        packet, return_dict, "dnp3.al_objq_range", "dnp3_application_objq_range"
    )

    if filename:
        return_dict["pcap_file"] = filename

    # TODO: Determine the best way to incorporate object values into this without making the node IDs too volatile

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
            replay_dnp3_pcap(pcap_file)
