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
from collections import OrderedDict
from stix2.base import _Extension
from stix2.properties import StringProperty
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
        destination_dict[destination_key] = None

    return destination_dict


@shared_task(name="replay_dnp3_pcap")
def replay_dnp3_pcap(pcap_file: str) -> None:
    with pyshark.FileCapture(pcap_file, display_filter="dnp3") as cap:
        for packet in cap:
            packet_dict = parse_dnp3_packet(packet)
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
    return_dict["src_mac"] = packet.eth.src
    return_dict["dst_mac"] = packet.eth.dst
    return_dict["src_ip"] = packet.ip.src_host
    return_dict["dst_ip"] = packet.ip.dst_host
    return_dict["src_port"] = packet.tcp.srcport
    return_dict["dst_port"] = packet.tcp.dstport

    # DNP3 Datalink Header
    return_dict["dnp3_datalink_from_master"] = packet.dnp3.ctl_dir
    return_dict["dnp3_datalink_from_primary"] = packet.dnp3.ctl_prm
    if packet.dnp3.ctl_prm:
        return_dict["dnp3_datalink_function"] = packet.dnp3.ctl_prifunc
    else:
        return_dict["dnp3_datalink_function"] = packet.dnp3.ctl_secfunc

    # Note: there may be multiple DNP3 dsts/srcs per IP!
    return_dict["dnp3_datalink_dst"] = packet.dnp3.dst
    return_dict["dnp3_datalink_src"] = packet.dnp3.src

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
            replay_dnp3_pcap(pcap_file, send_task=False)


class DNP3RequestExt(_Extension):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part4-cyber-observable-objects/stix-v2.0-cs01-part4-cyber-observable-objects.html#_Toc496716262>`__.
    """  # noqa

    _type = "dnp3-request-ext"
    _properties = OrderedDict(
        [
            ("dnp3_datalink_src", StringProperty(required=True)),
            ("dnp3_datalink_dst", StringProperty(required=True)),
            ("dnp3_application_unsolicited_from_slave", StringProperty(required=True)),
            ("dnp3_datalink_from_master", StringProperty(required=True)),
            ("dnp3_datalink_from_primary", StringProperty(required=True)),
            ("dnp3_datalink_function", StringProperty(required=True)),
            ("dnp3_application_function", StringProperty(required=False)),
            ("dnp3_application_iin", StringProperty(required=False)),
            ("dnp3_application_obj", StringProperty(required=False)),
            ("dnp3_application_objq_code", StringProperty(required=False)),
            ("dnp3_application_objq_index", StringProperty(required=False)),
            ("dnp3_application_objq_prefix", StringProperty(required=False)),
            ("dnp3_application_objq_range", StringProperty(required=False)),
        ]
    )
