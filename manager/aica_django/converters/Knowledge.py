"""
This module defines objects representing nodes and relations in the Knowledge graph, and functions for
handling them (e.g., parsing/converting).

Classes:
    KnowledgeNode: Base/generic class for representing a knowledge object
    KnowledgeRelation: Base/generic class for representing a knowledge relationship
    Host: A physical/virtual system, potentially with multiple addresses
    IPv4Address: The IPv4 address corresponding to a host, potentially with listening ports (NetworkEndpoints)
    IPv6Address: The IPv6 address corresponding to a host, potentially with listening ports (NetworkEndpoints)
    NetworkEndpoint: A listening or transmitting NetworkPort tied to a specific address
    NetworkPort: A global representation a network port and associated attributes
    NetworkTraffic: A record of a transmission over the network

Functions:
    antivirus_alert_to_knowledge: Converts an alert from the antivirus system to KnowledgeNodes/Relations
    netflow_to_knowledge: Converts a network flow record to KnowledgeNodes/Relations
    nginx_accesslog_to_knowledge: Converts an HTTP access log entry to KnowledgeNodes/Relations
    nmap_scan_to_knowledge: Converts a network scan result to KnowledgeNodes/Relations
    suricata_alert_to_knowledge: Converts an alert from the IDS to KnowledgeNodes/Relations
    knowledge_to_neo: Stores lists of KnowledgeNodes and KnowledgeRelations in the knowledge graph database
    normalize_mac_addr: Converts MAC address to standard lowercase hex value without separators
    dissect_time: Converts a timestamp value into a dictionary of time attributes potential relevant for classification

"""

import dateparser
import datetime
import ipaddress
import logging
import os
import pytz
import re
import socket
import uuid

from typing import Any, Dict, List, Optional, Tuple, Union

from aica_django.connectors.GraphDatabase import (
    AicaNeo4j,
    defined_node_labels,
    defined_relation_labels,
)
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def dissect_time(timestamp: Union[int, float], prefix: str = "") -> Dict[str, Any]:
    """
    Converts a timestamp into a dictionary of timestamp attributes potentially relevant
    for classification.

    @param timestamp: The timestamp to "dissect"
    @type timestamp: float
    @param prefix: A prefix to use for dictionary keys, if desired
    @type prefix: str
    @return: Dictionary of attributes related to this timestamp
    @rtype: dict
    """

    dt_utc = datetime.datetime.utcfromtimestamp(timestamp)
    dt_americas = dt_utc.astimezone(pytz.timezone("America/Chicago"))
    dt_europeafrica = dt_utc.astimezone(pytz.timezone("Europe/Berlin"))
    dt_asiaoceana = dt_utc.astimezone(pytz.timezone("Asia/Shanghai"))
    time_details = {
        "second_of_minute": dt_utc.second,
        "minute_of_hour": dt_utc.minute,
        "hour_of_day": dt_utc.hour,
        "day_of_week": dt_utc.weekday(),
        "day_of_month": dt_utc.day,
        "week_of_month": dt_utc.isocalendar()[1]
        - dt_utc.replace(day=1).isocalendar()[1]
        + 1,
        "week_of_year": dt_utc.isocalendar()[1],
        "month_of_year": dt_utc.month,
        "year": dt_utc.year,
        # These are only meant to be rough proxies
        "workhours_americas": (dt_americas.weekday() < 5)
        and (6 < dt_americas.hour < 21),
        "workhours_euraf": (dt_europeafrica.weekday() < 5)
        and (5 < dt_europeafrica.hour < 19),
        "workhours_asoce": (dt_asiaoceana.weekday() < 5)
        and (5 < dt_asiaoceana.hour < 21),
    }
    if prefix != "":
        time_details = {f"{prefix}_{key}": value for key, value in time_details.items()}

    return time_details


class KnowledgeNode:
    """
    Represents an arbitrary knowledge object, intended mainly for sub-classing
    """

    def __init__(
        self, label: str, name: str, values: Union[None, Dict[str, Any]] = None
    ):
        """
        Initialize a new KnowledgeNode object.

        @param label: The type of node, of the types specified in aica_django.connectors.GraphDatabase
        @type label: str
        @param name: A human-readable name for this node
        @type name: str
        @param values: Any metadata values that should be stored with this node
        @type values: dict
        @raise ValueError: If an unsupported node label or invalid name is provided.
        """

        if label not in defined_node_labels:
            raise ValueError(f"Unsupported node label {label} for {name}")

        if name == "":
            raise ValueError(f"Name must be non-empty")

        self.values = values if values else {}
        if label == "MACAddress":
            name = normalize_mac_addr(name)
            self.values["value"] = name

        self.label = label
        self.name = name


class NetworkPort(KnowledgeNode):
    """
    Represents a global reference for an IP port that may contain additional metadata useful
    for classification.
    """

    def __init__(
        self,
        port: int,
        protocol: Union[int, str],
        values: Union[None, Dict[str, Any]] = None,
    ):
        """
        Initialize this NetworkPort object

        @param port: The port number (0-65535)
        @type port: int
        @param protocol: The protocol name or numerical representation (e.g., TCP or 6)
        @type protocol: Union[int, str]
        @param values: Any metadata values that should be stored with this node
        @type values: dict
        @raise: ValueError: if the specific port or protocol numbers are out of bounds
        """

        self.label = "NetworkPort"

        if 0 <= port < 65535:
            self.port = port
        else:
            raise ValueError("Invalid port number")

        if type(protocol) == int:
            if 0 <= protocol < 256:
                self.protocol = protocol
            else:
                raise ValueError("Invalid protocol number")
        else:
            assert type(protocol) == str
            try:
                proto_num = socket.getprotobyname(protocol)
                self.protocol = proto_num
            except OSError:
                raise ValueError("Invalid protocol name")

        self.name = f"{self.port}/{self.protocol}"
        self.values = values if values else {}
        super().__init__(self.label, self.name, values=self.values)

    def to_knowledge_node(self) -> KnowledgeNode:
        """
        Convert this NetworkPort object to a KnowledgeNode representation.

        @return: KnowledgeNode version of this object.
        @rtype: KnowledgeNode
        """

        values = self.values
        values["port"] = self.port
        values["protocol"] = self.protocol
        values["privileged"] = self.port < 1024
        return KnowledgeNode(
            label=self.label,
            name=self.name,
            values=values,
        )


class NetworkEndpoint(KnowledgeNode):
    """
    Represents a specific reference to a communicating IP port on a host (source or destination).
    """

    def __init__(
        self,
        ip_address: str,
        port: int,
        protocol: Union[str, int],
        endpoint: str = "",
        values: Union[None, Dict[str, Any]] = None,
    ):
        """
        Initialize this NetworkEndpoint object.

        @param ip_address: The string representation of the IP address associated with this port
        @type ip_address: str
        @param port: The port number (0-65535)
        @type port: int
        @param protocol: The protocol name or numerical representation (e.g., TCP or 6)
        @type protocol: Union[int, str]
        @param endpoint: Whether this endpoint is the source ("src") or destination ("dst") of the flow
        @type endpoint: str
        @param values: Any metadata values that should be stored with this node
        @type values: dict
        @raise: ValueError: if the specific port or protocol numbers are out of bounds
        """
        self.label = "NetworkEndpoint"

        try:
            self.ip_addr = ipaddress.ip_address(ip_address)
            self.ip_address = ip_address
        except ValueError:
            raise ValueError("Provided IP address was not a valid IPv4 or IPv6 address")

        if 0 <= port < 65535:
            self.port = port
        else:
            raise ValueError("Invalid port number")

        if type(protocol) == int:
            if 0 <= protocol < 256:
                self.protocol = protocol
            else:
                raise ValueError("Invalid protocol number")
        else:
            assert type(protocol) == str
            try:
                proto_num = socket.getprotobyname(protocol)
                self.protocol = proto_num
            except OSError:
                raise ValueError("Invalid protocol name")

        self.endpoint = endpoint if endpoint in ["src", "dst"] else None

        self.name = f"{self.ip_address}:{self.port}/{self.protocol}"
        self.values = values if values else {}
        super().__init__(self.label, self.name, values=self.values)

    def to_network_port_ref(self) -> NetworkPort:
        """
        Convert to genericized NetworkPort reference (remove specific Host/IP info)
        @return: Generic NetworkPort object
        @rtype: NetworkPort
        """

        return NetworkPort(self.port, self.protocol, values=self.values)

    def to_knowledge_node(self) -> KnowledgeNode:
        """
        Convert this NetworkEndpoint object to a KnowledgeNode representation.

        @return: KnowledgeNode version of this object.
        @rtype: KnowledgeNode
        """

        values = self.values
        values["port"] = self.port
        values["protocol"] = self.protocol
        values["ip_address"] = self.ip_address
        values["endpoint"] = self.endpoint

        return KnowledgeNode(
            label=self.label,
            name=self.name,
            values=values,
        )


class IPv4Address(KnowledgeNode):
    """
    Represents an IPv4 address
    """

    def __init__(self, ip_addr: str, values: Union[None, Dict[str, Any]] = None):
        """
        Initialize this IPv4Address object

        @param ip_addr: A string representation (dotted quad) of this IP
        @type ip_addr: str
        @param values: Any metadata values that should be stored with this relationship
        @type values: dict
        """

        self.label = "IPv4Address"

        try:
            socket.inet_pton(socket.AF_INET, ip_addr)
        except socket.error:
            logging.error(f"Invalid IPv4 Address: {ip_addr}")
        self.ip_addr = ipaddress.ip_address(ip_addr)
        self.name = ip_addr

        self.values = values if values else {}
        super().__init__(self.label, self.name, values=self.values)

    def to_knowledge_node(self) -> KnowledgeNode:
        """
        Convert this IPv4Address object to a KnowledgeNode representation.

        @return: KnowledgeNode version of this object.
        @rtype: KnowledgeNode
        """

        values = self.values
        values["address"] = str(self.ip_addr)
        values["is_private"] = self.ip_addr.is_private
        values["reserved"] = self.ip_addr.is_reserved
        values["multicast"] = self.ip_addr.is_multicast
        values["loopback"] = self.ip_addr.is_loopback
        # Hex to discourage use as continuous value
        int_value = int(self.ip_addr)
        values["int_value"] = hex(int_value)
        values["class_a"] = str(ipaddress.ip_address(int_value & 0xFF000000))
        values["class_b"] = str(ipaddress.ip_address(int_value & 0xFFFF0000))
        values["class_c"] = str(ipaddress.ip_address(int_value & 0xFFFFFF00))

        return KnowledgeNode(
            label=self.label,
            name=self.name,
            values=values,
        )


class IPv6Address(KnowledgeNode):
    """
    Represents an IPv6 address
    """

    def __init__(self, ip_addr: str, values: Union[None, Dict[str, Any]] = None):
        """
        Initialize this IPv6Address object

        @param ip_addr: A string representation (colon-separated) of this IP
        @type ip_addr: str
        @param values: Any metadata values that should be stored with this relationship
        @type values: dict
        """

        self.label = "IPv6Address"

        try:
            socket.inet_pton(socket.AF_INET6, ip_addr)
        except socket.error:
            logging.error(f"Invalid IPv6 Address: {ip_addr}")
        self.ip_addr = ipaddress.ip_address(ip_addr)
        self.name = ip_addr

        self.values = values if values else {}
        super().__init__(self.label, self.name, values=self.values)

    def to_knowledge_node(self) -> KnowledgeNode:
        """
        Convert this IPv6Address object to a KnowledgeNode representation.

        @return: KnowledgeNode version of this object.
        @rtype: KnowledgeNode
        """

        values = self.values
        values["address"] = str(self.ip_addr)
        values["is_private"] = self.ip_addr.is_private
        values["reserved"] = self.ip_addr.is_reserved
        values["multicast"] = self.ip_addr.is_multicast
        values["loopback"] = self.ip_addr.is_loopback
        values["link_local"] = self.ip_addr.is_link_local
        # Hex to discourage use as continuous value
        int_value = int(self.ip_addr)
        values["int_value"] = hex(int_value)
        values["class_16"] = hex(int_value & 0xFFFF0000000000000000000000000000)
        values["class_32"] = hex(int_value & 0xFFFFFFFF000000000000000000000000)
        values["class_48"] = hex(int_value & 0xFFFFFFFFFFFF00000000000000000000)
        values["class_56"] = hex(int_value & 0xFFFFFFFFFFFFFF000000000000000000)
        values["class_64"] = hex(int_value & 0xFFFFFFFFFFFFFFFF0000000000000000)

        return KnowledgeNode(
            label=self.label,
            name=self.name,
            values=values,
        )


class NetworkTraffic(KnowledgeNode):
    """
    Represents a specific network communication observed on the network
    """

    def __init__(
        self,
        in_packets: int,
        in_octets: int,
        start_ts: float,
        end_ts: float = 0,
        flags: int = 0,
        tos: int = 0,
        values: Union[None, Dict[str, Any]] = None,
    ):
        """
        Initialize this NetworkTraffic object.

        @param in_packets: Number of ingress packets, per Netflow
        @type in_packets: int
        @param in_octets: Number of ingress bytes, per Netflow
        @type in_octets: int
        @param start_ts: Start timestamp for flow
        @type start_ts: float
        @param end_ts: End timestamp for flow, defaults to "0"
        @type end_ts: float
        @param flags: Integer representation of flags field, per Netflow
        @type flags: int
        @param tos: Integer representation of TOS field, per Netflow
        @type tos: int
        @param values: Any metadata values that should be stored with this relationship
        @type values: dict
        @raises: ValueError: if the provided flags or tos values are invalid
        """

        self.label = "NetworkTraffic"
        self.in_packets = in_packets
        self.in_octets = in_octets
        self.start = start_ts
        self.end = end_ts if end_ts else None

        if 0 <= flags < 513:
            self.tcp_flags_fin = bool(flags & 0x1)
            self.tcp_flags_syn = bool(flags & 0x2)
            self.tcp_flags_rst = bool(flags & 0x4)
            self.tcp_flags_psh = bool(flags & 0x8)
            self.tcp_flags_ack = bool(flags & 0x16)
            self.tcp_flags_urg = bool(flags & 0x32)
            self.tcp_flags_ece = bool(flags & 0x64)
            self.tcp_flags_cwr = bool(flags & 0x128)
            self.tcp_flags_ns = bool(flags & 0x256)
        else:
            raise ValueError(f"Invalid flags value specified: {flags}")

        if 0 <= tos < 256:
            # Hex to discourage use as continuous value
            self.tos = hex(tos)
        else:
            raise ValueError(f"Invalid TOS/DSCP value specified: {tos}")

        self.values = values if values else {}
        self.name = str(uuid.uuid4())
        super().__init__(self.label, self.name, values=self.values)

    def to_knowledge_node(self) -> KnowledgeNode:
        """
        Convert this NetworkTraffic object to a KnowledgeNode representation.

        @return: KnowledgeNode version of this object.
        @rtype: KnowledgeNode
        """

        return KnowledgeNode(
            label="NetworkTraffic",
            name=self.name,
            values={
                "in_packets": self.in_packets,
                "in_octets": self.in_octets,
                "start": self.start,
                "end": self.end,
                "tcp_flags_fin": self.tcp_flags_fin,
                "tcp_flags_syn": self.tcp_flags_syn,
                "tcp_flags_rst": self.tcp_flags_rst,
                "tcp_flags_psh": self.tcp_flags_psh,
                "tcp_flags_ack": self.tcp_flags_ack,
                "tcp_flags_urg": self.tcp_flags_urg,
                "tcp_flags_ece": self.tcp_flags_ece,
                "tcp_flags_cwr": self.tcp_flags_cwr,
                "tcp_flags_ns": self.tcp_flags_ns,
                "tos": self.tos,
            },
        )


class Host(KnowledgeNode):
    """
    Represents a specific (physical/virtual) system, potentially with multiple IP addresses.
    """

    def __init__(
        self,
        identifier: str,
        last_seen: float,
        values: Union[None, Dict[str, Any]] = None,
    ):
        """
        Initialize this Host object.

        @param identifier: A unique identifier for this host.
        @type identifier: str
        @param last_seen: A timestamp value for the last time this host was observed.
        @type last_seen: float
        @param values: Any metadata values that should be stored with this relationship
        @type values: dict
        """
        self.label = "Host"
        self.name = identifier
        self.values = values if values else {}
        self.values["last_seen"] = last_seen
        super().__init__(self.label, self.name, values=self.values)

    def to_knowledge_node(self) -> KnowledgeNode:
        """
        Convert this Host object to a KnowledgeNode representation.

        @return: KnowledgeNode version of this object.
        @rtype: KnowledgeNode
        """

        return KnowledgeNode(
            label=self.label,
            name=self.name,
            values=self.values,
        )


class KnowledgeRelation:
    """
    Represents an arbitrary knowledge relationship object, intended mainly for sub-classing
    """

    def __init__(
        self,
        label: str,
        source_node: KnowledgeNode,
        target_node: KnowledgeNode,
        values: Union[None, Dict[str, Any]] = None,
    ):
        """
        Initialize this knowledge relation

        @param label: The type of relation, of the types specified in aica_django.connectors.GraphDatabase
        @type label: str
        @param source_node: The originating point for this relationship
        @type source_node: KnowledgeNode
        @param target_node: The terminating point for this relationship
        @type target_node: KnowledgeNode
        @param values: Any metadata values that should be stored with this relationship
        @type values: dict
        """

        if label not in defined_relation_labels:
            raise ValueError(
                f"Unsupported relation label {label} from {source_node}->{target_node}"
            )

        if not (isinstance(source_node, KnowledgeNode)):
            raise ValueError(
                f"Source node must be a KnowledgeNode, not {type(source_node)}"
            )
        if not (isinstance(target_node, KnowledgeNode)):
            raise ValueError(
                f"Target node must be a KnowledgeNode, not {type(target_node)}"
            )

        self.label = label
        self.source_node = source_node.name
        self.source_label = source_node.label
        self.target_node = target_node.name
        self.target_label = target_node.label
        self.values = values if values else {}


def normalize_mac_addr(mac_addr: str) -> str:
    """

    @param mac_addr: A MAC address string to be normalized
    @type mac_addr: str
    @return: A normalized (lowercase, hex, no separators) representation of the provided MAC address
    @rtype: str
    @raise: ValueError: MAC address does not parse to normalized form
    """

    normed_mac = re.sub(r"[^A-Fa-f\d]", "", mac_addr).lower()
    if len(normed_mac) != 12:
        raise ValueError("Invalid MAC Address Provided")

    return normed_mac


def netflow_to_knowledge(
    flow: Dict[str, str]
) -> Tuple[List[KnowledgeNode], List[KnowledgeRelation]]:
    """
    Converts a netflow dictionary (from the Python netflow library) to knowledge objects.

    @param flow: A netflow dictionary to be converted to knowledge objects
    @type flow: Dict[str, str]
    @return: Knowledge nodes and relations resulting form this conversion
    @rtype: Tuple[list, list]
    """

    knowledge_nodes = []
    knowledge_relations = []

    # Create source host and port nodes (and link to protocol node)
    if "IPV4_SRC_ADDR" in flow and flow["IPV4_SRC_ADDR"] is not None:
        ip_src_addr = str(ipaddress.ip_address(flow["IPV4_SRC_ADDR"]))
        source_addr = IPv4Address(ip_src_addr).to_knowledge_node()

        ip_dst_addr_obj = ipaddress.ip_address(flow["IPV4_DST_ADDR"])
        ip_dst_addr = str(ip_dst_addr_obj)
        dest_addr = IPv4Address(ip_dst_addr).to_knowledge_node()

    elif "IPV6_SRC_ADDR" in flow and flow["IPV6_SRC_ADDR"] is not None:
        ip_src_addr = str(ipaddress.ip_address(flow["IPV6_SRC_ADDR"]))
        source_addr = IPv6Address(ip_src_addr).to_knowledge_node()

        ip_dst_addr_obj = ipaddress.ip_address(flow["IPV6_DST_ADDR"])
        ip_dst_addr = str(ip_dst_addr_obj)
        dest_addr = IPv6Address(ip_dst_addr).to_knowledge_node()

    source_host = Host(ip_src_addr, last_seen=float(flow["LAST_SWITCHED"]))
    source_port = NetworkEndpoint(
        ip_src_addr, int(flow["SRC_PORT"]), flow["PROTO"], endpoint="src"
    )
    dest_port = NetworkEndpoint(
        ip_dst_addr, int(flow["DST_PORT"]), flow["PROTO"], endpoint="dst"
    )

    source_addr_knowledge = source_addr
    knowledge_nodes.append(source_addr_knowledge)

    source_port_ref = source_port.to_network_port_ref()
    source_port_knowledge = source_port.to_knowledge_node()
    source_port_ref_knowledge = source_port_ref.to_knowledge_node()

    knowledge_nodes.append(source_port_knowledge)
    knowledge_nodes.append(source_port_ref_knowledge)

    knowledge_relations.append(
        KnowledgeRelation(
            label="IS_TYPE",
            source_node=source_port_knowledge,
            target_node=source_port_ref_knowledge,
        )
    )
    knowledge_relations.append(
        KnowledgeRelation(
            label="HAS_PORT",
            source_node=source_addr_knowledge,
            target_node=source_port_knowledge,
        )
    )

    source_host_knowledge = source_host.to_knowledge_node()
    knowledge_nodes.append(source_host_knowledge)
    knowledge_relations.append(
        KnowledgeRelation(
            label="HAS_ADDRESS",
            source_node=source_host_knowledge,
            target_node=source_addr_knowledge,
        )
    )

    # Create destination host and port nodes (and link to protocol node)

    dest_addr_knowledge = dest_addr
    knowledge_nodes.append(dest_addr_knowledge)

    dest_port_ref = dest_port.to_network_port_ref()
    dest_port_knowledge = dest_port.to_knowledge_node()
    dest_port_ref_knowledge = dest_port_ref.to_knowledge_node()
    knowledge_nodes.append(dest_port_knowledge)
    knowledge_nodes.append(dest_port_ref_knowledge)

    knowledge_relations.append(
        KnowledgeRelation(
            label="IS_TYPE",
            source_node=dest_port_knowledge,
            target_node=dest_port_ref_knowledge,
        )
    )
    knowledge_relations.append(
        KnowledgeRelation(
            label="HAS_PORT",
            source_node=dest_addr_knowledge,
            target_node=dest_port_knowledge,
        )
    )

    if not (ip_dst_addr_obj.is_multicast or ip_dst_addr_obj.is_reserved):
        dest_host = Host(
            ip_dst_addr,
            last_seen=float(flow["LAST_SWITCHED"]),
        )
        dest_host_knowledge = dest_host.to_knowledge_node()
        knowledge_nodes.append(dest_host_knowledge)
        knowledge_relations.append(
            KnowledgeRelation(
                label="HAS_ADDRESS",
                source_node=dest_host_knowledge,
                target_node=dest_addr_knowledge,
            )
        )

    # Create NetworkTraffic node
    flow_knowledge = NetworkTraffic(
        int(flow["IN_PACKETS"]),
        int(flow["IN_OCTETS"]),
        int(flow["FIRST_SWITCHED"]),
        int(flow["LAST_SWITCHED"]),
        int(flow["TCP_FLAGS"]),
        int(flow["TOS"]),
        values={
            "source": "netflow",
        },
    ).to_knowledge_node()
    knowledge_nodes.append(flow_knowledge)
    knowledge_relations.append(
        KnowledgeRelation(
            label="COMMUNICATES_TO",
            source_node=source_port_knowledge,
            target_node=flow_knowledge,
        )
    )
    knowledge_relations.append(
        KnowledgeRelation(
            label="COMMUNICATES_TO",
            source_node=flow_knowledge,
            target_node=dest_port_knowledge,
        )
    )

    return knowledge_nodes, knowledge_relations


def nginx_accesslog_to_knowledge(
    log_dict: Dict[str, Any]
) -> Tuple[List[KnowledgeNode], List[KnowledgeRelation]]:
    """
    Converts an HTTP access log dictionary (as returned by aica_django.connectors.Nginx.poll_nginx_accesslogs)
    to knowledge objects.

    @param log_dict: An HTTP access log dictionary to be converted to knowledge objects
    @type log_dict: Dict[str, Any]
    @return: Knowledge nodes and relations resulting form this conversion
    @rtype: Tuple[list, list]
    """

    knowledge_nodes = []
    knowledge_relations = []

    # dateparser can't seem to handle this format
    request_time = datetime.datetime.strptime(
        log_dict["dateandtime"], "%d/%b/%Y:%H:%M:%S %z"
    )

    if not request_time:
        raise ValueError(f"Couldn't parse timestamp {log_dict['dateandtime']}")

    dissected_request_time = dissect_time(request_time.timestamp(), prefix="last_seen")
    target_ip = log_dict["server_ip"]

    server_ip_knowledge = None
    try:
        server_ipv4 = IPv4Address(target_ip)
        server_ipv4_knowledge = server_ipv4.to_knowledge_node()
        server_ip_knowledge = server_ipv4_knowledge
        knowledge_nodes.append(server_ipv4_knowledge)
    except:
        pass

    if not server_ip_knowledge:
        try:
            server_ipv6 = IPv6Address(target_ip)
            server_ipv6_knowledge = server_ipv6.to_knowledge_node()
            server_ip_knowledge = server_ipv6_knowledge
            knowledge_nodes.append(server_ipv6_knowledge)
        except:
            raise ValueError("Could not parse server IP address")

    # Add requesting host
    value_dict = dissected_request_time
    requesting_host = Host(
        log_dict["src_ip"],
        last_seen=request_time.timestamp(),
        values=value_dict,
    )

    requesting_host_knowledge = requesting_host.to_knowledge_node()
    knowledge_nodes.append(requesting_host_knowledge)

    if type(ipaddress.ip_address(log_dict["src_ip"])) is ipaddress.IPv4Address:
        src_ip_addr_knowledge = IPv4Address(log_dict["src_ip"]).to_knowledge_node()
    elif type(ipaddress.ip_address(log_dict["src_ip"])) is ipaddress.IPv6Address:
        src_ip_addr_knowledge = IPv6Address(log_dict["src_ip"]).to_knowledge_node()
    else:
        raise Exception(
            f"Unhandled address type: {type(ipaddress.ip_address(log_dict['src_ip'])) }"
        )

    knowledge_nodes.append(src_ip_addr_knowledge)
    knowledge_relations.append(
        KnowledgeRelation(
            label="HAS_ADDRESS",
            source_node=requesting_host_knowledge,
            target_node=src_ip_addr_knowledge,
        )
    )

    value_dict = dissected_request_time
    value_dict["request_time"] = request_time.timestamp()
    value_dict["method"] = log_dict["method"]
    value_dict["url"] = log_dict["url"]
    value_dict["response_status"] = log_dict["statuscode"]
    value_dict["bytes"] = log_dict["bytes_sent"]
    value_dict["referer"] = log_dict["referer"]
    value_dict["user_agent"] = log_dict["useragent"]

    http_request_knowledge = KnowledgeNode(
        label="HttpRequest",
        name=str(uuid.uuid4()),
        values=value_dict,
    )
    knowledge_nodes.append(http_request_knowledge)

    knowledge_relations.append(
        KnowledgeRelation(
            label="COMMUNICATES_TO",
            source_node=src_ip_addr_knowledge,
            target_node=http_request_knowledge,
        )
    )
    knowledge_relations.append(
        KnowledgeRelation(
            label="COMMUNICATES_TO",
            source_node=http_request_knowledge,
            target_node=server_ip_knowledge,
        )
    )

    return knowledge_nodes, knowledge_relations


def caddy_accesslog_to_knowledge(
    log_dict: Dict[str, Any]
) -> Tuple[List[KnowledgeNode], List[KnowledgeRelation]]:
    """
    Converts an HTTP access log dictionary (as returned by aica_django.connectors.CaddyServer.poll_caddy_accesslogs)
    to knowledge objects.

    @param log_dict: An HTTP access log dictionary to be converted to knowledge objects
    @type log_dict: Dict[str, Any]
    @return: Knowledge nodes and relations resulting form this conversion
    @rtype: Tuple[list, list]
    """

    knowledge_nodes = []
    knowledge_relations = []

    # dateparser can't seem to handle this format
    request_time = datetime.datetime.utcfromtimestamp(
        log_dict["ts"], "%d/%b/%Y:%H:%M:%S %z"
    )

    if not request_time:
        raise ValueError(f"Couldn't parse timestamp {log_dict['ts']}")
    else:
        dissected_request_time = dissect_time(
            request_time.timestamp(), prefix="last_seen"
        )

    request_timestamp = int(request_time.timestamp())
    my_hostname = socket.gethostname()
    try:
        my_ipv4 = IPv4Address(socket.gethostbyname(my_hostname))
        my_ipv4_knowledge = my_ipv4.to_knowledge_node()
        knowledge_nodes.append(my_ipv4_knowledge)
    except:
        pass

    try:
        my_ipv6 = IPv6Address(
            socket.getaddrinfo(my_hostname, None, socket.AF_INET6)[0][4][0]
        )
        my_ipv6_knowledge = my_ipv6.to_knowledge_node()
        knowledge_nodes.append(my_ipv6_knowledge)
    except:
        pass

    # Add requesting host
    value_dict = dissected_request_time
    requesting_host = Host(
        log_dict["request"]["remote_ip"],
        last_seen=request_timestamp,
        values=value_dict,
    )
    requesting_host_knowledge = requesting_host.to_knowledge_node()
    knowledge_nodes.append(requesting_host_knowledge)

    # Add target NIC to target host
    nic_knowledge = KnowledgeNode(
        label="NetworkInterface",
        name=str(
            uuid.uuid4()
        ),  # This results in hundreds of NIC's per host, does not make sense.
        values=value_dict,
    )
    knowledge_nodes.append(nic_knowledge)
    knowledge_relations.append(
        KnowledgeRelation(
            label="COMPONENT_OF",
            source_node=nic_knowledge,
            target_node=requesting_host_knowledge,
        )
    )

    if type(ipaddress.ip_address(log_dict["src_ip"])) is ipaddress.IPv4Address:
        ip_addr_knowledge = IPv4Address(log_dict["src_ip"]).to_knowledge_node()
    elif type(ipaddress.ip_address(log_dict["src_ip"])) is ipaddress.IPv6Address:
        ip_addr_knowledge = IPv6Address(log_dict["src_ip"]).to_knowledge_node()
    else:
        raise Exception(
            f"Unhandled address type: {type(ipaddress.ip_address(log_dict['src_ip'])) }"
        )

    knowledge_nodes.append(ip_addr_knowledge)
    knowledge_relations.append(
        KnowledgeRelation(
            label="HAS_ADDRESS",
            source_node=nic_knowledge,
            target_node=ip_addr_knowledge,
        )
    )

    value_dict = dissected_request_time
    value_dict["request_time"] = request_time
    value_dict["method"] = log_dict["request"]["method"]
    value_dict["url"] = log_dict["request"]["host"] + log_dict["uri"]
    value_dict["response_status"] = log_dict["status"]
    value_dict["bytes"] = log_dict["size"]
    try:
        value_dict["referer"] = log_dict["request"]["headers"]["Referer"]
    except KeyError:
        value_dict["referer"] = "null" # TODO: change this to better data

    try:
        value_dict["unique_id"] = log_dict["id"]
    except KeyError:
        value_dict["unique_id"] = "null" # TODO: change this to better data

    value_dict["user_agent"] = log_dict["request"]["headers"]["User-Agent"]

    http_request_knowledge = KnowledgeNode(
        label="HttpRequest",
        name=str(uuid.uuid4()),
        values=value_dict,
    )
    knowledge_nodes.append(http_request_knowledge)

    knowledge_relations.append(
        KnowledgeRelation(
            label="COMMUNICATES_TO",
            source_node=ip_addr_knowledge,
            target_node=http_request_knowledge,
        )
    )
    knowledge_relations.append(
        KnowledgeRelation(
            label="COMMUNICATES_TO",
            source_node=http_request_knowledge,
            target_node=ip_addr_knowledge,
        )
    )

    return knowledge_nodes, knowledge_relations

def nmap_scan_to_knowledge(
    scan_results: Dict[str, Any]
) -> Tuple[List[KnowledgeNode], List[KnowledgeRelation]]:
    """
    Converts an nmap scan result (from the Python nmap3 library) to knowledge objects.

    @param scan_results: A dictionary as returned by nmap3 to be converted to knowledge objects
    @type scan_results: Dict[str, str]
    @return: Knowledge nodes and relations resulting form this conversion
    @rtype: Tuple[list, list]
    """

    knowledge_nodes = []
    knowledge_relations = []

    assert "runtime" in scan_results

    scan_time: Optional[datetime.datetime] = dateparser.parse(
        scan_results["runtime"]["time"]
    )
    assert scan_time is not None

    # Not needed and make iteration below messy
    if "stats" in scan_results:
        del scan_results["stats"]

    if "runtime" in scan_results:
        del scan_results["runtime"]

    my_hostname = socket.gethostname()
    try:
        my_ipv4 = IPv4Address(socket.gethostbyname(my_hostname)).to_knowledge_node()
        knowledge_nodes.append(my_ipv4)
    except:
        pass
    try:
        my_ipv6 = IPv6Address(
            socket.getaddrinfo(my_hostname, None, socket.AF_INET6)[0][4][0]
        ).to_knowledge_node()
        knowledge_nodes.append(my_ipv6)
    except:
        pass

    for host, data in scan_results.items():
        if "task_results" in host:
            continue
        if "state" not in data:
            print("Knowledge.py state not found!", host, data)
        elif "state" not in scan_results[host]["state"]:
            print("Knowledge.py double state not found!", host, data)
        if (
            "state" in data
            and "state" in data["state"]
            and data["state"]["state"] != "up"
        ):
            continue

        # Add scan target
        target_host = Host(
            host,
            last_seen=scan_time.timestamp(),
            values={
                "state_reason": data["state"]["reason"],
                "state_reason_ttl": data["state"]["reason_ttl"],
            },
        )
        target_host_knowledge = target_host.to_knowledge_node()
        knowledge_nodes.append(target_host_knowledge)

        # Add target IPv4 to host
        if type(ipaddress.ip_address(host)) is ipaddress.IPv4Address:
            ip_addr = IPv4Address(host).to_knowledge_node()
            ip_addr_knowledge = ip_addr
        elif type(ipaddress.ip_address(host)) is ipaddress.IPv6Address:
            ip_addr = IPv6Address(host)
            ip_addr_knowledge = ip_addr
        else:
            raise ValueError(
                f"Unsupported ip type {type(ipaddress.ip_address(host)) } for {host}"
            )
        knowledge_nodes.append(ip_addr_knowledge)
        knowledge_relations.append(
            KnowledgeRelation(
                label="HAS_ADDRESS",
                source_node=target_host_knowledge,
                target_node=ip_addr_knowledge,
            )
        )

        if scan_results[host]["macaddress"]:
            # Add MAC to NIC
            mac_addr_knowledge = KnowledgeNode(
                label="MACAddress",
                name=scan_results[host]["macaddress"]["addr"],
                values={
                    "mac_address": scan_results[host]["macaddress"]["addr"],
                },
            )
            knowledge_nodes.append(mac_addr_knowledge)
            knowledge_relations.append(
                KnowledgeRelation(
                    label="HAS_ADDRESS",
                    source_node=target_host_knowledge,
                    target_node=mac_addr_knowledge,
                )
            )

            if "vendor" in scan_results[host]["macaddress"]:
                nic_manufacturer_knowledge = KnowledgeNode(
                    label="Vendor",
                    name=f"{scan_results[host]['macaddress']['vendor']}",
                    values={
                        "vendor": scan_results[host]["macaddress"]["vendor"],
                    },
                )
                knowledge_nodes.append(nic_manufacturer_knowledge)
                knowledge_relations.append(
                    KnowledgeRelation(
                        label="MANUFACTURES",
                        source_node=nic_manufacturer_knowledge,
                        target_node=mac_addr_knowledge,
                    )
                )

        for hostname in scan_results[host]["hostname"]:
            domain_name = KnowledgeNode(
                label="DNSRecord",
                name=hostname["name"],
                values={
                    "dns_type": hostname["type"],
                    "dns_record": hostname["name"],
                },
            )
            knowledge_nodes.append(domain_name)

        if len(scan_results[host]["osmatch"]) > 1:
            os_match = scan_results[host]["osmatch"][0]
            operating_system_knowledge = KnowledgeNode(
                label="Software",
                name=os_match["cpe"] if os_match["cpe"] else os_match["name"],
                values={
                    "name": os_match["name"],
                    "version": os_match["osclass"]["osgen"],
                },
            )
            knowledge_nodes.append(operating_system_knowledge)
            knowledge_relations.append(
                KnowledgeRelation(
                    label="RUNS_ON",
                    source_node=operating_system_knowledge,
                    target_node=target_host_knowledge,
                )
            )

            if os_match["osclass"]["vendor"]:
                os_vendor_knowledge = KnowledgeNode(
                    label="Vendor",
                    name=os_match["osclass"]["vendor"],
                    values={
                        "vendor": os_match["osclass"]["vendor"],
                    },
                )
                knowledge_nodes.append(os_vendor_knowledge)
                knowledge_relations.append(
                    KnowledgeRelation(
                        label="MANUFACTURES",
                        source_node=os_vendor_knowledge,
                        target_node=operating_system_knowledge,
                    )
                )

        for port in scan_results[host]["ports"]:
            if port["state"] == "open":
                open_port = NetworkEndpoint(
                    host,
                    int(port["portid"]),
                    port["protocol"],
                    endpoint="dst",
                    values={"service_name": port["service"]["name"]},
                )
                open_port_ref = open_port.to_network_port_ref()
                open_port_knowledge = open_port.to_knowledge_node()
                open_port_ref_knowledge = open_port_ref.to_knowledge_node()
                knowledge_nodes.append(open_port_knowledge)
                knowledge_nodes.append(open_port_ref_knowledge)
                knowledge_relations.append(
                    KnowledgeRelation(
                        label="IS_TYPE",
                        source_node=open_port_knowledge,
                        target_node=open_port_ref_knowledge,
                    )
                )
                knowledge_relations.append(
                    KnowledgeRelation(
                        label="HAS_PORT",
                        source_node=ip_addr_knowledge,
                        target_node=open_port_knowledge,
                        values={"last_seen": scan_time.timestamp(), "status": "open"},
                    )
                )

    return knowledge_nodes, knowledge_relations


def suricata_alert_to_knowledge(
    alert: Dict[str, Any]
) -> Tuple[List[KnowledgeNode], List[KnowledgeRelation]]:
    """
    Converts a Suricata alert (as returned from aica_django.connectors.Suricata.poll_suricata_alerts)
    to knowledge objects.

    @param alert: A dictionary as returned by poll_suricata_alerts to be converted to knowledge objects
    @type alert: Dict[str, Any]
    @return: Knowledge nodes and relations resulting form this conversion
    @rtype: Tuple[list, list]
    """

    knowledge_nodes = []
    knowledge_relations = []

    alert_dt: Optional[datetime.datetime] = dateparser.parse(alert["timestamp"])
    assert alert_dt is not None

    dissected_time_tripped = dissect_time(alert_dt.timestamp(), prefix="time_tripped")
    value_dict: Dict[str, Any] = dissected_time_tripped
    value_dict["time_tripped"] = alert_dt.timestamp()
    value_dict["flow_id"] = alert["flow_id"]

    alert_knowledge = KnowledgeNode(
        label="Alert",
        name=str(uuid.uuid4()),
        values=value_dict,
    )
    knowledge_nodes.append(alert_knowledge)
    alert_sig_knowledge = KnowledgeNode(
        label="AttackSignature",
        name=f"Suricata {alert['alert']['gid']}: {alert['alert']['signature_id']}",
        values={
            "gid": alert["alert"]["gid"],
            "signature_id": alert["alert"]["signature_id"],
            "rev": alert["alert"]["rev"],
            "signature": alert["alert"]["signature"],
            "severity": alert["alert"]["severity"],
        },
    )
    knowledge_nodes.append(alert_sig_knowledge)

    knowledge_relations.append(
        KnowledgeRelation(
            label="IS_TYPE",
            source_node=alert_knowledge,
            target_node=alert_sig_knowledge,
        )
    )

    if alert["alert"]["category"] == "":
        raise ValueError(f"Name must be non-empty|alert:" + str(alert))
    alert_cat_knowledge = KnowledgeNode(
        label="AttackSignatureCategory",
        name=alert["alert"]["category"],
        values={
            "category": alert["alert"]["category"],
        },
    )
    knowledge_nodes.append(alert_cat_knowledge)
    knowledge_relations.append(
        KnowledgeRelation(
            label="MEMBER_OF",
            source_node=alert_sig_knowledge,
            target_node=alert_cat_knowledge,
        )
    )

    dissected_time = dissect_time(alert_dt.timestamp())
    source_host = Host(
        alert["src_ip"],
        last_seen=alert_dt.timestamp(),
        values=dissected_time,
    )
    source_host_knowledge = source_host.to_knowledge_node()
    knowledge_nodes.append(source_host_knowledge)

    if type(ipaddress.ip_address(alert["src_ip"])) is ipaddress.IPv4Address:
        source_ip = IPv4Address(alert["src_ip"]).to_knowledge_node()
    elif type(ipaddress.ip_address(alert["src_ip"])) is ipaddress.IPv6Address:
        source_ip = IPv6Address(alert["src_ip"]).to_knowledge_node()
    else:
        raise ValueError(
            f"Unsupported src_ip type {type(ipaddress.ip_address(alert['src_ip'])) } for {alert['src_ip']}"
        )

    source_ip_knowledge = source_ip
    knowledge_nodes.append(source_ip_knowledge)
    knowledge_relations.append(
        KnowledgeRelation(
            label="HAS_ADDRESS",
            source_node=source_host_knowledge,
            target_node=source_ip_knowledge,
        )
    )

    dest_host = Host(
        alert["dest_ip"],
        last_seen=alert_dt.timestamp(),
    )
    dest_host_knowledge = dest_host.to_knowledge_node()
    knowledge_nodes.append(dest_host_knowledge)

    if type(ipaddress.ip_address(alert["dest_ip"])) is ipaddress.IPv4Address:
        dest_ip = IPv4Address(alert["dest_ip"]).to_knowledge_node()
    elif type(ipaddress.ip_address(alert["dest_ip"])) is ipaddress.IPv6Address:
        dest_ip = IPv6Address(alert["dest_ip"]).to_knowledge_node()
    else:
        raise ValueError(
            f"Unsupported dest_ip type {type(ipaddress.ip_address(alert['dest_ip'])) } for {alert['dest_ip']}"
        )

    dest_ip_knowledge = dest_ip
    knowledge_nodes.append(dest_ip_knowledge)

    knowledge_relations.append(
        KnowledgeRelation(
            label="HAS_ADDRESS",
            source_node=dest_host_knowledge,
            target_node=dest_ip_knowledge,
        )
    )

    source_port = NetworkEndpoint(
        alert["src_ip"], alert["src_port"], alert["proto"], endpoint="source"
    )
    source_port_ref = source_port.to_network_port_ref()
    source_port_knowledge = source_port.to_knowledge_node()
    source_port_ref_knowledge = source_port_ref.to_knowledge_node()
    knowledge_nodes.append(source_port_knowledge)
    knowledge_nodes.append(source_port_ref_knowledge)

    knowledge_relations.append(
        KnowledgeRelation(
            label="HAS_PORT",
            source_node=source_ip_knowledge,
            target_node=source_port_knowledge,
        )
    )
    knowledge_relations.append(
        KnowledgeRelation(
            label="IS_TYPE",
            source_node=source_port_knowledge,
            target_node=source_port_ref_knowledge,
        )
    )

    dest_port = NetworkEndpoint(
        alert["dest_ip"], alert["dest_port"], alert["proto"], endpoint="dest"
    )
    dest_port_ref = dest_port.to_network_port_ref()
    dest_port_knowledge = dest_port.to_knowledge_node()
    dest_port_ref_knowledge = dest_port_ref.to_knowledge_node()
    knowledge_nodes.append(dest_port_knowledge)
    knowledge_nodes.append(dest_port_ref_knowledge)
    knowledge_relations.append(
        KnowledgeRelation(
            label="HAS_PORT",
            source_node=dest_ip_knowledge,
            target_node=dest_port_knowledge,
        )
    )

    knowledge_relations.append(
        KnowledgeRelation(
            label="IS_TYPE",
            source_node=dest_port_knowledge,
            target_node=dest_port_ref_knowledge,
        )
    )

    flow_start_dt: Optional[datetime.datetime] = dateparser.parse(
        alert["flow"]["start"]
    )
    assert flow_start_dt is not None

    dissected_start: Dict[str, Any] = dissect_time(
        flow_start_dt.timestamp(), prefix="start"
    )
    value_dict = dissected_start
    value_dict["source"] = "suricata"

    network_flow = NetworkTraffic(
        int(alert["flow"]["pkts_toserver"]),
        int(alert["flow"]["bytes_toserver"]),
        flow_start_dt.timestamp(),
        values=value_dict,
    )
    network_flow_knowledge = network_flow.to_knowledge_node()
    knowledge_nodes.append(network_flow_knowledge)

    knowledge_relations.append(
        KnowledgeRelation(
            label="HAS_PORT",
            source_node=source_ip_knowledge,
            target_node=source_port_knowledge,
        )
    )
    knowledge_relations.append(
        KnowledgeRelation(
            label="HAS_PORT",
            source_node=dest_ip_knowledge,
            target_node=dest_port_knowledge,
        )
    )
    knowledge_relations.append(
        KnowledgeRelation(
            label="COMMUNICATES_TO",
            source_node=source_port_knowledge,
            target_node=network_flow_knowledge,
        )
    )
    knowledge_relations.append(
        KnowledgeRelation(
            label="COMMUNICATES_TO",
            source_node=network_flow_knowledge,
            target_node=dest_port_knowledge,
        )
    )
    knowledge_relations.append(
        KnowledgeRelation(
            label="TRIGGERED_BY",
            source_node=alert_knowledge,
            target_node=network_flow_knowledge,
        )
    )

    return knowledge_nodes, knowledge_relations


def antivirus_alert_to_knowledge(
    alert: Dict[str, Any]
) -> Tuple[List[KnowledgeNode], List[KnowledgeRelation]]:
    """
    Converts an antivirus alert (as returned from aica_django.connectors.Antivirus.poll_antivirus_alerts)
    to knowledge objects.

    @param alert: A dictionary as returned by poll_antivirus_alerts to be converted to knowledge objects
    @type alert: Dict[str, Any]
    @return: Knowledge nodes and relations resulting form this conversion
    @rtype: Tuple[list, list]
    """

    nodes = []
    relations = []

    # The if statement is here for error handling the case where the VirusTotal
    # data isn't properly stored in the alert object and we get the "Not Available"
    # as specified in the antivirus.py file. Otherwise, we'd have a bunch of errors
    # showing up anytime an API key was invalid or the VT servers are unavailable
    alert_knowledge = KnowledgeNode(
        label="Alert",
        name=str(uuid.uuid4()),
        values={
            "date": alert["date"],
        },
    )
    nodes.append(alert_knowledge)

    alert_signature_knowledge = KnowledgeNode(
        label="AttackSignature",
        name=f"{alert['signature']}:{alert['revision']}",
        values={
            "platform": alert["platform"],
            "name": alert["name"],
        },
    )
    nodes.append(alert_signature_knowledge)
    alert_signature_category_knowledge = KnowledgeNode(
        label="AttackSignatureCategory",
        name=f"{alert['category']}",
    )
    nodes.append(alert_signature_category_knowledge)
    relations.append(
        KnowledgeRelation(
            "IS_TYPE",
            source_node=alert_signature_knowledge,
            target_node=alert_signature_category_knowledge,
        )
    )

    relations.append(
        KnowledgeRelation(
            label="IS_TYPE",
            source_node=alert_knowledge,
            target_node=alert_signature_knowledge,
        )
    )

    path_knowledge = KnowledgeNode(
        label="FilePath",
        name=alert["path"],
    )
    nodes.append(path_knowledge)

    host = Host(alert["source_ip"], last_seen=datetime.datetime.now().timestamp())
    host_knowledge = host.to_knowledge_node()
    nodes.append(host_knowledge)

    relations.append(
        KnowledgeRelation(
            label="TRIGGERED_BY",
            source_node=alert_knowledge,
            target_node=path_knowledge,
        )
    )

    relations.append(
        KnowledgeRelation(
            label="STORED_ON",
            source_node=path_knowledge,
            target_node=host_knowledge,
        )
    )

    return nodes, relations

def waf_alert_to_knowledge(
    alert: Dict[str, Any]
) -> Tuple[List[KnowledgeNode], List[KnowledgeRelation]]:
    """
    Converts an waf alert (as returned from aica_django.connectors.WAF.poll_waf_alerts)
    to knowledge objects.

    **TODO**

    @param alert: A dictionary as returned by poll_waf_alerts to be converted to knowledge objects
    @type alert: Dict[str, Any]
    @return: Knowledge nodes and relations resulting form this conversion
    @rtype: Tuple[list, list]
    """

    knowledge_nodes = []
    knowledge_relations = []

    # alert_dt: Optional[datetime.datetime] = dateparser.parse(alert["timestamp"])
    alert_dt = float(alert["ts"])
    assert alert_dt is not None

    dissected_time_tripped = dissect_time(alert_dt, prefix="time_tripped")
    value_dict: Dict[str, Any] = dissected_time_tripped
    value_dict["time_tripped"] = alert_dt
    value_dict["unique_id"] = alert["unique_id"]

    alert_knowledge = KnowledgeNode(
        label="Alert",
        name=str(uuid.uuid4()),
        values=value_dict,
    )
    knowledge_nodes.append(alert_knowledge)
    alert_sig_knowledge = KnowledgeNode(
        label="AttackSignature",
        name=f"OWASP CRS {alert['id']}",
        values={
            "rule_id": alert["alert"]["id"],
            "rev": alert["rev"],
            "data": alert["data"],
            "severity": alert["severity"],
        },
    )
    knowledge_nodes.append(alert_sig_knowledge)

    knowledge_relations.append(
        KnowledgeRelation(
            label="IS_TYPE",
            source_node=alert_knowledge,
            target_node=alert_sig_knowledge,
        )
    )

    for tag in alert["tags"]:
        alert_cat_knowledge = KnowledgeNode(
            label="AttackSignatureCategory",
            name=tag,
            values={
                "tag": tag,
            },
        )
        knowledge_nodes.append(alert_cat_knowledge)
        knowledge_relations.append(
            KnowledgeRelation(
                label="MEMBER_OF",
                source_node=alert_sig_knowledge,
                target_node=alert_cat_knowledge,
            )
        )

    # Make Cypher query and return node that contains the correct unique ID
    graph = AicaNeo4j()
    req_id = alert["unique_id"] # leaving this here because format strings
    nodes = list(graph.run(f'MATCH (n:HttpRequest) WHERE n.unique_id = "{req_id}" RETURN n'))

    if len(nodes) > 0:
        source_http_req = nodes[0]
        # DO NOT APPEND THIS TO THE NODES LIST
        source_http_knowledge = KnowledgeNode(
            label="HttpRequest",
            name=source_http_req['id']
        )
        knowledge_relations.append(
            KnowledgeRelation(
                label="TRIGGERED_BY",
                source_node=source_http_knowledge,
                target_node=alert_knowledge
            )            
        )

    else:
        source_host = Host(alert["client"], last_seen=alert_dt)
        knowledge_nodes.append(source_host.to_knowledge_node())
        knowledge_relations.append(
            KnowledgeRelation(
                label="TRIGGERED_BY",
                source_node=source_host,
                target_node=alert_knowledge
            )            
        )


    return knowledge_nodes, knowledge_relations

def knowledge_to_neo(
    nodes: List[KnowledgeNode], relations: List[KnowledgeRelation]
) -> bool:
    """
    Stores KnowledgeNode and KnowledgeRelation objects in the knowledge graph database.

    @param nodes: KnowledgeNodes to store
    @type nodes: list
    @param relations: KnowledgeRelations to store (must consist entirely of existing or to-be-added nodes)
    @type relations: list
    @return: Whether the insert was successful
    @rtype: bool
    """

    neo_host = str(os.getenv("N4J_HOST"))
    neo_user = str(os.getenv("N4J_USER"))
    neo_password = str(os.getenv("N4J_PASSWORD"))

    graph = AicaNeo4j()

    # Intentionally only handling lists to encourage batching
    res1 = False
    res2 = False
    for node in nodes:
        res1 = graph.add_node(
            node.name,
            node.label,
            node.values,
        )

    for relation in relations:
        res2 = graph.add_relation(
            relation.source_node,
            relation.source_label,
            relation.target_node,
            relation.target_label,
            relation.label,
            relation.values,
        )

    return res1 and res2
