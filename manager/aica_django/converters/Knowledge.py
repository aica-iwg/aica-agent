import dateparser
import datetime
import ipaddress
import logging
import os
import pytz
import re
import socket
import uuid

from typing import Tuple, Dict, Any

from aica_django.connectors.AicaNeo4j import (
    AicaNeo4j,
    defined_node_labels,
    defined_relation_labels,
)
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def dissect_time(timestamp: int) -> dict:
    dt_utc = datetime.datetime.fromtimestamp(timestamp)
    dt_americas = dt_utc.astimezone(pytz.timezone("America/Chicago"))
    dt_europeafrica = dt_utc.astimezone(pytz.timezone("Europe/Berlin"))
    dt_asiaoceana = dt_utc.astimezone(pytz.timezone("Asia/Shanghai"))
    time_details = {
        "minute_of_hour": dt_utc.minute,
        "hour_of_day": dt_utc.hour,
        "day_of_week": dt_utc.weekday(),
        "week_of_month": dt_utc.isocalendar()[1]
        - dt_utc.replace(day=1).isocalendar()[1]
        + 1,
        "week_of_year": dt_utc.isocalendar()[1],
        "month_of_year": dt_utc.month,
        # These are only meant to be rough proxies
        "workhours_americas": (dt_americas.weekday() < 5)
        and (6 < dt_americas.hour < 21),
        "workhours_euraf": (dt_europeafrica.weekday() < 5)
        and (5 < dt_europeafrica.hour < 19),
        "workhours_asoce": (dt_asiaoceana.weekday() < 5)
        and (5 < dt_asiaoceana.hour < 21),
    }

    return time_details


class KnowledgeNode:
    label: str = ""
    name: str = ""
    values: Dict[str, Any] = dict()

    def __init__(self, label: str, name: str, values: Dict[str, Any] = None):
        if label not in defined_node_labels:
            raise ValueError(f"Unsupported node label {label} for {name}")

        if type(label) != str or label == "":
            raise ValueError(f"Label must be a non-empty string, not {type(label)}")
        if type(name) not in (str, int) or name == "":
            raise ValueError(
                f"Name must be a non-empty string or int, not {type(name)}"
            )
        if values and type(values) != dict:
            raise ValueError(f"Values must be a dictionary, not {type(values)}")

        self.values = values if values else Dict[str, Any]()
        if label == "MACAddress":
            name = normalize_mac_addr(name)
            self.values["value"] = name

        self.label = label
        self.name = name


class NetworkPort(KnowledgeNode):
    def __init__(self, port: int, protocol: str, values: Dict[str, Any] = None):
        self.label = "NetworkPort"
        self.port = port
        self.protocol = protocol
        self.name = f"{self.port}/{self.protocol}"
        self.values = values if values else {}
        super().__init__(self.label, self.name, values=self.values)

    def to_knowledge_node(self) -> KnowledgeNode:
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
    def __init__(
        self,
        host: str,
        port: int,
        protocol: str,
        endpoint: str = None,
        values: Dict[str, Any] = None,
    ):
        self.label = "NetworkEndpoint"
        self.host = host
        self.port = port
        self.protocol = protocol
        self.endpoint = (endpoint if endpoint in ["src", "dst"] else None,)
        self.name = f"{self.host}:{self.port}/{self.protocol}"
        self.values = values if values else {}
        super().__init__(self.label, self.name, values=self.values)

    def to_network_port_ref(self) -> NetworkPort:
        return NetworkPort(self.port, self.protocol, values=self.values)

    def to_knowledge_node(self) -> KnowledgeNode:
        values = self.values
        values["port"] = self.port
        values["protocol"] = self.protocol
        values["host"] = self.host
        values["endpoint"] = self.endpoint

        return KnowledgeNode(
            label=self.label,
            name=self.name,
            values=values,
        )


class IPv4Address(KnowledgeNode):
    def __init__(self, ip_addr: str, values: Dict[str, Any] = None):
        try:
            socket.inet_pton(socket.AF_INET, ip_addr)
        except socket.error:
            logging.error(f"Invalid IPv4 Address: {ip_addr}")
        self.label = "IPv4Address"
        self.ip_addr = ipaddress.ip_address(ip_addr)
        self.name = ip_addr
        self.values = values if values else {}
        super().__init__(self.label, self.name, values=self.values)

    def to_knowledge_node(self) -> KnowledgeNode:
        values = self.values
        values["address"] = (str(self.ip_addr),)
        values["is_private"] = (self.ip_addr.is_private,)
        values["reserved"] = (self.ip_addr.is_reserved,)
        values["multicast"] = (self.ip_addr.is_multicast,)
        values["loopback"] = (self.ip_addr.is_loopback,)
        # Hex to discourage use as continuous value
        int_value = int(self.ip_addr)
        values["int_value"] = (hex(int_value),)
        values["class_a"] = (hex(int_value & 0xFF000000),)
        values["class_b"] = (hex(int_value & 0xFFFF0000),)
        values["class_c"] = (hex(int_value & 0xFFFFFF00),)

        return KnowledgeNode(
            label=self.label,
            name=self.name,
            values=values,
        )


class IPv6Address(KnowledgeNode):
    def __init__(self, ip_addr: str, values: Dict[str, Any] = None):
        try:
            socket.inet_pton(socket.AF_INET6, ip_addr)
        except socket.error:
            logging.error(f"Invalid IPv6 Address: {ip_addr}")
        self.label = "IPv6Address"
        self.ip_addr = ipaddress.ip_address(ip_addr)
        self.name = ip_addr
        self.values = values if values else {}
        super().__init__(self.label, self.name, values=self.values)

    def to_knowledge_node(self) -> KnowledgeNode:
        values = self.values
        values["address"] = (str(self.ip_addr),)
        values["is_private"] = (self.ip_addr.is_private,)
        values["reserved"] = (self.ip_addr.is_reserved,)
        values["multicast"] = (self.ip_addr.is_multicast,)
        values["loopback"] = (self.ip_addr.is_loopback,)
        values["link_local"] = (self.ip_addr.is_link_local,)
        # Hex to discourage use as continuous value
        int_value = int(self.ip_addr)
        values["int_value"] = (hex(int_value),)
        values["class_16"] = (hex(int_value & 0xFFFF0000000000000000000000000000),)
        values["class_32"] = (hex(int_value & 0xFFFFFFFF000000000000000000000000),)
        values["class_48"] = (hex(int_value & 0xFFFFFFFFFFFF00000000000000000000),)
        values["class_56"] = (hex(int_value & 0xFFFFFFFFFFFFFF000000000000000000),)
        values["class_64"] = (hex(int_value & 0xFFFFFFFFFFFFFFFF0000000000000000),)

        return KnowledgeNode(
            label=self.label,
            name=self.name,
            values=values,
        )


class NetworkTraffic(KnowledgeNode):
    def __init__(
        self,
        in_packets: int,
        in_octets: int,
        start_ts: int,
        end_ts: int = -1,
        flags: str = "",
        tos: str = "",
        values: Dict[str, Any] = None,
    ):
        self.label = "NetworkTraffic"
        self.in_packets = in_packets
        self.in_octets = in_octets
        self.start = (datetime.datetime.fromtimestamp(start_ts),)
        self.end = datetime.datetime.fromtimestamp(end_ts) if end_ts else None
        self.flags = flags
        self.tos = tos
        self.values = values if values else {}
        self.name = str(uuid.uuid4())
        super().__init__(self.label, self.name, values=self.values)

    def to_knowledge_node(self) -> KnowledgeNode:
        return KnowledgeNode(
            label="NetworkTraffic",
            name=self.name,
            values={
                "in_packets": self.in_packets,
                "in_octets": self.in_octets,
                "start": self.start,
                "end": self.end,
                "flags": self.flags,
                "tos": self.tos,
            },
        )


class Host(KnowledgeNode):
    def __init__(self, identifier, values=None):
        self.label = "Host"
        self.name = identifier
        self.values = values if values else {}
        super().__init__(self.label, self.name, values=self.values)

    def to_knowledge_node(self) -> KnowledgeNode:
        return KnowledgeNode(
            label=self.label,
            name=self.name,
            values=self.values,
        )


class KnowledgeRelation:
    label = None
    source_node = None
    source_label = None
    target_node = None
    target_label = None
    values: Dict[str, Any] = dict()

    def __init__(self, label, source_node, target_node, values=None):
        if label not in defined_relation_labels:
            raise ValueError(
                f"Unsupported relation label {label} from {source_node}->{target_node}"
            )

        if type(label) != str or label == "":
            raise ValueError(f"Label must be a string, not {type(label)}")
        if type(source_node) != KnowledgeNode:
            raise ValueError(
                f"Source node must be a KnowledgeNode, not {type(source_node)}"
            )
        if type(target_node) != KnowledgeNode:
            raise ValueError(
                f"Target node must be a KnowledgeNode, not {type(target_node)}"
            )
        if values and type(values) != Dict[str, Any]:
            raise ValueError(f"Values must be a dictionary, not {type(values)}")

        self.label = label
        self.source_node = source_node.name
        self.source_label = source_node.label
        self.target_node = target_node.name
        self.target_label = target_node.label
        self.values = values


def normalize_mac_addr(mac_addr: str) -> str:
    return re.sub(r"[^A-Fa-f\d]", "", mac_addr).lower()


def netflow_to_knowledge(flow: Dict[str, str]) -> Tuple[list, list]:
    nodes = []
    relations = []

    # Create source host and port nodes (and link to protocol node)
    ipv4_src_addr = str(ipaddress.ip_address(flow["IPV4_SRC_ADDR"]))
    source_addr = IPv4Address(ipv4_src_addr).to_knowledge_node()
    nodes.append(source_addr)

    source_port = NetworkEndpoint(
        ipv4_src_addr, int(flow["SRC_PORT"]), flow["PROTO"], endpoint="src"
    )
    source_port_ref = source_port.to_network_port_ref()
    source_port_knowledge = source_port.to_knowledge_node()
    source_port_ref_knowledge = source_port_ref.to_knowledge_node()

    nodes.append(source_port_knowledge)
    nodes.append(source_port_ref_knowledge)

    relations.append(
        KnowledgeRelation(
            label="is-type",
            source_node=source_port_knowledge,
            target_node=source_port_ref_knowledge,
        )
    )
    relations.append(
        KnowledgeRelation(
            label="has-port",
            source_node=source_addr,
            target_node=source_port,
        )
    )

    source_host = Host(ipv4_src_addr).to_knowledge_node()
    nodes.append(source_host)
    relations.append(
        KnowledgeRelation(
            label="has-address",
            source_node=source_host,
            target_node=source_addr,
        )
    )

    # Create destination host and port nodes (and link to protocol node)
    ipv4_dst_addr_obj = ipaddress.ip_address(flow["IPV4_DST_ADDR"])
    ipv4_dst_addr = str(ipv4_dst_addr_obj)
    dest_addr = IPv4Address(ipv4_dst_addr).to_knowledge_node()
    nodes.append(dest_addr)

    dest_port = NetworkEndpoint(
        ipv4_dst_addr, int(flow["DST_PORT"]), flow["PROTO"], endpoint="dst"
    )
    dest_port_ref = dest_port.to_network_port_ref()
    dest_port_knowledge = dest_port.to_knowledge_node()
    dest_port_ref_knowledge = dest_port_ref.to_knowledge_node()
    nodes.append(dest_port_knowledge)
    nodes.append(dest_port_ref_knowledge)

    relations.append(
        KnowledgeRelation(
            label="is-type",
            source_node=dest_port_knowledge,
            target_node=dest_port_ref_knowledge,
        )
    )
    relations.append(
        KnowledgeRelation(
            label="has-port",
            source_node=dest_addr,
            target_node=dest_port,
        )
    )

    if not (ipv4_dst_addr_obj.is_multicast or ipv4_dst_addr_obj.is_reserved):
        dest_host = Host(
            ipv4_dst_addr, values={"last_seen": flow["LAST_SWITCHED"]}
        ).to_knowledge_node()
        nodes.append(dest_host)
        relations.append(
            KnowledgeRelation(
                label="has-address",
                source_node=dest_host,
                target_node=dest_addr,
            )
        )

    # Create NetworkTraffic node
    flow_knowledge = NetworkTraffic(
        int(flow["IN_PACKETS"]),
        int(flow["IN_OCTETS"]),
        int(flow["FIRST_SWITCHED"]),
        int(flow["LAST_SWITCHED"]),
        flow["TCP_FLAGS"],
        flow["TOS"],
        values={
            "source": "netflow",
        },
    ).to_knowledge_node()
    nodes.append(flow_knowledge)
    relations.append(
        KnowledgeRelation(
            label="communicates-to",
            source_node=source_port,
            target_node=flow_knowledge,
        )
    )
    relations.append(
        KnowledgeRelation(
            label="communicates-to",
            source_node=flow,
            target_node=dest_port,
        )
    )

    return nodes, relations


def nginx_accesslog_to_knowledge(log_dict: Dict[str, Any]) -> Tuple[list, list]:
    nodes = []
    relations = []

    # dateparser can't seem to handle this format
    request_time = datetime.datetime.strptime(
        log_dict["dateandtime"], "%d/%b/%Y:%H:%M:%S %z"
    )

    if not request_time:
        raise ValueError(f"Couldn't parse timestamp {log_dict['dateandtime']}")
    else:
        dissected_request_time = dissect_time(int(request_time.timestamp()))

    my_hostname = socket.gethostname()
    my_ipv4 = IPv4Address(socket.gethostbyname(my_hostname)).to_knowledge_node()
    nodes.append(my_ipv4)

    # Add requesting host
    requesting_host = Host(
        log_dict["src_ip"],
        values={
            "last_seen": request_time,
            "dissected_last_seen": dissected_request_time,
        },
    ).to_knowledge_node()
    nodes.append(requesting_host)

    # Add target NIC to target host
    nic = KnowledgeNode(
        label="NetworkInterface",
        name=str(uuid.uuid4()),
        values={
            "last_seen": request_time,
            "dissected_last_seen": dissected_request_time,
        },
    )
    nodes.append(nic)
    relations.append(
        KnowledgeRelation(
            label="component-of",
            source_node=nic,
            target_node=requesting_host,
        )
    )

    ipv4_addr = IPv4Address(log_dict["src_ip"]).to_knowledge_node()
    nodes.append(ipv4_addr)
    relations.append(
        KnowledgeRelation(
            label="has-address",
            source_node=nic,
            target_node=ipv4_addr,
        )
    )

    http_request = KnowledgeNode(
        label="HttpRequest",
        name=str(uuid.uuid4()),
        values={
            "request_time": request_time,
            "dissected_request_time": dissected_request_time,
            "method": log_dict["method"],
            "url": log_dict["url"],
            "response_status": log_dict["statuscode"],
            "bytes": log_dict["bytes_sent"],
            "referer": log_dict["referer"],
            "user_agent": log_dict["useragent"],
        },
    )
    nodes.append(http_request)

    relations.append(
        KnowledgeRelation(
            label="communicates-to",
            source_node=ipv4_addr,
            target_node=http_request,
        )
    )
    relations.append(
        KnowledgeRelation(
            label="communicates-to",
            source_node=http_request,
            target_node=my_ipv4,
        )
    )

    return nodes, relations


def nmap_scan_to_knowledge(scan_results: Dict[str, Any]) -> Tuple[list, list]:
    nodes = []
    relations = []

    scan_time = dateparser.parse(scan_results["runtime"]["time"])

    # Not needed and make iteration below messy
    del scan_results["stats"]
    del scan_results["runtime"]

    my_hostname = socket.gethostname()
    my_ipv4 = IPv4Address(socket.gethostbyname(my_hostname)).to_knowledge_node()
    nodes.append(my_ipv4)

    for host, data in scan_results.items():
        if scan_results[host]["state"]["state"] != "up":
            continue

        # Add scan target
        target_host = Host(
            host,
            values={
                "last_seen": scan_time,
                "state_reason": scan_results[host]["state"]["reason"],
                "state_reason_ttl": scan_results[host]["state"]["reason_ttl"],
            },
        ).to_knowledge_node()
        nodes.append(target_host)

        # Add target NIC to target host
        nic = KnowledgeNode(
            label="NetworkInterface",
            name=str(uuid.uuid4()),
            values={"last_seen": scan_time},
        )
        nodes.append(nic)
        relations.append(
            KnowledgeRelation(
                label="component-of",
                source_node=nic,
                target_node=target_host,
            )
        )

        # Add target IPv4 to NIC
        ipv4_addr = IPv4Address(host).to_knowledge_node()
        nodes.append(ipv4_addr)
        relations.append(
            KnowledgeRelation(
                label="has-address",
                source_node=nic,
                target_node=ipv4_addr,
            )
        )

        if scan_results[host]["macaddress"]:
            # Add MAC to NIC
            mac_addr = KnowledgeNode(
                label="MACAddress",
                name=scan_results[host]["macaddress"]["addr"],
                values={
                    "mac_address": scan_results[host]["macaddress"]["addr"],
                },
            )
            nodes.append(mac_addr)
            relations.append(
                KnowledgeRelation(
                    label="has-address",
                    source_node=nic,
                    target_node=mac_addr,
                )
            )

            if "vendor" in scan_results[host]["macaddress"]:
                # Add firmware to NIC
                nic_manufacturer = KnowledgeNode(
                    label="Vendor",
                    name=f"{scan_results[host]['macaddress']['vendor']}",
                    values={
                        "vendor": scan_results[host]["macaddress"]["vendor"],
                    },
                )
                nodes.append(nic_manufacturer)
                relations.append(
                    KnowledgeRelation(
                        label="manufactures",
                        source_node=nic_manufacturer,
                        target_node=nic,
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
            nodes.append(domain_name)

            domain_source_node = None
            domain_target_node = None
            if hostname["type"] in ["A", "AAAA", "user"]:
                domain_source_node = domain_name
                domain_target_node = ipv4_addr
            elif hostname["type"] == "PTR":
                domain_source_node = ipv4_addr
                domain_target_node = domain_name
            relations.append(
                KnowledgeRelation(
                    label="resolves-to",
                    source_node=domain_source_node,
                    target_node=domain_target_node,
                )
            )

        if len(scan_results[host]["osmatch"]) > 1:
            os_match = scan_results[host]["osmatch"][0]
            operating_system = KnowledgeNode(
                label="Software",
                name=os_match["cpe"] if os_match["cpe"] else os_match["name"],
                values={
                    "name": os_match["name"],
                    "version": os_match["osclass"]["osgen"],
                },
            )
            nodes.append(operating_system)
            relations.append(
                KnowledgeRelation(
                    label="runs-on",
                    source_node=operating_system,
                    target_node=target_host,
                )
            )

            if os_match["osclass"]["vendor"]:
                os_vendor = KnowledgeNode(
                    label="Vendor",
                    name=os_match["osclass"]["vendor"],
                    values={
                        "vendor": os_match["osclass"]["vendor"],
                    },
                )
                nodes.append(os_vendor)
                relations.append(
                    KnowledgeRelation(
                        label="manufactures",
                        source_node=os_vendor,
                        target_node=operating_system,
                    )
                )

        for port in scan_results[host]["ports"]:
            if port["state"] == "open":
                open_port = NetworkEndpoint(
                    host,
                    port["portid"],
                    port["protocol"],
                    endpoint="dst",
                    values={"service_name": port["service"]["name"]},
                )
                open_port_ref = open_port.to_network_port_ref()
                open_port_knowledge = open_port.to_knowledge_node()
                open_port_ref_knowledge = open_port_ref.to_knowledge_node()
                nodes.append(open_port_knowledge)
                nodes.append(open_port_ref_knowledge)
                relations.append(
                    KnowledgeRelation(
                        label="is-type",
                        source_node=open_port_knowledge,
                        target_node=open_port_ref_knowledge,
                    )
                )
                relations.append(
                    KnowledgeRelation(
                        label="has-port",
                        source_node=ipv4_addr,
                        target_node=open_port,
                        values={"last_seen": scan_time, "status": "open"},
                    )
                )

    return nodes, relations


def suricata_alert_to_knowledge(alert: Dict[str, Any]) -> Tuple[list, list]:
    nodes = []
    relations = []

    time_tripped = dateparser.parse(alert["timestamp"])
    dissected_time = dissect_time(int(alert["timestamp"]))

    alert_obj = KnowledgeNode(
        label="Alert",
        name=str(uuid.uuid4()),
        values={
            "time_tripped": time_tripped,
            "dissected_time_tripped": dissected_time,
            "flow_id": alert["flow_id"],
        },
    )
    nodes.append(alert_obj)

    alert_signature = KnowledgeNode(
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
    nodes.append(alert_signature)

    relations.append(
        KnowledgeRelation(
            label="is-type",
            source_node=alert_obj,
            target_node=alert_signature,
        )
    )

    alert_category = KnowledgeNode(
        label="AttackSignatureCategory",
        name=alert["alert"]["category"],
        values={
            "category": alert["alert"]["category"],
        },
    )
    nodes.append(alert_category)
    relations.append(
        KnowledgeRelation(
            label="member-of",
            source_node=alert_signature,
            target_node=alert_category,
        )
    )

    source_host = Host(
        alert["src_ip"],
        values={
            "last_seen": time_tripped,
            "dissected_last_seen": dissected_time,
        },
    ).to_knowledge_node()
    nodes.append(source_host)
    source_ip = IPv4Address(alert["src_ip"]).to_knowledge_node()
    nodes.append(source_ip)
    relations.append(
        KnowledgeRelation(
            label="has-address",
            source_node=source_host,
            target_node=source_ip,
        )
    )

    dest_host = Host(
        alert["dest_ip"],
        values={
            "last_seen": time_tripped,
            "dissected_last_seen": dissected_time,
        },
    ).to_knowledge_node()
    nodes.append(dest_host)
    dest_ip = IPv4Address(alert["dest_ip"]).to_knowledge_node()
    nodes.append(dest_ip)

    relations.append(
        KnowledgeRelation(
            label="has-address",
            source_node=dest_host,
            target_node=dest_ip,
        )
    )

    source_port = NetworkEndpoint(
        alert["src_ip"], alert["src_port"], alert["proto"], endpoint="source"
    )
    source_port_ref = source_port.to_network_port_ref()
    source_port_knowledge = source_port.to_knowledge_node()
    source_port_ref_knowledge = source_port_ref.to_knowledge_node()
    nodes.append(source_port_knowledge)
    nodes.append(source_port_ref_knowledge)
    relations.append(
        KnowledgeRelation(
            label="is-type",
            source_node=source_port_knowledge,
            target_node=source_port_ref_knowledge,
        )
    )

    dest_port = NetworkEndpoint(
        alert["dst_ip"], alert["dest_port"], alert["proto"], endpoint="dest"
    )
    dest_port_ref = dest_port.to_network_port_ref()
    dest_port_knowledge = dest_port.to_knowledge_node()
    dest_port_ref_knowledge = dest_port_ref.to_knowledge_node()
    nodes.append(dest_port_knowledge)
    nodes.append(dest_port_ref_knowledge)
    relations.append(
        KnowledgeRelation(
            label="is-type",
            source_node=dest_port_knowledge,
            target_node=dest_port_ref_knowledge,
        )
    )

    dissected_start = dissect_time(alert["flow"]["start"])

    network_flow = NetworkTraffic(
        int(alert["flow"]["pkts_toserver"]),
        int(alert["flow"]["bytes_toserver"]),
        int(alert["flow"]["start"]),
        values={
            "source": "suricata",
            "dissected_start": dissected_start,
        },
    ).to_knowledge_node()
    nodes.append(network_flow)

    relations.append(
        KnowledgeRelation(
            label="component-of",
            source_node=source_port,
            target_node=source_ip,
        )
    )
    relations.append(
        KnowledgeRelation(
            label="component-of",
            source_node=dest_port,
            target_node=dest_ip,
        )
    )
    relations.append(
        KnowledgeRelation(
            label="communicates-to",
            source_node=source_port,
            target_node=network_flow,
        )
    )
    relations.append(
        KnowledgeRelation(
            label="communicates-to",
            source_node=network_flow,
            target_node=dest_port,
        )
    )
    relations.append(
        KnowledgeRelation(
            label="triggered-by",
            source_node=alert_obj,
            target_node=network_flow,
        )
    )

    return nodes, relations


def antivirus_alert_to_knowledge(alert: Dict[str, Any]) -> Tuple[list, list]:
    nodes = []
    relations = []

    # The if statement is here for error handling the case where the VirusTotal
    # data isn't properly stored in the alert object and we get the "Not Available"
    # as specified in the Antivirus.py file. Otherwise, we'd have a bunch of errors
    # showing up anytime an API key was invalid or the VT servers are unavailable
    if alert["vt_crit"] == "Not Available":
        alert_obj = KnowledgeNode(
            label="Alert",
            name=str(uuid.uuid4()),
            values={
                "date": alert["date"],
            },
        )
        nodes.append(alert_obj)

        alert_signature = KnowledgeNode(
            label="AttackSignature",
            name=f"{alert['path']}: {alert['sig']}",
            values={
                "AVSignature": alert["sig"],
                "md5sum": alert["md5sum"],
            },
        )
        nodes.append(alert_signature)

    else:
        alert_obj = KnowledgeNode(
            label="Alert",
            name=str(uuid.uuid4()),
            values={
                "date": alert["date"],
                "vt_malicious_confidence": alert["vt_crit"],
            },
        )
        nodes.append(alert_obj)

        alert_signature = KnowledgeNode(
            label="AttackSignature",
            name=f"{alert['path']}: {alert['sig']}",
            values={
                "VTSuggestedLabel": alert["vt_sig"],
                "md5": alert["md5sum"],
                "ssdeep": alert["ssdeep"],
            },
        )
        nodes.append(alert_signature)

    relations.append(
        KnowledgeRelation(
            label="is-type",
            source_node=alert_obj,
            target_node=alert_signature,
        )
    )

    path = KnowledgeNode(
        label="FilePath",
        name=alert["path"],
    )
    nodes.append(path)

    hostname = Host(alert["hostname"]).to_knowledge_node()
    nodes.append(hostname)

    relations.append(
        KnowledgeRelation(
            label="triggered-by",
            source_node=alert_obj,
            target_node=path,
        )
    )

    relations.append(
        KnowledgeRelation(
            label="stored-on",
            source_node=path,
            target_node=hostname,
        )
    )

    return nodes, relations


def knowledge_to_neo(nodes: list = None, relations: list = None) -> bool:
    if nodes is None:
        nodes = list()

    if relations is None:
        relations = list()

    neo_host = os.getenv("NEO4J_HOST")
    neo_user = os.getenv("NEO4J_USER")
    neo_password = os.getenv("NEO4J_PASSWORD")

    graph = AicaNeo4j(host=neo_host, user=neo_user, password=neo_password)

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
