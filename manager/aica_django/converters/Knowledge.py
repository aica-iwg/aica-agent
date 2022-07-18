import dateparser
import ipaddress
import os
import re
import socket
import uuid

from aica_django.connectors.AicaNeo4j import (
    AicaNeo4j,
    defined_node_labels,
    defined_relation_labels,
)
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


# TODO: Define subclasses for types above (important ones, anyway)
class KnowledgeNode:
    name = None
    label = None
    values = dict()

    def __init__(self, label, name, values=None):
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

        if label == "MACAddress":
            name = normalize_mac_addr(name)
            values["value"] = name

        self.label = label
        self.name = name
        self.values = values


# TODO: Define subclasses for types above (important ones, anyway)
class KnowledgeRelation:
    label = None
    source_node = None
    source_label = None
    target_node = None
    target_label = None
    values = dict()

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
        if values and type(values) != dict:
            raise ValueError(f"Values must be a dictionary, not {type(values)}")

        self.label = label
        self.source_node = source_node.name
        self.source_label = source_node.label
        self.target_node = target_node.name
        self.target_label = target_node.label
        self.values = values


def normalize_mac_addr(mac_addr):
    return re.sub(r"[^A-Fa-f\d]", "", mac_addr).lower()


def netflow_to_knowledge(flow):
    nodes = []
    relations = []

    protocol = KnowledgeNode(
        label="NetworkProtocol",
        name=flow["PROTO"],
        values={"value": flow["PROTO"]},
    )
    nodes.append(protocol)

    # Create source host and port nodes (and link to protocol node)
    ipv4_src_addr = str(ipaddress.ip_address(flow["IPV4_SRC_ADDR"]))
    source_addr = KnowledgeNode(
        label="IPv4Address",
        name=ipv4_src_addr,
        values={"value": ipv4_src_addr},
    )
    nodes.append(source_addr)
    source_port = KnowledgeNode(
        label="NetworkPort",
        name=f"{ipv4_src_addr}:{flow['SRC_PORT']}",
        values={"value": flow["SRC_PORT"]},
    )
    nodes.append(source_port)
    relations.append(
        KnowledgeRelation(
            label="has-port",
            source_node=source_addr,
            target_node=source_port,
        )
    )

    source_host = KnowledgeNode(
        label="Host",
        name=ipv4_src_addr,
        values={"value": ipv4_src_addr},
    )
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
    dest_addr = KnowledgeNode(
        label="IPv4Address",
        name=ipv4_dst_addr,
        values={"value": ipv4_dst_addr},
    )
    nodes.append(dest_addr)
    dest_port = KnowledgeNode(
        label="NetworkPort",
        name=f"{ipv4_dst_addr}:{flow['DST_PORT']}",
        values={"value": flow["DST_PORT"]},
    )
    nodes.append(dest_port)
    relations.append(
        KnowledgeRelation(
            label="has-port",
            source_node=dest_addr,
            target_node=dest_port,
        )
    )

    if not (ipv4_dst_addr_obj.is_multicast or ipv4_dst_addr_obj.is_reserved):
        dest_host = KnowledgeNode(
            label="Host",
            name=ipv4_dst_addr,
            values={"value": ipv4_dst_addr},
        )
        nodes.append(dest_host)
        relations.append(
            KnowledgeRelation(
                label="has-address",
                source_node=dest_host,
                target_node=dest_addr,
            )
        )

    # Create NetworkTraffic node
    flow = KnowledgeNode(
        label="NetworkTraffic",
        name=str(uuid.uuid4()),
        values={
            "in_packets": flow["IN_PACKETS"],
            "in_octets": flow["IN_OCTETS"],
            "start": flow["FIRST_SWITCHED"],
            "end": flow["LAST_SWITCHED"],
            "flags": flow["TCP_FLAGS"],
            "tos": flow["TOS"],
            "source": "netflow",
        },
    )
    nodes.append(flow)
    relations.append(
        KnowledgeRelation(
            label="is-type",
            source_node=flow,
            target_node=protocol,
        )
    )
    relations.append(
        KnowledgeRelation(
            label="communicates-to",
            source_node=source_port,
            target_node=flow,
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


def nginx_accesslog_to_knowledge(log_dict):
    nodes = []
    relations = []

    my_hostname = socket.gethostname()
    my_ipv4 = KnowledgeNode(
        label="IPv4Address",
        name=socket.gethostbyname(my_hostname),
        values={"value": socket.gethostbyname(my_hostname)},
    )
    nodes.append(my_ipv4)

    request_time = dateparser.parse(log_dict["dateandtime"])

    # Add requesting host
    requesting_host = KnowledgeNode(
        label="Host",
        name=log_dict["src_ip"],
        values={
            "last_seen": request_time,
        },
    )
    nodes.append(requesting_host)

    # Add target NIC to target host
    nic = KnowledgeNode(
        label="NetworkInterface",
        name=str(uuid.uuid4()),
        values={"last_seen": request_time},
    )
    nodes.append(nic)
    relations.append(
        KnowledgeRelation(
            label="component-of",
            source_node=nic,
            target_node=requesting_host,
        )
    )

    ipv4_addr = KnowledgeNode(
        label="IPv4Address",
        name=log_dict["src_ip"],
        values={"value": log_dict["src_ip"]},
    )
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


def nmap_scan_to_knowledge(scan_results):
    nodes = []
    relations = []

    scan_time = scan_results["runtime"]["time"]

    # Not needed and make iteration below messy
    del scan_results["stats"]
    del scan_results["runtime"]

    my_hostname = socket.gethostname()
    my_ipv4 = KnowledgeNode(
        label="IPv4Address",
        name=socket.gethostbyname(my_hostname),
        values={"value": socket.gethostbyname(my_hostname)},
    )
    nodes.append(my_ipv4)

    for host, data in scan_results.items():
        if scan_results[host]["state"]["state"] != "up":
            continue

        # Add scan target
        target_host = KnowledgeNode(
            label="Host",
            name=host,
            values={
                "last_seen": scan_time,
                "state_reason": scan_results[host]["state"]["reason"],
                "state_reason_ttl": scan_results[host]["state"]["reason_ttl"],
            },
        )
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
        ipv4_addr = KnowledgeNode(
            label="IPv4Address",
            name=host,
            values={"value": host},
        )
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
                values={"value": scan_results[host]["macaddress"]["addr"]},
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
                    values={"vendor": scan_results[host]["macaddress"]["vendor"]},
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
                values={"type": hostname["type"], "value": hostname["name"]},
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
                    label="Vendor", name=os_match["osclass"]["vendor"]
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
                open_port = KnowledgeNode(
                    label="NetworkPort",
                    name=f"{host}:{port['portid']}",
                    values={
                        "port_number": port["portid"],
                        "service_name": port["service"]["name"],
                    },
                )
                nodes.append(open_port)
                protocol = KnowledgeNode(
                    label="NetworkProtocol",
                    name=port["protocol"],
                )
                nodes.append(protocol)
                relations.append(
                    KnowledgeRelation(
                        label="has-port",
                        source_node=ipv4_addr,
                        target_node=open_port,
                        values={"last_seen": scan_time, "status": "open"},
                    )
                )

    return nodes, relations


def suricata_alert_to_knowledge(alert):
    nodes = []
    relations = []

    alert_obj = KnowledgeNode(
        label="Alert",
        name=str(uuid.uuid4()),
        values={
            "time_tripped": alert["timestamp"],
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
            # "metadata": alert["alert"]["metadata"],
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
        label="AttackSignatureCategory", name=alert["alert"]["category"]
    )
    nodes.append(alert_category)
    relations.append(
        KnowledgeRelation(
            label="member-of",
            source_node=alert_signature,
            target_node=alert_category,
        )
    )

    source_host = KnowledgeNode(
        label="Host",
        name=alert["src_ip"],
    )
    nodes.append(source_host)
    source_ip = KnowledgeNode(
        label="IPv4Address",
        name=alert["src_ip"],
    )
    nodes.append(source_ip)
    relations.append(
        KnowledgeRelation(
            label="has-address",
            source_node=source_host,
            target_node=source_ip,
        )
    )
    dest_host = KnowledgeNode(
        label="Host",
        name=alert["dest_ip"],
    )
    nodes.append(dest_host)
    dest_ip = KnowledgeNode(
        label="IPv4Address",
        name=alert["dest_ip"],
    )
    nodes.append(dest_ip)

    relations.append(
        KnowledgeRelation(
            label="has-address",
            source_node=dest_host,
            target_node=dest_ip,
        )
    )

    source_port = KnowledgeNode(
        label="NetworkPort",
        name=f"{alert['src_ip']}:{alert['src_port']}",
        values={
            "port_number": alert["src_port"],
        },
    )
    nodes.append(source_port)

    dest_port = KnowledgeNode(
        label="NetworkPort",
        name=f"{alert['dest_ip']}:{alert['dest_port']}",
        values={
            "port_number": alert["dest_port"],
        },
    )
    nodes.append(dest_port)

    protocol = KnowledgeNode(
        label="NetworkProtocol",
        name=alert["proto"],
    )
    nodes.append(protocol)

    network_flow = KnowledgeNode(
        label="NetworkTraffic",
        name=str(uuid.uuid4()),
        values={
            "pkts_toserver": alert["flow"]["pkts_toserver"],
            "pkts_toclient": alert["flow"]["pkts_toclient"],
            "bytes_toserver": alert["flow"]["bytes_toserver"],
            "bytes_toclient": alert["flow"]["bytes_toclient"],
            "start": alert["flow"]["start"],
            "source": "suricata",
        },
    )
    nodes.append(network_flow)

    relations.append(
        KnowledgeRelation(
            label="is-type",
            source_node=network_flow,
            target_node=protocol,
        )
    )
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


def antivirus_alert_to_knowledge(alert):
    nodes = []
    relations = []

    # The if statement is here for error handling the case where the VirusTotal 
    # data isn't properly stored in the alert object and we get the "Not Available" 
    # as specified in the Antivirus.py file. Otherwise, we'd have a bunch of errors 
    # showing up anytime an API key was wrong or the VT servers go down
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
                "ssdeep": alert["ssdeep"]
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

    hostname = KnowledgeNode(
        label="Host",
        name=alert["hostname"],
    )
    nodes.append(hostname)

    ip_addr = KnowledgeNode(
        label="IPv4Address",
        name=alert["ip_addr"],
    )
    nodes.append(ip_addr)    

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

    relations.append(
        KnowledgeRelation(
            label="has-address",
            source_node=hostname,
            target_node=ip_addr,
        )
    )

    return nodes, relations


def knowledge_to_neo(nodes=None, relations=None):
    neo_host = os.getenv("NEO4J_HOST")
    neo_user = os.getenv("NEO4J_USER")
    neo_password = os.getenv("NEO4J_PASSWORD")

    graph = AicaNeo4j(host=neo_host, user=neo_user, password=neo_password)

    for node in nodes:
        graph.add_node(
            node.name,
            node.label,
            node.values,
        )

    for relation in relations:
        graph.add_relation(
            relation.source_node,
            relation.source_label,
            relation.target_node,
            relation.target_label,
            relation.label,
            relation.values,
        )
