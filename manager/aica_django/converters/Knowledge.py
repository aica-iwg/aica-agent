import logging
import os
import re
import socket
import uuid

from aica_django.connectors.AicaNeo4j import (
    AicaNeo4j,
    defined_node_labels,
    defined_relation_labels,
)


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


def nmap_scan_to_knowledge(scan_results):
    if scan_results is None:
        logging.warning("Tried to convert empty scan results to STIX")
        return False

    scan_time = scan_results["runtime"]["time"]

    # Not needed and make iteration below messy
    del scan_results["stats"]
    del scan_results["runtime"]

    nodes = []
    relations = []

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
        nic_host_rel = KnowledgeRelation(
            label="component-of",
            source_node=nic,
            target_node=target_host,
        )
        nodes.append(nic)
        relations.append(nic_host_rel)

        # Add target IPv4 to NIC
        ipv4_addr = KnowledgeNode(
            label="IPv4Address",
            name=host,
            values={"value": host},
        )
        ip_nic_rel = KnowledgeRelation(
            label="has-address",
            source_node=nic,
            target_node=ipv4_addr,
        )
        nodes.append(ipv4_addr)
        relations.append(ip_nic_rel)

        if scan_results[host]["macaddress"]:
            # Add MAC to NIC
            mac_addr = KnowledgeNode(
                label="MACAddress",
                name=scan_results[host]["macaddress"]["addr"],
                values={"value": scan_results[host]["macaddress"]["addr"]},
            )
            nic_mac_rel = KnowledgeRelation(
                label="has-address",
                source_node=nic,
                target_node=mac_addr,
            )
            nodes.append(mac_addr)
            relations.append(nic_mac_rel)

            if "vendor" in scan_results[host]["macaddress"]:
                # Add firmware to NIC
                nic_manufacturer = KnowledgeNode(
                    label="Vendor",
                    name=f"{scan_results[host]['macaddress']['vendor']}",
                    values={"vendor": scan_results[host]["macaddress"]["vendor"]},
                )
                nic_firmware_rel = KnowledgeRelation(
                    label="manufactures",
                    source_node=nic_manufacturer,
                    target_node=nic,
                )
                nodes.append(nic_manufacturer)
                relations.append(nic_firmware_rel)

        for hostname in scan_results[host]["hostname"]:
            domain_name = KnowledgeNode(
                label="DNSRecord",
                name=hostname["name"],
                values={"type": hostname["type"], "value": hostname["name"]},
            )
            domain_source_node = None
            domain_target_node = None
            if hostname["type"] in ["A", "AAAA", "user"]:
                domain_source_node = domain_name
                domain_target_node = ipv4_addr
            elif hostname["type"] == "PTR":
                domain_source_node = ipv4_addr
                domain_target_node = domain_name
            domain_ip_rel = KnowledgeRelation(
                label="resolves-to",
                source_node=domain_source_node,
                target_node=domain_target_node,
            )
            nodes.append(domain_name)
            relations.append(domain_ip_rel)

        if len(scan_results[host]["osmatch"]) > 1:
            os = scan_results[host]["osmatch"][0]
            operating_system = KnowledgeNode(
                label="Software",
                name=os["cpe"] if os["cpe"] else os["name"],
                values={"name": os["name"], "version": os["osclass"]["osgen"]},
            )
            host_os_rel = KnowledgeRelation(
                label="runs-on",
                source_node=operating_system,
                target_node=target_host,
            )
            nodes.append(operating_system)
            relations.append(host_os_rel)

            if os["osclass"]["vendor"]:
                os_vendor = KnowledgeNode(label="Vendor", name=os["osclass"]["vendor"])
                os_vendor_rel = KnowledgeRelation(
                    label="manufactures",
                    source_node=os_vendor,
                    target_node=operating_system,
                )
                nodes.append(os_vendor)
                relations.append(os_vendor_rel)

        for port in scan_results[host]["ports"]:
            if port["state"] == "open":
                open_port = KnowledgeNode(
                    label="NetworkPort",
                    name=port["portid"],
                    values={
                        "port_number": port["portid"],
                        "service_name": port["service"]["name"],
                    },
                )
                protocol = KnowledgeNode(
                    label="NetworkProtocol",
                    name=port["protocol"],
                )
                port_proto_rel = KnowledgeRelation(
                    label="is-type",
                    source_node=open_port,
                    target_node=protocol,
                )
                port_ip_rel = KnowledgeRelation(
                    label="component-of",
                    source_node=open_port,
                    target_node=ipv4_addr,
                    values={"last_seen": scan_time, "status": "open"},
                )
                nodes.append(open_port)
                relations.extend([port_ip_rel, port_proto_rel])

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

    alert_signature_rel = KnowledgeRelation(
        label="is-type",
        source_node=alert_obj,
        target_node=alert_signature,
    )
    relations.append(alert_signature_rel)

    alert_category = KnowledgeNode(
        label="AttackSignatureCategory", name=alert["alert"]["category"]
    )
    nodes.append(alert_category)
    alert_category_rel = KnowledgeRelation(
        label="member-of",
        source_node=alert_signature,
        target_node=alert_category,
    )
    relations.append(alert_category_rel)

    source_host = KnowledgeNode(
        label="Host",
        name=alert["src_ip"],
    )
    source_ip = KnowledgeNode(
        label="IPv4Address",
        name=alert["src_ip"],
    )
    source_ip_rel = KnowledgeRelation(
        label="has-address",
        source_node=source_host,
        target_node=source_ip,
    )
    dest_host = KnowledgeNode(
        label="Host",
        name=alert["dest_ip"],
    )
    dest_ip = KnowledgeNode(
        label="IPv4Address",
        name=alert["dest_ip"],
    )
    dest_ip_rel = KnowledgeRelation(
        label="has-address",
        source_node=dest_host,
        target_node=dest_ip,
    )
    nodes.extend([source_host, source_ip, dest_host, dest_ip])
    relations.extend([source_ip_rel, dest_ip_rel])

    source_port = KnowledgeNode(
        label="NetworkPort",
        name=alert["src_port"],
        values={
            "port_number": alert["src_port"],
        },
    )
    dest_port = KnowledgeNode(
        label="NetworkPort",
        name=alert["dest_port"],
        values={
            "port_number": alert["dest_port"],
        },
    )
    protocol = KnowledgeNode(
        label="NetworkProtocol",
        name=alert["proto"],
    )
    network_flow = KnowledgeNode(
        label="NetworkTraffic",
        name=str(uuid.uuid4()),
        values={
            "pkts_toserver": alert["flow"]["pkts_toserver"],
            "pkts_toclient": alert["flow"]["pkts_toclient"],
            "bytes_toserver": alert["flow"]["bytes_toserver"],
            "bytes_toclient": alert["flow"]["bytes_toclient"],
            "start": alert["flow"]["start"],
        },
    )
    nodes.extend([network_flow, source_port, dest_port, protocol])

    network_proto_rel = KnowledgeRelation(
        label="is-type",
        source_node=network_flow,
        target_node=protocol,
    )
    src_port_ip_rel = KnowledgeRelation(
        label="component-of",
        source_node=source_port,
        target_node=source_ip,
    )
    dest_port_ip_rel = KnowledgeRelation(
        label="component-of",
        source_node=dest_port,
        target_node=dest_ip,
    )
    network_src_rel = KnowledgeRelation(
        label="communicates-to",
        source_node=source_port,
        target_node=network_flow,
    )
    network_dest_rel = KnowledgeRelation(
        label="communicates-to",
        source_node=network_flow,
        target_node=dest_port,
    )
    network_alert_rel = KnowledgeRelation(
        label="triggered-by",
        source_node=alert_obj,
        target_node=network_flow,
    )
    relations.extend(
        [
            src_port_ip_rel,
            dest_port_ip_rel,
            network_src_rel,
            network_dest_rel,
            network_alert_rel,
            network_proto_rel,
        ]
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
