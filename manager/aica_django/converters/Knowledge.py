import logging
import re
import socket

from aica_django.connectors.AicaNeo4j import AicaNeo4j

# Try to keep these as minimal and orthogonal as possible
defined_node_labels = [
    "AutonomousSystemNumber",
    "DNSRecord",
    "Firmware",
    "PhysicalLocation",
    "Host",
    "Identity",  # i.e., an actual human
    "IPv4Address",
    "IPv6Address",
    "MACAddress",
    "NetworkInterface",
    "NetworkPort",
    "Organization",  # e.g., corporation, agency
    "Process",
    "Subnet",
    "Software",
    "User",  # i.e., principal on a system
    "Vendor",
]
defined_relation_labels = [
    "connected-to",
    "communicates-to",
    "component-of",
    "has-address",
    "open-on",
    "located-in",
    "manufactures",
    "member-of",
    "resides-in",
    "resolves-to",
    "runs-on",
    "used-by",
    "works-in",
]


class KnowledgeNode:
    name = None
    label = None
    values = dict()

    def __init__(self, label, name, values=None):
        if label not in defined_node_labels:
            raise ValueError(f"Unsupported node label {label} for {name}")

        if type(label) != str or label == "":
            raise ValueError(f"Label must be a string, not {type(label)}")
        if type(name) != str or name == "":
            raise ValueError(f"Name must be a string, not {type(name)}")
        if values and type(values) != dict:
            raise ValueError(f"Values must be a dictionary, not {type(values)}")

        if label == "MACAddress":
            name = normalize_mac_addr(name)
            values["value"] = name

        self.label = label
        self.name = name
        self.values = values


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


def nmap_to_knowledge(scan_results):
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
        if scan_results[host]["macaddress"]:
            mac_label = (
                scan_results[host]["macaddress"]["addr"]
                if "addr" in scan_results[host]["macaddress"]
                else None
            )
            nic_label = f"{host}-{mac_label}"
        else:
            nic_label = host
        nic = KnowledgeNode(
            label="NetworkInterface",
            name=nic_label,
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
                    name=f"{port['portid']}/{port['protocol']}",
                    values={
                        "port_number": port["portid"],
                        "protocol": port["protocol"],
                        "service_name": port["service"]["name"],
                    },
                )
                port_ip_rel = KnowledgeRelation(
                    label="open-on",
                    source_node=open_port,
                    target_node=ipv4_addr,
                    values={"last_seen": scan_time},
                )
                nodes.append(open_port)
                relations.append(port_ip_rel)

    return nodes, relations


def knowledge_to_neo(
    neo_host=None, neo_user=None, neo_password=None, nodes=None, relations=None
):
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
