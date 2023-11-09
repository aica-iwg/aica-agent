"""
This module defines objects representing nodes and relations in the Knowledge graph, and functions for
handling them (e.g., parsing/converting).

Functions:
    antivirus_alert_to_knowledge: Converts an alert from the antivirus system to STIX objects 
    netflow_to_knowledge: Converts a network flow record to STIX objects 
    nginx_accesslog_to_knowledge: Converts an HTTP access log entry to STIX objects
    nmap_scan_to_knowledge: Converts a network scan result to STIX objects
    suricata_alert_to_knowledge: Converts an alert from the IDS to STIX objects 
    knowledge_to_neo: Stores lists of STIX objects in the knowledge graph database
    normalize_mac_addr: Converts MAC address to standard lowercase hex value without separators
    dissect_time: Converts a timestamp value into a dictionary of time attributes potential relevant for classification

"""

import dateparser
import datetime
import ipaddress
import json
import pytz
import re
import socket

from celery.utils.log import get_task_logger
from stix2.base import _STIXBase
from stix2 import (
    AttackPattern,
    Directory,
    DomainName,
    File,
    HTTPRequestExt,
    Indicator,
    Infrastructure,
    ICMPExt,
    IPv4Address,
    IPv6Address,
    Malware,
    MACAddress,
    NetworkTraffic,
    Note,
    ObservedData,
    Relationship,
    Sighting,
    SocketExt,
    Software,
    TCPExt,
)
from typing import Any, Dict, List, Optional, Union

from aica_django.connectors.GraphDatabase import AicaNeo4j


logger = get_task_logger(__name__)

graph = AicaNeo4j()


def get_or_create_ipv4(ip_addr: str):
    ip_addresses = graph.get_ipv4_by_addr(ip_addr)
    if len(ip_addresses) > 0:
        ip_address = ip_addresses[0]
    else:
        ip_address = IPv4Address(value=ip_addr)

    return ip_address


def get_or_create_ipv6(ip_addr: str):
    ip_addresses = graph.get_ipv6_by_addr(ip_addr)
    if len(ip_addresses) > 0:
        ip_address = ip_addresses[0]
    else:
        ip_address = IPv6Address(value=ip_addr)

    return ip_address


def get_or_create_attack_pattern(attack_pattern: str):
    attack_patterns = graph.get_attack_pattern_by_name(attack_pattern)
    if len(attack_patterns) > 0:
        ap = attack_patterns[0]
    else:
        ap = AttackPattern(name=attack_pattern)

    return ap


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
) -> List[Union[NetworkTraffic, IPv4Address, IPv6Address]]:
    """
    Converts a netflow dictionary (from the Python netflow library) to knowledge objects.

    @param flow: A netflow dictionary to be converted to knowledge objects
    @type flow: Dict[str, str]
    @return: Knowledge nodes resulting form this conversion
    @rtype: list
    """

    knowledge_nodes = []

    # Create source host and port nodes (and link to protocol node)
    if "IPV4_SRC_ADDR" in flow and flow["IPV4_SRC_ADDR"] is not None:
        ip_src_addr = str(ipaddress.ip_address(flow["IPV4_SRC_ADDR"]))
        source_addr = get_or_create_ipv4(ip_src_addr)

        ip_dst_addr = str(ipaddress.ip_address(flow["IPV4_DST_ADDR"]))
        dest_addr = get_or_create_ipv4(ip_dst_addr)

    elif "IPV6_SRC_ADDR" in flow and flow["IPV6_SRC_ADDR"] is not None:
        ip_src_addr = str(ipaddress.ip_address(flow["IPV4_SRC_ADDR"]))
        source_addr = get_or_create_ipv6(ip_src_addr)

        ip_dst_addr = str(ipaddress.ip_address(flow["IPV4_DST_ADDR"]))
        dest_addr = get_or_create_ipv6(ip_dst_addr)

    knowledge_nodes.append(source_addr)
    knowledge_nodes.append(dest_addr)

    params = {
        "protocols": [flow["PROTO"]],
        "src_ref": source_addr.id,
        "src_port": flow["SRC_PORT"],
        "src_packets": flow["IN_PACKETS"],
        "src_byte_count": flow["IN_OCTETS"],
        "dst_ref": dest_addr.id,
        "dst_port": flow["DST_PORT"],
        "start": float(flow["FIRST_SWITCHED"]),
        "end": float(flow["LAST_SWITCHED"]),
    }

    if flow["PROTO"] == "icmp":
        traffic = ICMPExt(
            **params
        )
    elif flow["PROTO"] == "tcp":
        traffic = TCPExt(
            **params
        )
    else:
        traffic = NetworkTraffic(
            **params
        )

    knowledge_nodes.append(traffic)

    dst_port_notes = graph.get_port_note(flow["DST_PORT"], flow["PROTO"])
    if len(dst_port_notes) > 0:
        dst_port_note = dst_port_notes[0]
        dst_port_note["object_refs"].append(traffic.id)
        knowledge_nodes.append(dst_port_note)

    return knowledge_nodes


def nginx_accesslog_to_knowledge(
    log_dict: Dict[str, Any]
) -> List[Union[IPv4Address, IPv6Address, HTTPRequestExt]]:
    """
    Converts an HTTP access log dictionary (as returned by aica_django.connectors.Nginx.poll_nginx_accesslogs)
    to knowledge objects.

    @param log_dict: An HTTP access log dictionary to be converted to knowledge objects
    @type log_dict: Dict[str, Any]
    @return: Knowledge nodes resulting form this conversion
    @rtype: list
    """

    knowledge_nodes = []

    # dateparser can't seem to handle this format
    request_time = datetime.datetime.strptime(
        log_dict["dateandtime"], "%d/%b/%Y:%H:%M:%S %z"
    )

    if not request_time:
        raise ValueError(f"Couldn't parse timestamp {log_dict['dateandtime']}")

    # Create source host and port nodes (and link to protocol node)
    ip_src_addr = str(ipaddress.ip_address(log_dict["src_ip"]))
    if ip_src_addr.version == 4:
        source_addr = get_or_create_ipv4(ip_src_addr)
    elif ip_src_addr.version == 6:
        source_addr = get_or_create_ipv6(ip_src_addr)
    else:
        raise ValueError(
            f"Unsupported ip type {ip_src_addr.version} for {log_dict['src_ip']}"
        )
    knowledge_nodes.append(source_addr)

    if log_dict["server_ip"] is not None:
        ip_dst_addr = str(ipaddress.ip_address(log_dict["server_ip"]))
        if ip_dst_addr.version == 4:
            dest_addr = get_or_create_ipv4(ip_dst_addr)
        elif ip_dst_addr.version == 6:
            dest_addr = get_or_create_ipv6(ip_dst_addr)
        else:
            raise ValueError(
                f"Unsupported ip type {ip_dst_addr.version} for {log_dict['server_ip']}"
            )
        knowledge_nodes.append(dest_addr)
    else:
        dest_addr = None

    traffic = HTTPRequestExt(
        start=request_time,
        src_ref=source_addr.id,
        dst_ref=dest_addr.id if dest_addr else None,
        request_method=log_dict["method"],
        request_value=log_dict["url"],
        dst_byte_count=log_dict["bytes_sent"],
        request_header={
            "User-Agent": log_dict["useragent"],
            "Referer": log_dict["referer"],
        },
    )
    knowledge_nodes.append(traffic)

    http_status_abstract = f"status: {log_dict['status']}"

    http_statuses = graph.get_note_by_abstract(http_status_abstract)
    if len(http_statuses) > 0:
        http_status = http_statuses[0]
        http_status["object_refs"].append(traffic.id)
    else:
        http_status = Note(
            abstract=f"status: {log_dict['status']}",
            content=json.dumps({"status": log_dict["status"]}),
            object_refs=[traffic.id],
        )

    knowledge_nodes.append(http_status)

    return knowledge_nodes


def caddy_accesslog_to_knowledge(log_dict: Dict[str, Any]) -> List[_STIXBase]:
    """
    Converts an HTTP access log dictionary (as returned by aica_django.connectors.CaddyServer.poll_caddy_accesslogs)
    to knowledge objects.

    @param log_dict: An HTTP access log dictionary to be converted to knowledge objects
    @type log_dict: Dict[str, Any]
    @return: Knowledge nodes resulting from this conversion
    @rtype: list
    """

    knowledge_nodes = []

    # dateparser can't seem to handle this format
    request_time = datetime.datetime.strptime(log_dict["ts"], "%d/%b/%Y:%H:%M:%S %z")

    if not request_time:
        raise ValueError(f"Couldn't parse timestamp {log_dict['ts']}")

    if type(ipaddress.ip_address(log_dict["src_ip"])) is ipaddress.IPv4Address:
        src_ip = get_or_create_ipv4(log_dict["src_ip"])
    elif type(ipaddress.ip_address(log_dict["src_ip"])) is ipaddress.IPv6Address:
        src_ip = get_or_create_ipv6(log_dict["src_ip"])
    else:
        raise Exception(
            f"Unhandled address type: {type(ipaddress.ip_address(log_dict['src_ip'])) }"
        )

    knowledge_nodes.append(src_ip)

    try:
        # TODO See if port is in the Caddy log once this is running
        dst_ip = socket.getaddrinfo(log_dict["request"]["host"], port=None)[4]
        if type(ipaddress.ip_address(log_dict["src_ip"])) is ipaddress.IPv4Address:
            dst_ip = get_or_create_ipv4(log_dict["dst_ip"])
        elif type(ipaddress.ip_address(log_dict["src_ip"])) is ipaddress.IPv6Address:
            dst_ip = get_or_create_ipv6(log_dict["dst_ip"])
        else:
            raise Exception(
                f"Unhandled address type: {type(ipaddress.ip_address(log_dict['dst_ip'])) }"
            )
    except OSError as e:
        logger.warning(e)
        dst_ip = None

    knowledge_nodes.append(dst_ip)

    traffic = HTTPRequestExt(
        start=request_time,
        src_ref=src_ip.id,
        dst_ref=dst_ip.id if dst_ip else None,
        request_method=log_dict["request"]["method"],
        request_value=log_dict["url"],
        dst_byte_count=log_dict["request"]["host"] + log_dict["uri"],
        request_header={
            "User-Agent": log_dict["request"]["headers"]["User-Agent"],
            "Referer": log_dict["request"]["headers"]["Referer"],
        },
        custom_properties={
            "caddy_id": log_dict["id"],
            "http_response_stats": log_dict["status"],
        },
    )
    knowledge_nodes.append(traffic)

    return knowledge_nodes


def nmap_scan_to_knowledge(scan_results: Dict[str, Any]) -> List[_STIXBase]:
    """
    Converts an nmap scan result (from the Python nmap3 library) to knowledge objects.

    @param scan_results: A dictionary as returned by nmap3 to be converted to knowledge objects
    @type scan_results: Dict[str, str]
    @return: Knowledge nodes resulting form this conversion
    @rtype: list
    """

    knowledge_nodes = []

    scan_time: Optional[datetime.datetime] = dateparser.parse(
        scan_results["runtime"]["time"]
    )

    # Not needed and makes iteration below messy
    if "stats" in scan_results:
        del scan_results["stats"]

    if "runtime" in scan_results:
        del scan_results["runtime"]

    my_hostname = socket.gethostname()
    try:
        source_addr = get_or_create_ipv4(socket.gethostbyname(my_hostname))
    except:
        source_addr = get_or_create_ipv6(
            socket.getaddrinfo(my_hostname, None, socket.AF_INET6)[0][4][0]
        )

    knowledge_nodes.append(source_addr)

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

        mac_addr = None
        if scan_results[host]["macaddress"]:
            mac_addr = MACAddress(value=scan_results[host]["macaddress"])
            knowledge_nodes.append(mac_addr)

            vendor_abstract = f"vendor: {scan_results[host]['vendor']}"
            vendors = graph.get_note_by_abstract(vendor_abstract)
            if len(vendors) > 0:
                vendor_note = vendors[0]
                vendor_note["object_refs"].append(mac_addr.id)
            else:
                vendor_note = Note(
                    abstract=vendor_abstract,
                    content=json.dumps({"vendor": scan_results[host]["vendor"]}),
                    object_refs=[mac_addr.id],
                )

            knowledge_nodes.append(vendor_note)

        ip_addr = ipaddress.ip_address(host)
        if ip_addr.version == 4:
            dest_addr = get_or_create_ipv4(str(ip_addr))
            if mac_addr:
                dest_addr["resolves_to_refs"] = [mac_addr.id]
        elif ip_addr.version == 6:
            dest_addr = get_or_create_ipv6(str(ip_addr))
        else:
            raise ValueError(
                f"Unsupported ip type {type(ipaddress.ip_address(host)) } for {host}"
            )

        knowledge_nodes.append(dest_addr)

        for hostname in scan_results[host]["hostname"]:
            domain_name = DomainName(value=hostname["name"], resolves_to=dest_addr.id)
            knowledge_nodes.append(domain_name)

        if len(scan_results[host]["osmatch"]) > 1:
            os_match = scan_results[host]["osmatch"][0]
            operating_system = Software(
                name=os_match["name"],
                cpe=os_match["cpe"] if os_match["cpe"] else "unknown",
                version=os_match["osclass"]["osgen"],
                vendor=os_match["osclass"]["vendor"],
            )
            knowledge_nodes.append(operating_system)

        target_host = Infrastructure(
            name=str(host),
            consists_of=[mac_addr.id, operating_system.id],
            infrastructure_type_ov="unknown",
            last_seen=scan_time,
        )
        knowledge_nodes.append(target_host)

        for port in scan_results[host]["ports"]:
            if port["state"] == "open":
                open_port = SocketExt(
                    is_listening=True,
                    dst_port=port["portid"],
                    dst_ref=target_host.id,
                    protocols=[port["protocol"]],
                )
            knowledge_nodes.append(open_port)

            dst_port_notes = graph.get_port_note(port["portid"], port["protocol"])
            if len(dst_port_notes) > 0:
                dst_port_note = dst_port_notes[0]
                dst_port_note["object_refs"].append(open_port.id)
                knowledge_nodes.append(dst_port_note)

    return knowledge_nodes


def suricata_alert_to_knowledge(alert: Dict[str, Any]) -> List[_STIXBase]:
    """
    Converts a Suricata alert (as returned from aica_django.connectors.Suricata.poll_suricata_alerts)
    to knowledge objects.

    @param alert: A dictionary as returned by poll_suricata_alerts to be converted to knowledge objects
    @type alert: Dict[str, Any]
    @return: Knowledge nodes resulting form this conversion
    @rtype: list
    """

    knowledge_nodes = []

    alert_dt: Optional[datetime.datetime] = dateparser.parse(alert["timestamp"])
    assert alert_dt is not None

    if type(ipaddress.ip_address(alert["src_ip"])) is ipaddress.IPv4Address:
        source_ip = get_or_create_ipv4(str(alert["src_ip"]))
        dest_ip = get_or_create_ipv4(str(alert["dest_ip"]))
    elif type(ipaddress.ip_address(alert["src_ip"])) is ipaddress.IPv6Address:
        source_ip = get_or_create_ipv6(str(alert["src_ip"]))
        dest_ip = get_or_create_ipv6(str(alert["dest_ip"]))

    knowledge_nodes.append(source_ip)
    knowledge_nodes.append(dest_ip)

    params = {
        "protocols": [alert["proto"]],
        "src_ref": source_ip.id,
        "src_port": alert["src_port"],
        "dst_ref": dest_ip.id,
        "dst_port": alert["dest_port"],
        "start": alert_dt.timestamp(),
        "end": alert_dt.timestamp(),
    }

    if alert["proto"] == "icmp":
        traffic = ICMPExt(
            kwargs=params,
        )
    elif alert["proto"] == "tcp":
        traffic = TCPExt(
            kwargs=params,
        )
    else:
        traffic = NetworkTraffic(
            kwargs=params,
        )
    knowledge_nodes.append(traffic)

    dst_port_notes = graph.get_port_note(alert["dest_port"], alert["proto"])
    if len(dst_port_notes) > 0:
        dst_port_note = dst_port_notes[0]
        dst_port_note["object_refs"].append(traffic.id)
        knowledge_nodes.append(dst_port_note)

    alert = ObservedData(
        first_observed=alert["timestamp"],
        last_observed=alert["timestamp"],
        number_observed=1,
        object_refs=[traffic.id],
    )
    knowledge_nodes.append(alert)

    alert_name = f"suricata:{alert['alert']['signature_id']}/{alert['alert']['rev']}"

    # Check for existing indicator in DB. Create if it doesn't exist, reference if it does.
    alert_sigs = graph.get_indicators_by_name(alert_name)
    if len(alert_sigs) == 0:
        attack_patterns = graph.get_attack_pattern_by_name(alert["alert"]["category"])
        if len(attack_patterns) == 0:
            attack_pattern = AttackPattern(
                name=alert["alert"]["category"],
            )
            knowledge_nodes.append(attack_pattern)
        else:
            attack_pattern = attack_patterns[0]

        indicator = Indicator(
            name=alert_name,
            description=alert["alert"]["signature"],
            pattern="Not Provided",  # Required field, but we don't have this info
            pattern_type="suricata",
            pattern_version=alert["alert"]["rev"],
            indicates=attack_pattern.id,
        )
        knowledge_nodes.append(indicator)
    else:
        indicator = alert_sigs[0]

    sighting = Sighting(
        description="suricata_alert",
        last_seen=alert["timestamp"],
        count=1,
        observed_data_refs=[alert.id],
        sighting_of_ref=indicator.id,
    )
    knowledge_nodes.append(sighting)

    return knowledge_nodes


def clamav_alert_to_knowledge(alert: Dict[str, Any]) -> List[_STIXBase]:
    """
    Converts an antivirus alert (as returned from aica_django.connectors.Antivirus.poll_antivirus_alerts)
    to knowledge objects.

    @param alert: A dictionary as returned by poll_antivirus_alerts to be converted to knowledge objects
    @type alert: Dict[str, Any]
    @return: Knowledge nodes resulting form this conversion
    @rtype: list
    """

    knowledge_nodes = []
    timestamp = dateparser.parse(alert["date"])
    alert_name = f"clamav:{alert['signature']}/{alert['revision']}"

    directory_path = "/".join(alert["path"].split("/")[:-1])
    file_name = alert["path"].split("/")[-1]

    directory = Directory(path=directory_path)
    knowledge_nodes.append(directory)

    file = File(name=file_name, parent_directory_ref=directory.id)
    knowledge_nodes.append(file)

    alert_indicator = Indicator(
        name=alert_name,
        values={
            "platform": alert["platform"],
            "name": alert["name"],
        },
    )
    knowledge_nodes.append(alert_indicator)

    platform = Software(name=alert["platform"])
    knowledge_nodes.append(platform)

    malware = Malware(
        name=alert_name,
        description=alert["name"],
        is_family=False,
        operating_system_refs=[platform.id],
        sample_refs=[file.id],
    )
    knowledge_nodes.append(malware)

    attack_pattern = AttackPattern(name=f"clamav:{alert['category']}")
    knowledge_nodes.append(attack_pattern)

    malware_pattern_rel = Relationship(
        relationship_type="delivers",
        source_ref=attack_pattern.id,
        target_ref=malware.id,
    )
    knowledge_nodes.append(malware_pattern_rel)

    host = Infrastructure(
        name=alert["hostname"],
        infrastructure_types=["workstation"],
        last_seen=timestamp,
    )
    knowledge_nodes.append(host)

    sighting = Sighting(
        description="clamav_alert",
        last_seen=timestamp,
        count=1,
        observed_data_refs=[file.id],
        sighting_of_ref=alert_indicator.id,
        where_sighted_refs=[host.id],
    )
    knowledge_nodes.append(sighting)

    return knowledge_nodes


def waf_alert_to_knowledge(alert: Dict[str, Any]) -> List[_STIXBase]:
    """
    Converts an waf alert (as returned from aica_django.connectors.WAF.poll_waf_alerts)
    to knowledge objects.

    @param alert: A dictionary as returned by poll_waf_alerts to be converted to knowledge objects
    @type alert: Dict[str, Any]
    @return: Knowledge nodes resulting from this conversion
    @rtype: list
    """

    knowledge_nodes = []

    # alert_dt: Optional[datetime.datetime] = dateparser.parse(alert["timestamp"])
    alert_dt = float(alert["ts"])
    assert alert_dt is not None

    alert_name = f"owasp_crs:{alert['id']}/{alert['rev']}"
    alert_indicator = Indicator(
        name=alert_name,
        description=alert["data"],
        pattern="Not specified",
        pattern_type="owasp_crs",
        valid_from=alert_dt,
    )
    knowledge_nodes.append(alert_indicator)

    for tag in alert["tags"]:
        ap = get_or_create_attack_pattern(tag)
        ap_rel = Relationship(alert_indicator.id, "indicates", ap.id)
        knowledge_nodes.append(ap_rel)

    # Make Cypher query and return node that contains the correct unique ID
    http_req_nodes = list(
        graph.graph.run(
            f"MATCH (n:HttpRequest) WHERE n.caddy_id = \"{alert['unique_id']}\" RETURN n"
        )
    )

    sighting = Sighting(
        description="waf_alert",
        last_seen=alert_dt,
        count=1,
        observed_data_refs=[http_req_nodes[0].id] if len(http_req_nodes) > 0 else [],
        sighting_of_ref=alert_indicator.id,
    )
    knowledge_nodes.append(sighting)

    return knowledge_nodes


def knowledge_to_neo(
    nodes: List[_STIXBase],
) -> bool:
    """
    Stores STIX objects in the knowledge graph database. This assumes all references
    refer to nodes that will exist after provided nodes have all been created.

    @param nodes: STIX Objects to store
    @type nodes: list
    @return: Whether the insert was successful
    @rtype: bool
    """

    rels_to_add = []
    for node in nodes:
        graph.add_node(
            node.id,
            node.type,
            {
                x: node[x]
                for x in node.properties_populated()
                if x not in ["id", "type"]
                and not x.endswith("_ref")
                and not x.endswith("_refs")
            },
        )
        for x in node.properties_populated():
            if x.endswith("_ref"):
                rels_to_add.append((node.id, node[x], x))
            elif x.endswith("_refs"):
                rels_to_add.extend([(node.id, x, y) for y in node[x]])

    for rel in rels_to_add:
        graph.add_relation(rel[0], rel[1], rel[2])

    return False
