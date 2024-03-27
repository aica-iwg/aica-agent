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
import pytz
import re

from celery.utils.log import get_task_logger
from stix2.base import _STIXBase  # type: ignore
from stix2 import (  # type: ignore
    AttackPattern,
    Directory,
    DomainName,
    File,
    HTTPRequestExt,
    Incident,
    Indicator,
    Infrastructure,
    IPv4Address,
    IPv6Address,
    Malware,
    MACAddress,
    NetworkTraffic,
    Note,
    ObservedData,
    Relationship,
    Sighting,
    Software,
)
from typing import Any, Dict, List, Optional, Union

from aica_django.connectors.GraphDatabase import AicaNeo4j


logger = get_task_logger(__name__)

graph = AicaNeo4j()

ip_protos = {
    0: "hopopt",
    1: "icmp",
    2: "igmp",
    3: "ggp",
    4: "ip-in-ip",
    5: "st",
    6: "tcp",
    7: "cbt",
    8: "egp",
    9: "igp",
    10: "bbn-rcc-mon",
    11: "nvp-ii",
    12: "pup",
    13: "argus",
    14: "emcon",
    15: "xnet",
    16: "chaos",
    17: "udp",
    18: "mux",
    19: "dcn-meas",
    20: "hmp",
    21: "prm",
    22: "xns-idp",
    23: "trunk-1",
    24: "trunk-2",
    25: "leaf-1",
    26: "leaf-2",
    27: "rdp",
    28: "irtp",
    29: "iso-tp4",
    30: "netblt",
    31: "mfe-nsp",
    32: "merit-inp",
    33: "dccp",
    34: "3pc",
    35: "idpr",
    36: "xtp",
    37: "ddp",
    38: "idpr-cmtp",
    39: "tp++",
    40: "il",
    41: "ipv6",
    42: "sdrp",
    43: "ipv6-route",
    44: "ipv6-frag",
    45: "idrp",
    46: "rsvp",
    47: "gre",
    48: "dsr",
    49: "bna",
    50: "esp",
    51: "ah",
    52: "i-nlsp",
    53: "swipe",
    54: "narp",
    55: "mobile",
    56: "tlsp",
    57: "skip",
    58: "ipv6-icmp",
    59: "ipv6-nonxt",
    60: "ipv6-opts",
    62: "cftp",
    64: "sat-expak",
    65: "kryptolan",
    66: "rvd",
    67: "ippc",
    69: "sat-mon",
    70: "visa",
    71: "ipcu",
    72: "cpnx",
    73: "cphb",
    74: "wsn",
    75: "pvp",
    76: "br-sat-mon",
    77: "sun-nd",
    78: "wb-mon",
    79: "wb-expak",
    80: "iso-ip",
    81: "vmtp",
    82: "secure-vmtp",
    83: "vines",
    84: "ttp",
    84: "iptm",
    85: "nsfnet-igp",
    86: "dgp",
    87: "tcf",
    88: "eigrp",
    89: "ospf",
    90: "sprite-rpc",
    91: "larp",
    92: "mtp",
    93: "ax.25",
    94: "os",
    95: "micp",
    96: "scc-sp",
    97: "etherip",
    98: "encap",
    100: "gmtp",
    101: "ifmp",
    102: "pnni",
    103: "pim",
    104: "aris",
    105: "scps",
    106: "qnx",
    107: "a/n",
    108: "ipcomp",
    109: "snp",
    110: "compaq-peer",
    111: "ipx-in-ip",
    112: "vrrp",
    113: "pgm",
    115: "l2tp",
    116: "ddx",
    117: "iatp",
    118: "stp",
    119: "srp",
    120: "uti",
    121: "smp",
    122: "sm",
    123: "ptp",
    124: "is-is over ipv4",
    125: "fire",
    126: "crtp",
    127: "crudp",
    128: "sscopmce",
    129: "iplt",
    130: "sps",
    131: "pipe",
    132: "sctp",
    133: "fc",
    134: "rsvp-e2e-ignore",
    135: "mobility header",
    136: "udplite",
    137: "mpls-in-ip",
    138: "manet",
    139: "hip",
    140: "shim6",
    141: "wesp",
    142: "rohc",
    143: "ethernet",
    144: "aggfrag",
    145: "nsh",
}


def get_ipv4(ip_addr: str) -> Union[str, None]:
    ip_addresses = graph.get_ipv4_ids_by_addr(ip_addr)
    if len(ip_addresses) > 0:
        return list(ip_addresses)[0]
    else:
        return None


def get_ipv6(ip_addr: str) -> Union[str, None]:
    ip_addresses = graph.get_ipv6_ids_by_addr(ip_addr)
    if len(ip_addresses) > 0:
        return list(ip_addresses)[0]
    else:
        return None


def get_attack_pattern(attack_pattern: str) -> Union[str, None]:
    attack_patterns = graph.get_attack_pattern_ids_by_name(attack_pattern)
    if len(attack_patterns) > 0:
        return list(attack_patterns)[0]
    else:
        return None


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
        source_addr_id = get_ipv4(ip_src_addr)
        if source_addr_id:
            source_addr = IPv4Address(id=source_addr_id, value=ip_src_addr)
        else:
            source_addr = IPv4Address(value=ip_src_addr)
            knowledge_nodes.append(source_addr)

        ip_dst_addr = str(ipaddress.ip_address(flow["IPV4_DST_ADDR"]))
        dest_addr_id = get_ipv4(ip_dst_addr)
        if dest_addr_id:
            dest_addr = IPv4Address(id=dest_addr_id, value=ip_dst_addr)
        else:
            dest_addr = IPv4Address(value=ip_dst_addr)
            knowledge_nodes.append(dest_addr)

    elif "IPV6_SRC_ADDR" in flow and flow["IPV6_SRC_ADDR"] is not None:
        ip_src_addr = str(ipaddress.ip_address(flow["IPV6_SRC_ADDR"]))
        source_addr_id = get_ipv6(ip_src_addr)
        if source_addr_id:
            source_addr = IPv6Address(id=source_addr_id, value=ip_src_addr)
        else:
            source_addr = IPv6Address(value=ip_src_addr)
            knowledge_nodes.append(source_addr)

        ip_dst_addr = str(ipaddress.ip_address(flow["IPV6_DST_ADDR"]))
        dest_addr_id = get_ipv6(ip_dst_addr)
        if dest_addr_id:
            dest_addr = IPv6Address(id=dest_addr_id, value=dest_addr_id)
        else:
            dest_addr = IPv6Address(value=ip_dst_addr)
            knowledge_nodes.append(dest_addr)

    # STIX 2.0 Mandated format
    start_time = dateparser.parse(str(flow["FIRST_SWITCHED"]))
    end_time = dateparser.parse(str(flow["LAST_SWITCHED"]))

    try:
        protocol = ip_protos[int(flow["PROTO"])]
    except KeyError:
        protocol = "unknown"

    params = {
        "protocols": [protocol],
        "src_ref": source_addr,
        "src_port": int(flow["SRC_PORT"]),
        "src_packets": int(flow["IN_PACKETS"]),
        "src_byte_count": int(flow["IN_OCTETS"]),
        "dst_ref": dest_addr,
        "dst_port": int(flow["DST_PORT"]),
        "start": start_time,
        "end": end_time,
    }

    # is_active must be false if end_time is set (per STIX)
    traffic = NetworkTraffic(is_active=False, **params)

    knowledge_nodes.append(traffic)

    dst_port_note_ids = graph.get_port_note_ids_by_abstract(
        int(flow["DST_PORT"]), protocol
    )
    label = f"{flow['DST_PORT']}/{protocol}"
    if len(dst_port_note_ids) > 0:
        dst_port_note = Note(
            id=list(dst_port_note_ids)[0],
            object_refs=[traffic],
            abstract=label,
            content=label,
        )
    else:
        dst_port_note = Note(object_refs=[traffic], abstract=label, content=label)

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
        str(log_dict["dateandtime"]), "%d/%b/%Y:%H:%M:%S %z"
    )

    if not request_time:
        raise ValueError(f"Couldn't parse timestamp {log_dict['dateandtime']}")

    # Create source host and port nodes (and link to protocol node)
    ip_version = ipaddress.ip_address(log_dict["src_ip"]).version
    ip_src_addr = log_dict["src_ip"]
    if ip_version == 4:
        source_addr_id = get_ipv4(ip_src_addr)
        if source_addr_id:
            source_addr = IPv4Address(id=source_addr_id, value=ip_src_addr)
        else:
            source_addr = IPv4Address(value=ip_src_addr)
            knowledge_nodes.append(source_addr)

        ip_dst_addr = str(ipaddress.ip_address(log_dict["server_ip"]))
        dest_addr_id = get_ipv4(ip_dst_addr)
        if dest_addr_id:
            dest_addr = IPv4Address(id=dest_addr_id, value=ip_dst_addr)
        else:
            dest_addr = IPv4Address(value=ip_dst_addr)
            knowledge_nodes.append(dest_addr)

    elif ip_version == 6:
        ip_src_addr = str(ipaddress.ip_address(log_dict["src_ip"]))
        source_addr_id = get_ipv6(ip_src_addr)
        if source_addr_id:
            source_addr = IPv6Address(id=source_addr_id, value=ip_src_addr)
        else:
            source_addr = IPv6Address(value=ip_src_addr)
            knowledge_nodes.append(source_addr)

        ip_dst_addr = str(ipaddress.ip_address(log_dict["server_ip"]))
        dest_addr_id = get_ipv6(ip_dst_addr)
        if dest_addr_id:
            dest_addr = IPv6Address(id=dest_addr_id, value=ip_dst_addr)
        else:
            dest_addr = IPv6Address(value=ip_dst_addr)
            knowledge_nodes.append(dest_addr)

    traffic = NetworkTraffic(
        start=request_time,
        src_ref=source_addr,
        dst_ref=dest_addr,
        dst_byte_count=log_dict["bytes_sent"],
        extensions=HTTPRequestExt(
            request_method=log_dict["method"],
            request_value=log_dict["url"],
            request_header={
                "User-Agent": log_dict["useragent"],
                "Referer": log_dict["referer"],
            },
        ),
    )
    knowledge_nodes.append(traffic)

    http_status_abstract = f"status: {log_dict['status']}"

    http_status_ids = graph.get_note_ids_by_abstract(http_status_abstract)
    label = f"status: {log_dict['status']}"
    if len(http_status_ids) > 0:
        http_status = Note(
            id=list(http_status_ids)[0],
            abstract=label,
            content=label,
            object_refs=[traffic],
        )
    else:
        http_status = Note(
            abstract=label,
            content=label,
            object_refs=[traffic],
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
    request_time = datetime.datetime.strptime(
        str(log_dict["ts"]), "%d/%b/%Y:%H:%M:%S %z"
    )

    if not request_time:
        raise ValueError(f"Couldn't parse timestamp {log_dict['ts']}")

    if type(ipaddress.ip_address(log_dict["src_ip"])) is ipaddress.IPv4Address:
        src_addr_id = get_ipv4(log_dict["src_ip"])
        if src_addr_id:
            src_addr = IPv4Address(id=src_addr_id, value=log_dict["src_ip"])
        else:
            src_addr = IPv4Address(value=log_dict["src_ip"])
            knowledge_nodes.append(src_addr)

        dst_addr_id = get_ipv4(log_dict["dest_ip"])
        if dst_addr_id:
            dst_addr = IPv4Address(id=dst_addr_id, value=log_dict["dest_ip"])
        else:
            dst_addr = IPv4Address(value=log_dict["dest_ip"])
            knowledge_nodes.append(dst_addr)
    else:
        src_addr_id = get_ipv6(log_dict["src_ip"])
        if src_addr_id:
            src_addr = IPv6Address(id=src_addr_id, value=log_dict["src_ip"])
        else:
            src_addr = IPv6Address(value=log_dict["src_ip"])
            knowledge_nodes.append(src_addr)
        dst_addr_id = get_ipv6(log_dict["dest_ip"])
        if dst_addr_id:
            dst_addr = IPv6Address(id=dst_addr_id, value=log_dict["dest_ip"])
        else:
            dst_addr = IPv6Address(value=log_dict["dest_ip"])
            knowledge_nodes.append(dst_addr)

    traffic = NetworkTraffic(
        start=request_time,
        src_ref=src_addr,
        dst_ref=dst_addr,
        extensions=HTTPRequestExt(
            request_method=log_dict["request"]["method"],
            request_value=log_dict["url"],
            dst_byte_count=log_dict["request"]["host"] + log_dict["uri"],
            request_header={
                "User-Agent": log_dict["request"]["headers"]["User-Agent"],
                "Referer": log_dict["request"]["headers"]["Referer"],
            },
        ),
        custom_properties={
            "caddy_id": log_dict["id"],
            "http_response_status": log_dict["status"],
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

        consists_of = []
        if scan_results[host]["macaddress"]:
            mac_addr = MACAddress(value=scan_results[host]["macaddress"])
            consists_of.append(mac_addr)
            knowledge_nodes.append(mac_addr)

            try:
                vendor_abstract = f"vendor: {scan_results[host]['vendor']}"
                vendors = graph.get_note_ids_by_abstract(vendor_abstract)
                if len(vendors) > 0:
                    vendor_note = Note(
                        id=list(vendors)[0],
                        abstract=vendor_abstract,
                        content=vendor_abstract,
                        object_refs=[mac_addr],
                    )
                else:
                    vendor_note = Note(
                        abstract=vendor_abstract,
                        content=vendor_abstract,
                        object_refs=[mac_addr],
                    )

                knowledge_nodes.append(vendor_note)
            except KeyError:
                # Vendor not in data, not a big deal
                logger.debug(
                    f"No vendor found in object for {scan_results[host]['macaddress']}"
                )

        mac_addr_list = [mac_addr] if mac_addr else []

        ip_addr = ipaddress.ip_address(host)
        # Update if new IP address or we found a MAC address, which could be new
        if ip_addr.version == 4:
            dest_addr_id = get_ipv4(str(ip_addr))
            if not dest_addr_id or len(mac_addr_list) > 0:
                dest_addr = IPv4Address(value=ip_addr, resolves_to_refs=mac_addr_list)
                knowledge_nodes.append(dest_addr)
            else:
                dest_addr = IPv4Address(
                    id=dest_addr_id, value=ip_addr, resolves_to_refs=mac_addr_list
                )
        elif ip_addr.version == 6:
            dest_addr_id = get_ipv6(str(ip_addr))
            if not dest_addr_id or len(mac_addr_list) > 0:
                dest_addr = IPv6Address(value=ip_addr, resolves_to_refs=mac_addr_list)
                knowledge_nodes.append(dest_addr)
            else:
                dest_addr = IPv6Address(
                    id=dest_addr_id, value=ip_addr, resolves_to_refs=mac_addr_list
                )

        else:
            raise ValueError(
                f"Unsupported ip type {type(ipaddress.ip_address(host)) } for {host}"
            )

        knowledge_nodes.append(dest_addr)

        for hostname in scan_results[host]["hostname"]:
            domain_name = DomainName(
                value=hostname["name"], resolves_to_refs=[dest_addr]
            )
            knowledge_nodes.append(domain_name)

        if len(scan_results[host]["osmatch"]) > 1:
            os_match = scan_results[host]["osmatch"][0]
            operating_system = Software(
                name=os_match["name"],
                cpe=os_match["cpe"] if os_match["cpe"] else "unknown",
                version=os_match["osclass"]["osgen"],
                vendor=os_match["osclass"]["vendor"],
            )
            consists_of.append(operating_system)
            knowledge_nodes.append(operating_system)

        target_host = Infrastructure(
            name=str(host),
            infrastructure_types=["unknown"],
            last_seen=scan_time,
        )
        for consists_ref in consists_of:
            knowledge_nodes.append(
                Relationship(
                    relationship_type="consists_of",
                    source_ref=target_host,
                    target_ref=consists_ref,
                )
            )

        knowledge_nodes.append(target_host)

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

    if type(ipaddress.ip_address(alert["src_ip"])) is ipaddress.IPv4Address:
        src_addr_id = get_ipv4(alert["src_ip"])
        if src_addr_id:
            src_addr = IPv4Address(id=src_addr_id, value=alert["src_ip"])
        else:
            src_addr = IPv4Address(value=alert["src_ip"])
            knowledge_nodes.append(src_addr)

        dst_addr_id = get_ipv4(alert["dest_ip"])
        if dst_addr_id:
            dst_addr = IPv4Address(id=dst_addr_id, value=alert["dest_ip"])
        else:
            dst_addr = IPv4Address(value=alert["dest_ip"])
            knowledge_nodes.append(dst_addr)
    else:
        src_addr_id = get_ipv6(alert["src_ip"])
        if src_addr_id:
            src_addr = IPv6Address(id=src_addr_id, value=alert["src_ip"])
        else:
            src_addr = IPv6Address(value=alert["src_ip"])
            knowledge_nodes.append(src_addr)

        dst_addr_id = get_ipv6(alert["dest_ip"])
        if dst_addr_id:
            dst_addr = IPv6Address(id=dst_addr_id, value=alert["dest_ip"])
        else:
            dst_addr = IPv6Address(value=alert["dest_ip"])
            knowledge_nodes.append(dst_addr)

    try:
        protocol = ip_protos[alert["PROTO"]]
    except KeyError:
        protocol = "unknown"

    start_time = dateparser.parse(str(alert["timestamp"]))

    params = {
        "protocols": [protocol],
        "src_ref": src_addr,
        "src_port": alert["src_port"],
        "dst_ref": dst_addr,
        "dst_port": alert["dest_port"],
        "start": start_time,
    }

    traffic = NetworkTraffic(
        **params,
    )

    knowledge_nodes.append(traffic)

    dst_port_note_ids = graph.get_port_note_ids_by_abstract(
        alert["dest_port"], alert["proto"]
    )
    if len(dst_port_note_ids) > 0:
        dst_port_note = Note(
            id=list(dst_port_note_ids)[0],
            abstract=f"{alert['dest_port']}/{alert['proto']}",
            content=f"{alert['dest_port']}/{alert['proto']}",
            object_refs=[traffic],
        )
    else:
        dst_port_note = Note(
            abstract=f"{alert['dest_port']}/{alert['proto']}",
            content=f"{alert['dest_port']}/{alert['proto']}",
            object_refs=[traffic],
        )

    knowledge_nodes.append(dst_port_note)

    alert_name = f"suricata:{alert['alert']['signature_id']}/{alert['alert']['rev']}"

    # Check for existing indicator in DB. Create if it doesn't exist, reference if it does.
    alert_sig_ids = graph.get_indicator_ids_by_name(alert_name)
    if len(alert_sig_ids) == 0:
        attack_pattern_ids = graph.get_attack_pattern_ids_by_category(
            alert["alert"]["category"]
        )
        if len(attack_pattern_ids) == 0:
            raise ValueError(f"Unknown Suricata attack pattern: {alert['alert']}")
        else:
            attack_pattern = AttackPattern(
                id=attack_pattern_ids[0],
                name=alert["alert"]["category"],
            )

        indicator = Indicator(
            name=alert_name,
            description=alert["alert"]["signature"],
            pattern="Not Provided",  # Required field, but we don't have this info
            pattern_type="suricata",
            pattern_version=alert["alert"]["rev"],
            valid_from=datetime.datetime.now(),
        )
        knowledge_nodes.append(indicator)
        indicates_rel = Relationship(
            relationship_type="indicates",
            source_ref=indicator,
            target_ref=attack_pattern,
        )
        knowledge_nodes.append(indicates_rel)
    else:
        indicator = Indicator(
            id=list(alert_sig_ids)[0],
            pattern="<PLACEHOLDER>",
            pattern_type="suricata",
            valid_from=datetime.datetime.now(),
        )

    try:
        observation = ObservedData(
            first_observed=start_time,
            last_observed=start_time,
            number_observed=1,
            object_refs=[traffic],
        )
        knowledge_nodes.append(observation)
        sighting = Sighting(
            description="suricata_alert",
            last_seen=dateparser.parse(alert["timestamp"]),
            count=1,
            observed_data_refs=[observation],
            sighting_of_ref=indicator,
        )
        knowledge_nodes.append(sighting)
    except Exception as e:
        logger.error(f"Couldn't create sighting ({e})")

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

    file = File(name=file_name, parent_directory_ref=directory)
    knowledge_nodes.append(file)

    alert_indicator = Incident(
        name=alert_name,
    )
    knowledge_nodes.append(alert_indicator)

    platform = Software(name=alert["platform"])
    knowledge_nodes.append(platform)

    malware = Malware(
        name=alert_name,
        description=alert["name"],
        is_family=False,
        operating_system_refs=[platform],
        sample_refs=[file],
    )
    knowledge_nodes.append(malware)

    attack_pattern = AttackPattern(name=f"clamav:{alert['category']}")
    knowledge_nodes.append(attack_pattern)

    malware_pattern_rel = Relationship(
        relationship_type="delivers",
        source_ref=attack_pattern,
        target_ref=malware,
    )
    knowledge_nodes.append(malware_pattern_rel)

    host = Infrastructure(
        name=alert["hostname"],
        infrastructure_types=["workstation"],
        last_seen=timestamp,
    )
    knowledge_nodes.append(host)

    observation = ObservedData(
        first_observed=timestamp,
        last_observed=timestamp,
        number_observed=1,
        object_refs=[file],
    )
    knowledge_nodes.append(malware_pattern_rel)

    try:
        sighting = Relationship(host, "hosts", malware)
        knowledge_nodes.append(sighting)
    except Exception as e:
        logger.error(e)

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

    alert_dt = datetime.datetime.fromtimestamp(alert["ts"])

    try:
        alert_name = f"owasp_crs:{alert['id']}/{alert['rev']}"
    except:
        logger.warning(f"Skipping alert with no ID: {alert}")
        return []

    alert_indicator = Indicator(
        name=alert_name,
        description=alert["data"],
        pattern="Not specified",
        pattern_type="owasp_crs",
        valid_from=alert_dt,
    )
    knowledge_nodes.append(alert_indicator)

    for tag in alert["tags"]:
        ap_id = get_attack_pattern(tag)
        ap_rel = Relationship(alert_indicator, "indicates", ap_id)
        knowledge_nodes.append(ap_rel)

    # Make Cypher query and return node that contains the correct unique ID
    http_req_nodes = graph.graph.run(
        f"MATCH (n:NetworkTraffic) WHERE n.caddy_id = \"{alert['unique_id']}\" RETURN n"
    )
    http_req = NetworkTraffic(id=list(http_req_nodes)[0].id)

    observation = ObservedData(
        first_observed=alert_dt,
        last_observed=alert_dt,
        number_observed=1,
        object_refs=[http_req] if len(http_req_nodes) > 0 else [],
    )

    sighting = Sighting(
        description="waf_alert",
        last_seen=alert_dt,
        count=1,
        observed_data_refs=[observation],
        sighting_of_ref=alert_indicator,
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
        # Sightings are relationships (SROs) - took me a while to figure that one out...
        if isinstance(node, Relationship) or isinstance(node, Sighting):
            rels_to_add.append(node)
        else:
            graph.add_node(
                node.id,
                f"{node.type}",
                {
                    x: node[x]
                    for x in node.properties_populated()
                    if x not in ["id", "type"]
                    and not x.endswith("_ref")
                    and not x.endswith("_refs")
                },
            )
            for x in node.properties_populated():
                label = "_".join(x.split("_")[0:-1])
                try:
                    if x.endswith("_ref"):
                        rels_to_add.append(
                            Relationship(
                                relationship_type=label,
                                source_ref=node,
                                target_ref=node[x],
                            )
                        )
                    elif x.endswith("_refs"):
                        rels_to_add.extend(
                            [
                                Relationship(
                                    relationship_type=label,
                                    source_ref=node,
                                    target_ref=y,
                                )
                                for y in node[x]
                            ]
                        )
                except Exception as e:
                    logger.error(f"Couldn't add ({node})->[{label}]->({node[x]}) | {e}")

    for rel in rels_to_add:
        if isinstance(rel, Sighting):
            label = "sighting_of"
            sources = rel["observed_data_refs"]
            target = "sighting_of_ref"
        else:
            label = rel["relationship_type"]
            sources = [rel["source_ref"]]
            target = "target_ref"

        try:
            for source in sources:
                graph.add_relation(
                    node_a_id=source,
                    node_b_id=rel[target],
                    relation_label=label,
                    # Only include valid Relationship/Sighting properties
                    # https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_e2e1szrqfoan
                    relation_properties={
                        x: rel[x]
                        for x in rel.properties_populated()
                        if x
                        in [
                            "description",
                            "start_time",
                            "stop_time",
                            "first_seen",
                            "last_seen",
                            "count",
                            "summary",
                        ]
                    },
                )
        except ValueError as e:
            logger.error(f"Failed to add relation {rel} ({e})")

    return False
