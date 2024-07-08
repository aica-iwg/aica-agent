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
import re2 as re  # type: ignore

from celery.utils.log import get_task_logger
from ipwhois import IPWhois  # type: ignore
from mac_vendor_lookup import MacLookup, VendorNotFoundError  # type: ignore
from stix2 import (  # type: ignore
    AutonomousSystem,
    Directory,
    DomainName,
    File,
    HTTPRequestExt,
    IPv4Address,
    IPv6Address,
    Malware,  # TODO: Create AICA Version
    MACAddress,
    NetworkTraffic,
    ObservedData,
    Relationship,
    Sighting,
    Software,
    Tool,
)
from stix2.base import _STIXBase  # type: ignore
from stix2.registration import _register_extension  # type: ignore
from typing import Any, Dict, List, Union

from aica_django.connectors.GraphDatabase import AicaNeo4j
from aica_django.converters.AICAStix import (
    AICAAttackPattern,
    AICAIncident,
    AICAIdentity,
    AICAIndicator,
    AICALocation,
    AICANetworkTraffic,
    AICANote,
    DNP3RequestExt,
)


logger = get_task_logger(__name__)

graph = AicaNeo4j()

# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
ip_protos = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IPv4",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-II",
    12: "PUP",
    13: "ARGUS",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    20: "HMP",
    21: "PRM",
    22: "XNS-IDP",
    23: "TRUNK-1",
    24: "TRUNK-2",
    25: "LEAF-1",
    26: "LEAF-2",
    27: "RDP",
    28: "IRTP",
    29: "ISO-TP4",
    30: "NETBLT",
    31: "MFE-NSP",
    32: "MERIT-INP",
    33: "DCCP",
    34: "3PC",
    35: "IDPR",
    36: "XTP",
    37: "DDP",
    38: "IDPR-CMTP",
    39: "TP++",
    40: "IL",
    41: "IPv6",
    42: "SDRP",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    45: "IDRP",
    46: "RSVP",
    47: "GRE",
    48: "DSR",
    49: "BNA",
    50: "ESP",
    51: "AH",
    52: "I-NLSP",
    53: "SWIPE",
    54: "NARP",
    55: "Min-IPv4",
    56: "TLSP",
    57: "SKIP",
    58: "IPv6-ICMP",
    59: "IPv6-NoNxt",
    60: "IPv6-Opts",
    62: "CFTP",
    64: "SAT-EXPAK",
    65: "KRYPTOLAN",
    66: "RVD",
    67: "IPPC",
    69: "SAT-MON",
    70: "VISA",
    71: "IPCV",
    72: "CPNX",
    73: "CPHB",
    74: "WSN",
    75: "PVP",
    76: "BR-SAT-MON",
    77: "SUN-ND",
    78: "WB-MON",
    79: "WB-EXPAK",
    80: "ISO-IP",
    81: "VMTP",
    82: "SECURE-VMTP",
    83: "VINES",
    84: "IPTM",
    85: "NSFNET-IGP",
    86: "DGP",
    87: "TCF",
    88: "EIGRP",
    89: "OSPFIGP",
    90: "Sprite-RPC",
    91: "LARP",
    92: "MTP",
    93: "AX.25",
    94: "IPIP",
    95: "MICP",
    96: "SCC-SP",
    97: "ETHERIP",
    98: "ENCAP",
    100: "GMTP",
    101: "IFMP",
    102: "PNNI",
    103: "PIM",
    104: "ARIS",
    105: "SCPS",
    106: "QNX",
    107: "A/N",
    108: "IPComp",
    109: "SNP",
    110: "Compaq-Peer",
    111: "IPX-in-IP",
    112: "VRRP",
    113: "PGM",
    115: "L2TP",
    116: "DDX",
    117: "IATP",
    118: "STP",
    119: "SRP",
    120: "UTI",
    121: "SMP",
    122: "SM",
    123: "PTP",
    124: "ISIS over IPv4",
    125: "FIRE",
    126: "CRTP",
    127: "CRUDP",
    128: "SSCOPMCE",
    129: "IPLT",
    130: "SPS",
    131: "PIPE",
    132: "SCTP",
    133: "FC",
    134: "RSVP-E2E-IGNORE",
    135: "Mobility Header",
    136: "UDPLite",
    137: "MPLS-in-IP",
    138: "manet",
    139: "HIP",
    140: "Shim6",
    141: "WESP",
    142: "ROHC",
    143: "Ethernet",
    144: "AGGFRAG",
    145: "NSH",
}
# Nmap data protocols are lowercase
ip_protos = {k: v.lower() for k, v in ip_protos.items()}

# We need this because Notes are required to have a reference, but the ID is based on them
# so we create this as an artificial reference point for Notes created before we know what
# their references are. It is stripped out in the knowledge_to_neo function.
# We use "Tool" because it has a single deterministic required property.
fake_note_root = Tool(
    id="tool--a6ed2b50-ea7d-40d0-8c3e-46ed99e67ea2", name="fake_note_root"
)

# To match the root used when port notes are created, as the ID is based on the name
port_root = Software(
    id="software--e3aaca11-5e6a-4ee7-bc59-e8d4d64b9e62", name="Generic Port Usage Info"
)

ip_version_4_note = AICANote(
    abstract=f"ip_version_4",
    content=f"ip_version_4",
    object_refs=[fake_note_root],
)

ip_version_6_note = AICANote(
    abstract=f"ip_version_6",
    content=f"ip_version_6",
    object_refs=[fake_note_root],
)

is_private_note = AICANote(
    abstract="ip_is_private",
    content="ip_is_private",
    object_refs=[fake_note_root],
)

is_multicast_note = AICANote(
    abstract="ip_is_multicast",
    content="ip_is_multicast",
    object_refs=[fake_note_root],
)

is_reserved_note = AICANote(
    abstract="ip_is_reserved",
    content="ip_is_reserved",
    object_refs=[fake_note_root],
)

is_loopback_note = AICANote(
    abstract="ip_is_loopback",
    content="ip_is_loopback",
    object_refs=[fake_note_root],
)

is_link_local_note = AICANote(
    abstract="ip_is_link_local",
    content="ip_is_link_local",
    object_refs=[fake_note_root],
)

mac_lookup = MacLookup()


def get_ip_context(ip_addr: Union[IPv4Address, IPv6Address]) -> List[_STIXBase]:
    note_refs = []
    return_nodes = []
    new_ip_addr_kwargs = {k: ip_addr[k] for k in ip_addr.properties_populated()}

    ip_string = ip_addr.value
    ip_obj = ipaddress.ip_address(ip_string)

    version: int = ip_obj.version
    if version == 4:
        note_refs.append(ip_version_4_note)
        return_nodes.append(ip_version_4_note)
    else:
        note_refs.append(ip_version_6_note)
        return_nodes.append(ip_version_6_note)

    is_private: bool = ip_obj.is_private
    if is_private:
        note_refs.append(is_private_note)
        return_nodes.append(is_private_note)

    is_multicast: bool = ip_obj.is_multicast
    if is_multicast:
        note_refs.append(is_multicast_note)
        return_nodes.append(is_multicast_note)

    is_reserved: bool = ip_obj.is_reserved
    if is_reserved:
        note_refs.append(is_reserved_note)
        return_nodes.append(is_reserved_note)

    is_loopback: bool = ip_obj.is_loopback
    if is_loopback:
        note_refs.append(is_loopback_note)
        return_nodes.append(is_loopback_note)

    is_link_local: bool = ip_obj.version == 6 and ip_obj.is_link_local
    if is_link_local:
        note_refs.append(is_link_local_note)
        return_nodes.append(is_link_local_note)

    asn = None

    if not any([is_private, is_multicast, is_reserved, is_loopback, is_link_local]):
        whois_obj = IPWhois(ip_string)
        whois_data = whois_obj.lookup_rdap(depth=1)
        cidr_kwargs: Dict[str, Dict[str, Any]] = {"custom_properties": dict()}

        if whois_data["asn"]:
            asn = AutonomousSystem(
                number=whois_data["asn"], rir=whois_data["asn_registry"]
            )
            return_nodes.append(asn)

        if whois_data["asn_country_code"]:
            location = AICALocation(country=whois_data["asn_country_code"])
            return_nodes.append(location)
        else:
            location = None

        if whois_data["entities"]:
            if "custom_properties" in new_ip_addr_kwargs.keys():
                new_ip_addr_kwargs["custom_properties"].update({"has_owner_refs": []})
            else:
                new_ip_addr_kwargs["custom_properties"] = {"has_owner_refs": []}

            if "custom_properties" in new_ip_addr_kwargs.keys():
                cidr_kwargs["custom_properties"].update({"has_owner_refs": []})
            else:
                cidr_kwargs["custom_properties"] = {"has_owner_refs": []}

            for entity in whois_data["entities"]:
                entity_kwargs = {"name": entity}
                entity = AICAIdentity(**entity_kwargs)
                new_ip_addr_kwargs["custom_properties"]["has_owner_refs"].append(entity)
                cidr_kwargs["custom_properties"]["has_owner_refs"].append(entity)
                return_nodes.append(entity)

                if location:
                    location_rel = Relationship(
                        source_ref=entity,
                        target_ref=location,
                        relationship_type="located-at",
                    )
                    return_nodes.append(location_rel)

        if whois_data["asn_cidr"]:
            cidr_kwargs.update({"value": whois_data["asn_cidr"]})
            cidr_kwargs["custom_properties"].update({"has_member_refs": [ip_addr]})
            if version == 4:
                asn_cidr = IPv4Address(**cidr_kwargs)
            else:
                asn_cidr = IPv6Address(**cidr_kwargs)
            return_nodes.append(asn_cidr)

            if asn:
                asn_rel = Relationship(
                    source_ref=asn_cidr, target_ref=asn, relationship_type="belongs-to"
                )
                return_nodes.append(asn_rel)

    if isinstance(ip_addr, IPv4Address):
        ip_stix = IPv4Address(**new_ip_addr_kwargs)
        return_nodes.append(IPv4Address(**new_ip_addr_kwargs))
    else:
        ip_stix = IPv4Address(**new_ip_addr_kwargs)
        return_nodes.append(IPv6Address(**new_ip_addr_kwargs))

    if asn:
        asn_rel = Relationship(
            source_ref=ip_stix, target_ref=asn, relationship_type="belongs-to"
        )
        return_nodes.append(asn_rel)

    for note_ref in note_refs:
        note_rel = Relationship(
            source_ref=note_ref, relationship_type="object", target_ref=ip_stix
        )
        return_nodes.append(note_rel)

    return return_nodes


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

    dt_utc = datetime.datetime.fromtimestamp(timestamp)
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

    normed_mac = str(re.sub(r"[^A-Fa-f\d]", "", mac_addr).lower())
    if len(normed_mac) != 12:
        raise ValueError("Invalid MAC Address Provided")

    return normed_mac


def netflow_to_knowledge(
    flow: Dict[str, str]
) -> List[Union[AICANetworkTraffic, IPv4Address, IPv6Address]]:
    """
    Converts a netflow dictionary (from the Python netflow library) to knowledge objects.

    @param flow: A netflow dictionary to be converted to knowledge objects
    @type flow: Dict[str, str]
    @return: Knowledge nodes resulting form this conversion
    @rtype: list
    """

    knowledge_nodes = []

    # Create source host nodes (and link to protocol node)
    if "IPV4_SRC_ADDR" in flow and flow["IPV4_SRC_ADDR"] is not None:
        ip_src_addr = str(ipaddress.ip_address(flow["IPV4_SRC_ADDR"]))
        source_addr = IPv4Address(value=ip_src_addr)
        knowledge_nodes.extend(get_ip_context(source_addr))

        ip_dest_addr = str(ipaddress.ip_address(flow["IPV4_DST_ADDR"]))
        dest_addr = IPv4Address(value=ip_dest_addr)
        knowledge_nodes.extend(get_ip_context(dest_addr))

    elif "IPV6_SRC_ADDR" in flow and flow["IPV6_SRC_ADDR"] is not None:
        ip_src_addr = str(ipaddress.ip_address(flow["IPV6_SRC_ADDR"]))
        source_addr = IPv6Address(value=ip_src_addr)
        knowledge_nodes.extend(get_ip_context(source_addr))

        ip_dest_addr = str(ipaddress.ip_address(flow["IPV6_DST_ADDR"]))
        dest_addr = IPv6Address(value=ip_dest_addr)
        knowledge_nodes.extend(get_ip_context(dest_addr))

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
    traffic = AICANetworkTraffic(is_active=False, **params)

    knowledge_nodes.append(traffic)

    label = f"{flow['DST_PORT']}/{protocol}"
    dest_port_note = AICANote(
        abstract=label,
        content=label,
        object_refs=[port_root],
    )

    knowledge_nodes.append(Relationship(dest_port_note, "object", traffic))

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

    # Create source host nodes (and link to protocol node)
    ip_version = ipaddress.ip_address(log_dict["src_ip"]).version
    ip_src_addr = log_dict["src_ip"]
    if ip_version == 4:
        protocols = ["ipv4", "tcp", "http"]
        source_addr = IPv4Address(value=ip_src_addr)
        knowledge_nodes.extend(get_ip_context(source_addr))

        ip_dest_addr = str(ipaddress.ip_address(log_dict["server_ip"]))
        dest_addr = IPv4Address(value=ip_dest_addr)
        knowledge_nodes.extend(get_ip_context(dest_addr))

    elif ip_version == 6:
        protocols = ["ipv6", "tcp", "http"]
        ip_src_addr = str(ipaddress.ip_address(log_dict["src_ip"]))
        source_addr = IPv6Address(value=ip_src_addr)
        knowledge_nodes.extend(get_ip_context(source_addr))

        ip_dest_addr = str(ipaddress.ip_address(log_dict["server_ip"]))
        dest_addr = IPv6Address(value=ip_dest_addr)
        knowledge_nodes.extend(get_ip_context(dest_addr))

    http_req_ext = HTTPRequestExt(
        request_method=log_dict["method"],
        request_value=log_dict["url"],
        request_header={
            "User-Agent": log_dict["useragent"],
            "Referer": log_dict["referer"],
        },
    )

    traffic = AICANetworkTraffic(
        protocols=protocols,
        start=request_time,
        src_ref=source_addr,
        dst_ref=dest_addr,
        dst_byte_count=log_dict["bytes_sent"],
        extensions={"http-request-ext": http_req_ext},
    )
    knowledge_nodes.append(traffic)

    label = f"status: {log_dict['status']}"
    http_status = AICANote(
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
    request_time = datetime.datetime.fromtimestamp(log_dict["ts"])

    if not request_time:
        raise ValueError(f"Couldn't parse timestamp {log_dict['ts']}")

    if type(ipaddress.ip_address(log_dict["src_ip"])) is ipaddress.IPv4Address:
        protocols = ["ipv4", "tcp", "http"]
        src_addr = IPv4Address(value=log_dict["src_ip"])
        knowledge_nodes.extend(get_ip_context(src_addr))

        dest_addr = IPv4Address(value=log_dict["dst_ip"])
        knowledge_nodes.extend(get_ip_context(dest_addr))
    else:
        protocols = ["ipv6", "tcp", "http"]
        src_addr = IPv6Address(value=log_dict["src_ip"])
        knowledge_nodes.extend(get_ip_context(src_addr))

        dest_addr = IPv6Address(value=log_dict["dst_ip"])
        knowledge_nodes.extend(get_ip_context(dest_addr))

    http_req_ext = HTTPRequestExt(
        request_method=log_dict["request"]["method"],
        request_value=log_dict["url"],
        request_header={
            "User-Agent": log_dict["request"]["headers"]["User-Agent"],
            "Referer": log_dict["request"]["headers"]["Referer"],
        },
    )

    traffic = AICANetworkTraffic(
        protocols=protocols,
        start=request_time,
        src_ref=src_addr,
        dst_ref=dest_addr,
        dst_byte_count=log_dict["request"]["host"] + log_dict["uri"],
        extensions={"http-request-ext": http_req_ext},
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
            mac_addr = MACAddress(value=scan_results[host]["macaddress"]["addr"])
            knowledge_nodes.append(mac_addr)

            try:
                vendor = mac_lookup.lookup(scan_results[host]["macaddress"]["addr"])
                mac_vendor = AICANote(
                    abstract=f"MAC Vendor: {vendor}",
                    content=f"MAC Vendor: {vendor}",
                    object_refs=[mac_addr],
                )
                knowledge_nodes.append(mac_vendor)
            except VendorNotFoundError:
                logger.info(
                    f"Unable to find vendor for MAC: {scan_results[host]['macaddress']['addr']}"
                )

            mac_addr_list = [mac_addr] if mac_addr else []
        else:
            mac_addr_list = []

        ip_addr = ipaddress.ip_address(host)
        # Update if new IP address or we found a MAC address, which could be new
        if ip_addr.version == 4:
            dest_addr = IPv4Address(value=ip_addr, resolves_to_refs=mac_addr_list)
            knowledge_nodes.extend(get_ip_context(dest_addr))
        elif ip_addr.version == 6:
            dest_addr = IPv6Address(value=ip_addr, resolves_to_refs=mac_addr_list)
            knowledge_nodes.extend(get_ip_context(dest_addr))

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

        for consists_ref in consists_of:
            knowledge_nodes.append(
                Relationship(
                    relationship_type="consists_of",
                    source_ref=mac_addr,
                    target_ref=consists_ref,
                )
            )

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
        src_addr = IPv4Address(value=alert["src_ip"])
        knowledge_nodes.extend(get_ip_context(src_addr))

        dest_addr = IPv4Address(value=alert["dest_ip"])
        knowledge_nodes.extend(get_ip_context(dest_addr))
    else:
        src_addr = IPv6Address(value=alert["src_ip"])
        knowledge_nodes.extend(get_ip_context(src_addr))

        dest_addr = IPv6Address(value=alert["dest_ip"])
        knowledge_nodes.append(dest_addr)

    try:
        protocol = ip_protos[alert["PROTO"]]
    except KeyError:
        protocol = "unknown"

    start_time = dateparser.parse(str(alert["timestamp"]))

    params = {
        "protocols": [protocol],
        "src_ref": src_addr,
        "src_port": alert["src_port"],
        "dst_ref": dest_addr,
        "dst_port": alert["dest_port"],
        "start": start_time,
    }

    traffic = AICANetworkTraffic(
        **params,
    )

    knowledge_nodes.append(traffic)

    label = f"{alert['dest_port']}/{alert['proto']}"
    dest_port_note = AICANote(
        abstract=label,
        content=label,
        object_refs=[port_root],
    )

    knowledge_nodes.append(Relationship(dest_port_note, "object", traffic))

    attack_pattern_name = alert["alert"]["category"]
    attack_pattern = AICAAttackPattern(
        name=attack_pattern_name,
    )

    alert_name = f"suricata:{alert['alert']['signature_id']}/{alert['alert']['rev']}"
    indicator = AICAIndicator(
        name=alert_name,
        description=alert["alert"]["signature"],
        pattern="Not Provided",  # Required field, but we don't have this info
        pattern_type="suricata",
        pattern_version=alert["alert"]["rev"],
        valid_from=datetime.datetime.fromtimestamp(
            0
        ),  # Required by STIX but we don't care
    )
    knowledge_nodes.append(indicator)
    indicates_rel = Relationship(
        relationship_type="indicates",
        source_ref=indicator,
        target_ref=attack_pattern,
    )
    knowledge_nodes.append(indicates_rel)

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

    alert_indicator = AICAIncident(
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

    attack_pattern_name = f"clamav:{alert['category']}"
    attack_pattern = AICAAttackPattern(name=attack_pattern_name)
    knowledge_nodes.append(attack_pattern)

    malware_pattern_rel = Relationship(
        relationship_type="delivers",
        source_ref=attack_pattern,
        target_ref=malware,
    )
    knowledge_nodes.append(malware_pattern_rel)

    observation = ObservedData(
        first_observed=timestamp,
        last_observed=timestamp,
        number_observed=1,
        object_refs=[file],
    )
    knowledge_nodes.append(observation)

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

    alert_indicator = AICAIndicator(
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


_register_extension(DNP3RequestExt)


def dnp3_to_knowledge(log_dict: dict[str, str]) -> List[_STIXBase]:
    """
    Converts a DNP3 message (as returned from aica_django.connectors.DNP3.parse_dnp3_packet)
    to knowledge objects.

    @param alert: A dictionary as returned by parse_dnp3_packet to be converted to knowledge objects
    @type alert: Dict[str, Any]
    @return: Knowledge nodes resulting from this conversion
    @rtype: list
    """

    knowledge_nodes: List[_STIXBase] = []

    # dateparser can't seem to handle this format
    request_time = dateparser.parse(log_dict["sniff_timestamp"])

    if not request_time:
        raise ValueError(f"Couldn't parse timestamp {log_dict['sniff_timestamp']}")

    src_mac_addr = MACAddress(value=log_dict["src_mac"])
    knowledge_nodes.append(src_mac_addr)

    try:
        vendor = mac_lookup.lookup(log_dict["src_mac"])
        src_mac_vendor = AICANote(
            abstract=f"MAC Vendor: {vendor}",
            content=f"MAC Vendor: {vendor}",
            object_refs=[src_mac_addr],
        )
        knowledge_nodes.append(src_mac_vendor)
    except VendorNotFoundError:
        logger.info(f"Unable to find vendor for MAC: {log_dict['src_mac']}")

    dst_mac_addr = MACAddress(value=log_dict["dst_mac"])
    knowledge_nodes.append(dst_mac_addr)

    try:
        vendor = mac_lookup.lookup(log_dict["dst_mac"])
        dst_mac_vendor = AICANote(
            abstract=f"MAC Vendor: {vendor}",
            content=f"MAC Vendor: {vendor}",
            object_refs=[dst_mac_addr],
        )
        knowledge_nodes.append(dst_mac_vendor)
    except VendorNotFoundError:
        logger.info(f"Unable to find vendor for MAC: {log_dict['dst_mac']}")

    # Create source host nodes (and link to protocol node)
    ip_version = ipaddress.ip_address(log_dict["src_ip"]).version
    ip_src_addr = log_dict["src_ip"]
    if ip_version == 4:
        protocols = ["ipv4", "tcp", "dnp3"]
        source_addr = IPv4Address(value=ip_src_addr, resolves_to_refs=[src_mac_addr])
        knowledge_nodes.extend(get_ip_context(source_addr))

        ip_dest_addr = str(ipaddress.ip_address(log_dict["dst_ip"]))
        dest_addr = IPv4Address(value=ip_dest_addr, resolves_to_refs=[dst_mac_addr])
        knowledge_nodes.extend(get_ip_context(dest_addr))

    elif ip_version == 6:
        protocols = ["ipv6", "tcp", "dnp3"]
        ip_src_addr = str(ipaddress.ip_address(log_dict["src_ip"]))
        source_addr = IPv6Address(value=ip_src_addr, resolves_to_refs=[src_mac_addr])
        knowledge_nodes.extend(get_ip_context(source_addr))

        ip_dest_addr = str(ipaddress.ip_address(log_dict["dst_ip"]))
        dest_addr = IPv6Address(value=ip_dest_addr, resolves_to_refs=[dst_mac_addr])
        knowledge_nodes.extend(get_ip_context(dest_addr))

    dnp3_req_ext = DNP3RequestExt(
        dnp3_application_function=log_dict["dnp3_application_function"],
        dnp3_application_iin=log_dict["dnp3_application_iin"],
        dnp3_application_obj=log_dict["dnp3_application_obj"],
        dnp3_application_objq_code=log_dict["dnp3_application_objq_code"],
        dnp3_application_objq_index=log_dict["dnp3_application_objq_index"],
        dnp3_application_objq_prefix=log_dict["dnp3_application_objq_prefix"],
        dnp3_application_objq_range=log_dict["dnp3_application_objq_range"],
        dnp3_datalink_dst=log_dict["dnp3_datalink_dst"],
        dnp3_datalink_from_master=log_dict["dnp3_datalink_from_master"],
        dnp3_datalink_from_primary=log_dict["dnp3_datalink_from_primary"],
        dnp3_datalink_function=log_dict["dnp3_datalink_function"],
        dnp3_datalink_src=log_dict["dnp3_datalink_src"],
    )

    traffic = AICANetworkTraffic(
        protocols=protocols,
        start=request_time,
        src_ref=source_addr,
        dst_ref=dest_addr,
        src_port=int(log_dict["src_port"]),
        dst_port=int(log_dict["dst_port"]),
        extensions={"dnp3-request-ext": dnp3_req_ext},
    )
    knowledge_nodes.append(traffic)

    return knowledge_nodes


def knowledge_to_neo(
    nodes: List[_STIXBase],
) -> None:
    """
    Stores STIX objects in the knowledge graph database. This assumes all references
    refer to nodes that will exist after provided nodes have all been created.

    @param nodes: STIX Objects to store
    @type nodes: list
    @return: Whether the insert was successful
    @rtype: bool
    """

    nodes_to_add = []
    rels = []
    for node in nodes:
        # Sightings are relationships (SROs) - took me a while to figure that one out...
        if isinstance(node, Relationship) or isinstance(node, Sighting):
            rels.append(node)
        else:
            node_tuple = (
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
            nodes_to_add.append(node_tuple)
            for x in node.properties_populated():
                label = "_".join(x.split("_")[0:-1])
                try:
                    if x.endswith("_ref"):
                        rels.append(
                            Relationship(
                                relationship_type=label,
                                source_ref=node,
                                target_ref=node[x],
                            )
                        )
                    elif x.endswith("_refs"):
                        rels.extend(
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

    rels_to_add = []
    for rel in rels:
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
                rel_tuple = (
                    source,
                    rel[target],
                    label,
                    # Only include valid Relationship/Sighting properties
                    # https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_e2e1szrqfoan
                    {
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
                    True,
                )
                rels_to_add.append(rel_tuple)
        except ValueError as e:
            logger.error(f"Failed to add relation {rel} ({e})")

    # Strip out any relationships from the placeholder fake note root
    # (Note is always source)
    rels_to_add = [x for x in rels_to_add if x[1] != fake_note_root.id]

    if len(nodes_to_add) > 0:
        node_ids: List[str] = [x[0] for x in nodes_to_add]
        node_labels: List[str] = [x[1] for x in nodes_to_add]
        node_properties: List[dict[str, Any]] = [x[2] for x in nodes_to_add]
        graph.add_nodes(node_ids, node_labels, node_properties)

    if len(rels_to_add) > 0:
        node_a_ids: List[str] = [x[0] for x in rels_to_add]
        node_b_ids: List[str] = [x[1] for x in rels_to_add]
        rel_labels: List[str] = [x[2] for x in rels_to_add]
        rel_properties: List[dict[str, Any]] = [x[3] for x in rels_to_add]
        rel_directionality: List[bool] = [x[4] for x in rels_to_add]
        graph.add_relations(
            node_a_ids, node_b_ids, rel_labels, rel_properties, rel_directionality
        )
