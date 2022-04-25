import socket
import stix2

from stix2.utils import get_timestamp

from aica_django.connectors.AicaNeo4j import AicaNeo4j


def nmap_to_stix(scan_results):
    now = get_timestamp()

    # Not needed and make iteration below messy
    del scan_results["stats"]
    del scan_results["runtime"]

    scos = []
    sdos = []
    sros = []

    my_hostname = socket.gethostname()
    my_ipv4 = stix2.IPv4Address(
        value=socket.gethostbyname(my_hostname),
    )
    scos.append(my_ipv4)

    # Add scan source
    source_host = stix2.Infrastructure(
        type="infrastructure",
        name=my_hostname,
        infrastructure_types=["unknown"],
        last_seen=now,
    )
    source_ip_rel = stix2.Relationship(
        relationship_type="consists-of",
        source_ref=source_host,
        target_ref=my_ipv4,
    )
    sdos.append(source_host)
    sros.append(source_ip_rel)

    for host, data in scan_results.items():
        if scan_results[host]["state"]["state"] != "up":
            continue

        # Add scan target
        target_host = stix2.Infrastructure(
            type="infrastructure",
            name=host,
            infrastructure_types=["unknown"],
            last_seen=now,
        )
        sdos.append(target_host)

        # Add target NIC to target host
        nic = stix2.Infrastructure(
            type="infrastructure",
            name="nic",
            infrastructure_types=["unknown"],
            last_seen=now,
        )
        nic_host_rel = stix2.Relationship(
            relationship_type="consists-of",
            source_ref=target_host,
            target_ref=nic,
        )
        sdos.append(nic)
        sros.append(nic_host_rel)

        # Add target IPv4 to NIC
        ipv4_addr = stix2.IPv4Address(
            value=host,
        )
        ip_nic_rel = stix2.Relationship(
            relationship_type="consists-of",
            source_ref=nic,
            target_ref=ipv4_addr,
        )
        scos.append(ipv4_addr)
        sros.append(ip_nic_rel)

        if scan_results[host]["macaddress"]:
            # Add MAC to NIC
            mac_addr = stix2.MACAddress(
                value=scan_results[host]["macaddress"]["addr"],
            )
            nic_mac_rel = stix2.Relationship(
                relationship_type="consists-of",
                source_ref=nic,
                target_ref=mac_addr,
            )
            scos.append(mac_addr)
            sros.append(nic_mac_rel)

            if "vendor" in scan_results[host]["macaddress"]:
                # Add firmware to NIC
                nic_firmware = stix2.Software(
                    name="Network Interface",
                    vendor=scan_results[host]["macaddress"]["vendor"],
                )
                nic_firmware_rel = stix2.Relationship(
                    relationship_type="consists-of",
                    source_ref=nic,
                    target_ref=nic_firmware,
                )
                scos.append(nic_firmware)
                sros.append(nic_firmware_rel)

        for hostname in scan_results[host]["hostname"]:
            domain_name = stix2.DomainName(
                value=hostname["name"],
            )
            domain_ip_rel = stix2.Relationship(
                relationship_type="resolves_to",
                source_ref=domain_name,
                target_ref=ipv4_addr,
            )
            scos.append(domain_name)
            sros.append(domain_ip_rel)

        if len(scan_results[host]["osmatch"]) > 1:
            os = scan_results[host]["osmatch"][0]
            operating_system = stix2.Software(
                name=os["name"],
                cpe=os["cpe"],
                vendor=os["osclass"]["vendor"],
                version=os["osclass"]["osgen"],
            )
            host_os_rel = stix2.Relationship(
                relationship_type="consists-of",
                source_ref=target_host,
                target_ref=operating_system,
            )
            scos.append(operating_system)
            sros.append(host_os_rel)

        for port in scan_results[host]["ports"]:
            if port["state"] == "open":
                # Best fit STIX2.1 has...
                open_port = stix2.NetworkTraffic(
                    type="network-traffic",
                    protocols=[port["protocol"]],
                    dst_port=port["portid"],
                    src_ref=my_ipv4,
                    dst_ref=ipv4_addr,
                    is_active=False,
                )
                scos.append(open_port)

    return scos, sdos, sros


def stix_to_neo(
    neo_host=None, neo_user=None, neo_password=None, scos=None, sdos=None, sros=None
):
    node_ignore_keys = [
        "id",
        "type",
        "spec_version",
    ]
    rel_ignore_keys = [
        "type",
        "spec_version",
        "relationship_type",
        "source_ref",
        "target_ref",
    ]

    graph = AicaNeo4j(host=neo_host, user=neo_user, password=neo_password)

    for sco in scos:
        graph.add_node(
            sco["id"],
            sco["type"],
            {k: v for k, v in sco.items() if k not in node_ignore_keys},
        )
        # STIX doesn't have a suitable relationship to use here
        if sco["type"] == "network-traffic":
            network_src_rel = {
                "relationship_type": "communicates_to",
                "source_ref": sco["src_ref"],
                "target_ref": sco["id"],
            }
            network_src_rel.update(sco)
            sros.append(network_src_rel)

            network_dst_rel = {
                "relationship_type": "communicates_to",
                "source_ref": sco["id"],
                "target_ref": sco["dst_ref"],
            }
            network_dst_rel.update(sco)
            sros.append(network_dst_rel)

    for sdo in sdos:
        graph.add_node(
            sdo["id"],
            sdo["type"],
            {k: v for k, v in sdo.items() if k not in node_ignore_keys},
        )

    for sro in sros:
        graph.add_relation(
            sro["relationship_type"],
            sro["source_ref"],
            sro["target_ref"],
            {k: v for k, v in sro.items() if k not in rel_ignore_keys},
        )
