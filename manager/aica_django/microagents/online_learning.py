# This microagent is responsible for pulling in any external data relevant to decision-
# making by the agent and loading/sending it to the knowledge base microagent during
# runtime. Per the NCIA SOW this is to include the following information:
#
# * World Description
# * Competence
# * Purpose
# * Behavior
#
# It is scheduled to run on a periodic basis via the main celery app.

import fcntl
import logging
import nmap3
import socket
import stix2

from connectors.AicaNeo4j import AicaNeo4j
from celery.app import shared_task
from celery.utils.log import get_task_logger
from hashlib import sha1
from stix2.utils import get_timestamp

logger = get_task_logger(__name__)


@shared_task(name="ma-online-learning-load")
def load():
    # TODO
    print(f"Running {__name__}: load")


@shared_task(name="ma-online_learning-nmap-to-stix")
def network_scan(nmap_target, nmap_args="-O -Pn --osscan-limit --host-timeout=60"):
    hasher = sha1()
    hasher.update(nmap_target.encode("utf-8"))
    host_hash = hasher.hexdigest()
    with open(f"/var/lock/aica-nmap-scan-{host_hash}", "rw") as lockfile:
        try:
            fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            logging.warning(
                "Couldn't obtain lock to run nmap scan of target, "
                "existing scan in-progress?"
            )
            return False

    # --Scan target(s) and add to graph -- #

    nmap = nmap3.Nmap()
    results = nmap.scan_top_ports(nmap_target, args=nmap_args)
    graph = AicaNeo4j()  # noqa: F841 (temp until used)

    my_hostname = socket.gethostname()
    my_ipv4 = stix2.IPv4Address(
        value=socket.gethostbyname(my_hostname),
    )
    now = get_timestamp()

    # Not needed and make iteration below messy
    del results["stats"]
    del results["runtime"]

    for host, data in results.items():
        if results[host]["state"]["state"] != "up":
            continue

        mac_addr = None
        refs = []
        if results[host]["macaddress"]:
            mac_addr = stix2.MACAddress(
                value=results[host]["macaddress"]["addr"],
                # vendor
            )
            refs.append(mac_addr)

        ipv4_addr = stix2.IPv4Address(
            value=host,
            resolves_to_refs=[mac_addr] if mac_addr else None,
        )
        refs.append(ipv4_addr)

        for hostname in results[host]["hostname"]:
            domain_name = stix2.DomainName(
                value=hostname["name"],
                resolves_to_refs=[ipv4_addr],
            )
            refs.append(domain_name)

        if len(results[host]["osmatch"]) > 1:
            os = results[host]["osmatch"][0]
            operating_system = stix2.Software(
                name=os["name"],
                cpe=os["cpe"],
                vendor=os["osclass"]["vendor"],
                version=os["osclass"]["osgen"],
            )
            refs.append(operating_system)

        for port in results[host]["ports"]:
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

                observation = stix2.ObservedData(  # noqa: F841 (temp until used)
                    first_observed=now,
                    last_observed=now,
                    number_observed=1,
                    object_refs=[*refs, open_port],
                )
