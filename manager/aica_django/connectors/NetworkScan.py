"""
This module contains all code relevant to interacting with Nmap scans

Functions:
    network_scan: Launch a scan using the nmap3 library and return the results
    periodic_network_scan: Start a periodically recurring scan job
"""

import datetime
import fasteners  # type: ignore
import logging
import netifaces  # type: ignore
import nmap3  # type: ignore
import os
import re2 as re
import time

from hashlib import sha256
from netaddr import IPAddress  # type: ignore
from celery import shared_task
from celery.utils.log import get_task_logger
from typing import Any, Dict

from aica_django.connectors.DocumentDatabase import AicaMongo
from aica_django.microagents.knowledge_base import record_nmap_scan

logger = get_task_logger(__name__)


@shared_task(name="network-scan")
def network_scan(
    nmap_target: str = "",
    nmap_args: str = "-O -Pn --osscan-limit --host-timeout=7",
    min_scan_interval: int = 300,
) -> Dict[str, Any]:
    """
    Start a network scan, with defined or default parameters. Uses lockfile and MongoDB record
    to ensure only one scan per target at a time, and not more frequently than the minimum interval
    (though note targets could overlap).

    @param nmap_target: The target (host, subnet - anything accepted by Nmap) to scan
    @type nmap_target: str
    @param nmap_args: Any arguments to nmap scanner, defaults to pingless, OS-scan
    @type nmap_args: str
    @param min_scan_interval: The most frequent interval to run a scan
    @type min_scan_interval: int
    @return: Results of scan
    @rtype: dict
    """
    targets = []
    logger.info(f"Running network_scan on {nmap_target}")
    if nmap_target == "":
        # Scan apparently local subnet(s)
        for interface in netifaces.interfaces():
            if re.match(r"^(lo|utun|tun|ip6tnl)", interface):
                continue
            addresses = netifaces.ifaddresses(interface)
            for k, v in addresses.items():
                if k == netifaces.AF_INET:
                    try:
                        for address in v:
                            cidr = IPAddress(address["mask"]).netmask_bits()
                            target = f"{address['addr']}/{cidr}"
                            targets.append(target)
                    except KeyError:
                        logger.warning(
                            f"Couldn't add interface {interface}'s ({v}) subnet to initial scans"
                        )

    else:
        # Scan requested target
        targets.append(nmap_target)

    scan_results = dict()
    aica_mongo = AicaMongo()
    for target in targets:
        hasher = sha256()
        hasher.update(target.encode("utf-8"))
        host_hash = hasher.hexdigest()
        last_scantime = aica_mongo.get_last_network_scan_timestamp(host_hash)
        if last_scantime < datetime.datetime.now().timestamp() - min_scan_interval:
            scan_lock = fasteners.InterProcessLock(
                f"/var/lock/aica-nmap-scan-{host_hash}"
            )
            with scan_lock:
                nmap = nmap3.Nmap()
                logging.debug(f"Scanning {target} with {nmap_args}")
                current_time = datetime.datetime.now().timestamp()
                scan_result = nmap.scan_top_ports(target, args=nmap_args)
                aica_mongo.record_network_scan(host_hash, current_time)
                scan_results.update(scan_result)
        else:
            logging.warning(
                f"Host {target} has been scanned recently, not scanning again"
            )

    if len(scan_results) > 0:
        logger.info(f"record_nmap_scan for: {nmap_target}")
        record_nmap_scan.apply_async(args=(scan_results,))
    else:
        logger.info(f"No nmap results for: {nmap_target}")

    return scan_results


@shared_task(name="periodic-network-scan")
def periodic_network_scan(nmap_target: str = "", nmap_args: str = "") -> None:
    """
    Periodically re-scan the specified target, with the provided arguments. Interval controlled
    by the NETWORK_SCAN_INTERVAL_MINUTES environment variable.

    @param nmap_target: The target (host, subnet - anything accepted by Nmap) to scan
    @type nmap_target: str
    @param nmap_args: Any arguments to nmap scanner, defaults to pingless, OS-scan
    @type nmap_args: str
    """

    logger.info(f"Running {__name__}: periodic-network-scan")
    while True:
        if nmap_args != "":
            logger.info(
                f"Running {__name__}:{nmap_target} {nmap_args}: periodic-network-scan with args"
            )
            results = network_scan(nmap_target, nmap_args)
        else:
            logger.info(f"Running {__name__}:{nmap_target} : periodic-network-scan")
            results = network_scan(nmap_target)

        time.sleep(int(os.getenv("NETWORK_SCAN_INTERVAL_MINUTES") or 0) * 60)
