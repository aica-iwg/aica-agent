import fcntl
import logging
import netifaces  # type: ignore
import nmap3  # type: ignore
import os
import re
import time
from hashlib import sha256
from netaddr import IPAddress  # type: ignore

from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(name="periodic-network-scan")
def periodic_network_scan(nmap_target: str = None, nmap_args: str = None) -> None:
    logger.info(f"Running {__name__}: periodic-network-scan")
    while True:
        if nmap_args:
            network_scan(nmap_target, nmap_args)
        else:
            network_scan(nmap_target)

        time.sleep(int(os.getenv("NETWORK_SCAN_INTERVAL_MINUTES") or 0) * 60)


@shared_task(name="network-scan")
def network_scan(
    nmap_target: str = None, nmap_args: str = "-O -Pn --osscan-limit --host-timeout=30"
) -> dict:
    targets = []
    if not nmap_target:
        # Scan apparently local subnet(s)
        for interface in netifaces.interfaces():
            if re.match(r"^(lo|utun|tun|ip6tnl)", interface):
                continue
            addresses = netifaces.ifaddresses(interface)
            for k, v in addresses.items():
                if k == netifaces.AF_INET:
                    for address in v:
                        cidr = IPAddress(address["netmask"]).netmask_bits()
                        target = f"{address['addr']}/{cidr}"
                        targets.append(target)
    else:
        # Scan requested target
        targets.append(nmap_target)

    scan_results = dict()
    for target in targets:
        hasher = sha256()
        hasher.update(target.encode("utf-8"))
        host_hash = hasher.hexdigest()
        with open(f"/var/lock/aica-nmap-scan-{host_hash}", "w") as lockfile:
            try:
                fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                logging.warning(
                    "Couldn't obtain lock to run nmap scan of target, "
                    "existing scan in-progress?"
                )
                return {}

        nmap = nmap3.Nmap()
        logging.debug(f"Scanning {target} with {nmap_args}")
        scan_result = nmap.scan_top_ports(target, args=nmap_args)
        scan_results.update(scan_result)

    return scan_results
