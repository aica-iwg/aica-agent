from netaddr import *  # pylint: disable=unused-wildcard-import
from typing import Optional
from cyst.api.logic.access import Authorization

from cyst.services.ucb_attacker.attacker_memory import AttackerMemory


class TargetSelector():

    def __init__(self, mem: AttackerMemory):
        self._mem = mem
        self._host = ""
        self._service = ""
        self._auth = None
        self._exploit = None

    def set_rit_and_submodule(self, rit: str, submodule) -> None:
        self._rit = rit
        self._submodule = submodule

    def ready(self) -> bool:
        return True

    def host(self) -> IPAddress:
        return self._host

    def service(self) -> str:
        return self._service

    def auth(self) -> Optional[Authorization]:
        return self._auth

    def exploit(self) -> Optional[str]:
        return self._exploit

    def session(self) -> str:
        if self._mem is None:
            return None
        return self._mem.get_session(self.host())

    @property
    def action_score(self) -> Optional[float]:
        if self._mem is None:
            return None
        return self._mem.actions.get_item_score(self._rit)

    @property
    def host_score(self) -> Optional[float]:
        if self._mem is None:
            return None
        return self._mem.hosts_ucb.get_item_score(self._host)

    @property
    def auth_score(self) -> Optional[float]:
        if self._mem is None:
            return None
        if self._host is not None and self._host != "":
            return self._mem.auths.get_item_score(self._auth)
        return None

    @property
    def service_score(self) -> Optional[float]:
        if self._mem is None:
            return None
        if self._host is not None and self._host != "" and "host_discovery" not in self._rit:
            return self._mem.hosts[self._host].services_ucb.get_item_score(self._service)
        return None


class HostSelector(TargetSelector):
    # selects a host to scan for services
    def ready(self) -> bool:
        self._host = self._mem.get_data(self._rit, lambda host: True)
        return self._host is not None


class ServiceSelector(TargetSelector):
    # selects a service to scan for exploits
    def ready(self) -> bool:
        self._host, self._service = \
            self._mem.get_data(self._rit,
                               lambda host: True,
                               lambda service: self._rit not in service.tested_rits)
        return self._host is not None


class ServiceAuthSelector(TargetSelector):
    # selects a service to scan for exploits

    def ready(self) -> bool:
        self._host, self._service, self._auth = \
            self._mem.get_data(self._rit,
                               lambda host: host.ready_for_rit(self._rit),
                               lambda service: True,
                               return_auth=True)
        return self._host is not None


class ServiceExploitSelector(TargetSelector):
    # selects a service to scan for exploits

    def ready(self) -> bool:
        self._host, self._service, self._exploit = \
            self._mem.get_data(self._rit,
                               lambda host: host.ready_for_rit(self._rit),
                               lambda service: True,
                               return_exploit=True)
        return self._host is not None


class ServiceExploitAuthSelector(TargetSelector):
    # selects a service to scan for exploits

    def ready(self) -> bool:
        self._host, self._service, self._exploit, self._auth = \
            self._mem.get_data(self._rit,
                               lambda host: host.ready_for_rit(self._rit),
                               lambda service: True,
                               return_exploit=True,
                               return_auth=True)
        return self._host is not None


class LateralMovementSelector(TargetSelector):
    def ready(self) -> bool:
        self._host, self._auth = \
            self._mem.get_data(self._rit,
                               lambda host: host.ready_for_rit(self._rit),
                               return_auth=True)
        return self._host is not None
