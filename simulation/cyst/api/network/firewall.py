from abc import ABC, abstractmethod
from enum import Enum
from typing import List, NamedTuple, Optional, Tuple
from netaddr import IPAddress, IPNetwork


class FirewallPolicy(Enum):
    ALLOW = 0,
    DENY = 1


class FirewallChainType(Enum):
    INPUT = 0,
    OUTPUT = 1,
    FORWARD = 2


class FirewallRule(NamedTuple):
    src_net: IPNetwork
    dst_net: IPNetwork
    service: str
    policy: FirewallPolicy


class Firewall(ABC):
    @abstractmethod
    def list_rules(self, chain: Optional[FirewallChainType] = None) -> List[
        Tuple[FirewallChainType, FirewallPolicy, List[FirewallRule]]]:
        pass

    @abstractmethod
    def add_local_ip(self, ip: IPAddress) -> None:
        pass

    @abstractmethod
    def remove_local_ip(self, ip: IPAddress) -> None:
        pass

    @abstractmethod
    def add_rule(self, chain: FirewallChainType, rule: FirewallRule) -> None:
        pass

    @abstractmethod
    def remove_rule(self, chain: FirewallChainType, index: int) -> None:
        pass

    @abstractmethod
    def set_default_policy(self, chain: FirewallChainType, policy: FirewallPolicy) -> None:
        pass

    @abstractmethod
    def get_default_policy(self, chain: FirewallChainType) -> FirewallPolicy:
        pass

    @abstractmethod
    def evaluate(self, src_ip: IPAddress, dst_ip: IPAddress, dst_service: str) -> Tuple[bool, int]:
        pass
