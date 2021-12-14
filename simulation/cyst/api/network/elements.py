from abc import ABC, abstractmethod
from typing import NamedTuple, Optional
from netaddr import IPNetwork, IPAddress


class Route(NamedTuple):
    net: IPNetwork
    port: int
    metric: int = 100

    # Custom comparison to enable sorting in a priority queue
    def __lt__(self, other: 'Route') -> bool:
        # Metric is a way to override the default longest-prefix routing
        if self.metric != other.metric:
            return self.metric < other.metric

        # This should usually suffice
        if self.net.prefixlen != other.net.prefixlen:
            # The comparison is inversed, because we want the longest prefix to have the lowest value and highest priority
            return self.net.prefixlen > other.net.prefixlen

        # This is just a fallback to have some stability in it
        return self.net.ip < other.net.ip


class Port(ABC):

    @property
    @abstractmethod
    def ip(self) -> Optional[IPAddress]:
        pass

    @property
    @abstractmethod
    def mask(self) -> Optional[str]:
        pass

    @property
    @abstractmethod
    def net(self) -> Optional[IPNetwork]:
        pass


class Interface(Port, ABC):

    @property
    @abstractmethod
    def gateway(self) -> Optional[IPAddress]:
        pass


class Connection(ABC):
    pass
