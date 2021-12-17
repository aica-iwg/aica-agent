from abc import ABC, abstractmethod
from typing import List, Union, Optional, Tuple, Dict
from netaddr import IPAddress

from cyst.api.host.service import Service
from cyst.api.network.elements import Interface


class Node(ABC):

    @property
    @abstractmethod
    def type(self) -> str:
        pass

    @property
    @abstractmethod
    def services(self) -> Dict[str, Service]:
        pass

    @property
    @abstractmethod
    def shell(self) -> Optional[Service]:
        pass

    @property
    @abstractmethod
    def interfaces(self) -> List[Interface]:
        pass

    @property
    @abstractmethod
    def ips(self) -> List[IPAddress]:
        pass

    @abstractmethod
    def gateway(self, ip: Union[str, IPAddress] = "") -> Optional[Tuple[IPAddress, int]]:
        pass

    @abstractmethod
    def __str__(self) -> str:
        pass
