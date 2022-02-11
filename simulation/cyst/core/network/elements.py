from abc import ABC, abstractmethod
from netaddr import IPAddress, IPNetwork
from typing import NamedTuple, Optional, Union

from cyst.api.network.elements import Port, Interface, Connection


class Resolver(ABC):
    @abstractmethod
    def resolve_ip(self, id: str, port: int) -> IPAddress:
        pass


class Endpoint:
    def __init__(self, id: str, port: int, ip: Optional[IPAddress] = None):
        self._id = id
        self._port = port
        self._ip = ip

    @property
    def id(self) -> str:
        return self._id

    @property
    def port(self) -> int:
        return self._port

    @property
    def ip(self) -> IPAddress:
        return self._ip

    @ip.setter
    def ip(self, value: IPAddress) -> None:
        self._ip = value

    def __str__(self) -> str:
        return "Endpoint(ID: {}, Port: {}, IP: {})".format(self._id, self._port, self._ip)

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, other: 'Endpoint') -> bool:
        return self.id == other.id and self.port == other.port and self.ip == other.ip


class Hop(NamedTuple):
    src: Endpoint
    dst: Endpoint

    # Necessary for reverse session to make sense
    def swap(self) -> 'Hop':
        return Hop(self.dst, self.src)


class ConnectionImpl(Connection):
    def __init__(self, hop: Optional[Hop] = None) -> None:
        self._hop = hop

    @property
    def hop(self) -> Hop:
        return self._hop

    @hop.setter
    def hop(self, value: Hop) -> None:
        self._hop = value


class PortImpl(Port):
    def __init__(self, ip: Union[str, IPAddress] = "", mask: str = "", index: int = 0) -> None:
        self._ip: Optional[IPAddress] = None
        self._net: Optional[IPNetwork] = None
        self._index: int = index
        self._endpoint: Optional[Endpoint] = None

        if ip:
            if type(ip) is str:
                self._ip = IPAddress(ip)
            else:
                self._ip = ip

        if mask:
            if not ip:
                raise Exception("Netmask cannot be specified without an IP address")
            if type(ip) is str:
                self._net = IPNetwork(ip + "/" + mask)
            else:
                self._net = IPNetwork(str(ip) + "/" + mask)

    @property
    def ip(self) -> Optional[IPAddress]:
        return self._ip

    def set_ip(self, value: Union[str, IPAddress]) -> None:
        if type(value) is str:
            self._ip = IPAddress(value)
        else:
            self._ip = value

        if self._net:
            # This str dance is sadly necessary, because IPNetwork does not enable changing of IP address
            if type(value) is str:
                self._net = IPNetwork(value + "/" + str(self._net.netmask))
            else:
                self._net = IPNetwork(str(value) + "/" + str(self._net.netmask))

    # Only IP address is returned as an object. Mask is for informative purposes outside construction, so it is
    # returned as a string
    @property
    def mask(self) -> Optional[str]:
        if self._net:
            return str(self._net.netmask)
        else:
            return None

    def set_mask(self, value: str) -> None:
        if not self._ip:
            raise Exception("Netmask cannot be specified without an IP address")

        # This str dance is necessary, because netaddr does not acknowledge changing IPNetwork IP address
        self._net = IPNetwork(str(self._ip) + "/" + value)

    @property
    def net(self) -> Optional[IPNetwork]:
        return self._net

    def set_net(self, value: IPNetwork) -> None:
        self._net = value

    @property
    def endpoint(self) -> Endpoint:
        return self._endpoint

    # There are no restrictions on connecting an endpoint to the port
    def connect_endpoint(self, endpoint: Endpoint) -> None:
        self._endpoint = endpoint

    @property
    def index(self) -> int:
        return self._index

    def set_index(self, value: int = 0) -> None:
        self._index = value

    # Returns true if given ip belongs to the network
    def routes(self, ip: Union[str, IPAddress] = ""):
        if ip in self._net:
            return True
        else:
            return False

    @staticmethod
    def cast_from(o: Port) -> 'PortImpl':
        if isinstance(o, PortImpl):
            return o
        else:
            raise ValueError("Malformed underlying object passed with the Port interface")


# Interface is just a port, which preserves gateway information (that is a port for end devices)
class InterfaceImpl(PortImpl, Interface):

    def __init__(self, ip: Union[str, IPAddress] = "", mask: str = "", index: int = 0):
        super(InterfaceImpl, self).__init__(ip, mask, index)

        self._gateway_ip: Optional[IPAddress] = None

        if self._ip and self._net:
            # Gateway is by default first host in the network
            self._gateway_ip = next(self._net.iter_hosts())

    def set_ip(self, value: Union[str, IPAddress]) -> None:
        super(InterfaceImpl, self).set_ip(value)

        if self._ip and self._net:
            # Gateway is by default first host in the network
            self._gateway_ip = next(self._net.iter_hosts())

    def set_net(self, value: IPNetwork) -> None:
        super(InterfaceImpl, self).set_net(value)
        self._gateway_ip = next(self._net.iter_hosts())

    def set_mask(self, value: str) -> None:
        super(InterfaceImpl, self).set_mask(value)
        self._gateway_ip = next(self._net.iter_hosts())

    @property
    def gateway(self) -> Optional[IPAddress]:
        return self._gateway_ip

    @property
    def gateway_id(self) -> Optional[str]:
        return self._endpoint.id

    def connect_gateway(self, ip: IPAddress, id: str, port: int = 0) -> None:
        if not self._gateway_ip:
            raise Exception("Trying to connect a gateway to an interface without first specifying network parameters")

        if self._gateway_ip != ip:
            raise Exception("Connecting a gateway with wrong configuration")

        self._endpoint = Endpoint(id, port, ip)

    @staticmethod
    def cast_from(o: Interface) -> 'InterfaceImpl':
        if isinstance(o, InterfaceImpl):
            return o
        else:
            raise ValueError("Malformed underlying object passed with the Interface interface")
