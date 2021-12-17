from netaddr import IPAddress
from typing import List, Union, Optional, Tuple, Dict

from cyst.core.network.elements import InterfaceImpl
from cyst.core.host.service import ServiceImpl

from cyst.api.host.service import Service, ActiveService
from cyst.api.environment.message import MessageType
from cyst.api.network.node import Node
from cyst.api.network.elements import Interface


class NodeImpl(Node):
    def __init__(self, id: str, type: str = "Node", ip: Union[str, IPAddress] = "", mask: str = "", shell: Service = None):
        self._id: str = id
        self._type: str = type
        self._interfaces: List[InterfaceImpl] = []
        self._services: Dict[str, ServiceImpl] = {}
        self._ip: Optional[IPAddress] = None
        if ip:
            self._interfaces.append(InterfaceImpl(ip, mask))
        self._shell = shell
        self._traffic_processors: List[ActiveService] = []

    @property
    def id(self) -> str:
        return self._id

    # ------------------------------------------------------------------------------------------------------------------
    # Node interface
    @property
    def type(self) -> str:
        return self._type

    @property
    def interfaces(self) -> List[Interface]:
        return self._interfaces

    @property
    def services(self) -> Dict[str, Service]:
        return self._services

    # Gateway returns both the IP address of the gateway and the port index
    def gateway(self, ip: Union[str, IPAddress] = "") -> Optional[Tuple[IPAddress, int]]:
        # If no IP is specified the the first gateway is used as a default gateway
        if not self._interfaces:
            return None

        # Explicit query for default gateway
        if not ip:
            return self._interfaces[0].gateway, 0

        # Checking all available routes for exact one
        for iface in self._interfaces:
            if iface.routes(ip):
                return iface.gateway, iface.index

        # Using a default one
        return self._interfaces[0].gateway, 0
    # ------------------------------------------------------------------------------------------------------------------

    @property
    def ips(self) -> List[IPAddress]:
        return [x.ip for x in self._interfaces]

    def add_interface(self, i: InterfaceImpl) -> int:
        # TODO Currently there is no control of interface overlaps. Question is whether it matters...
        self._interfaces.append(i)
        index = len(self._interfaces) - 1
        i.set_index(index)
        return index

    def process_message(self, message) -> int:
        if message.type == MessageType.ACK:
            return 0

        print("Processing message at node {}. {}".format(self.id, message))
        return 0

    @property
    def shell(self) -> Optional[Service]:
        return self._shell

    def set_shell(self, value: Service) -> None:
        self._shell = value

    def add_service(self, service: Service) -> None:
        s = ServiceImpl.cast_from(service)
        self._services[s.id] = s
        s.set_node(self._id)
        # TODO: create a mechanism for reasonable running of active services
        # Initiate active services
        # if not s.passive:
        #    s.active_service.run()

    def add_traffic_processor(self, value: ActiveService) -> None:
        self._traffic_processors.append(value)

    @property
    def traffic_processors(self) -> List[ActiveService]:
        return self._traffic_processors

    def __str__(self) -> str:
        return "Node: [Shell: {}, Services: {}, Interfaces: {}]".format(self.shell, self.services, self.interfaces)

    @staticmethod
    def cast_from(o: Node) -> 'NodeImpl':
        if isinstance(o, NodeImpl):
            return o
        else:
            raise ValueError("Malformed underlying object passed with the Node interface")