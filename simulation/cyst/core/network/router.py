from cachetools.lru import LRUCache
from copy import deepcopy
from enum import Enum
from typing import List, Union, Optional, Tuple, Dict, NamedTuple
from netaddr import IPAddress, IPNetwork

from cyst.api.environment.environment import EnvironmentMessaging
from cyst.api.environment.message import StatusValue, StatusOrigin, MessageType, Status
from cyst.api.network.elements import Route
from cyst.api.network.node import Node
from cyst.api.network.firewall import FirewallPolicy, FirewallRule, FirewallChainType

from cyst.core.environment.message import MessageImpl, RequestImpl, ResponseImpl
from cyst.core.network.node import NodeImpl
from cyst.core.network.elements import PortImpl, InterfaceImpl, Endpoint, Resolver
from cyst.core.network.firewall import FirewallImpl


class Router(NodeImpl):

    def __init__(self, id: str, env: EnvironmentMessaging) -> None:

        super(Router, self).__init__(id, "Router")

        self._env: EnvironmentMessaging = env
        self._ports: List[PortImpl] = []
        self._local_ips: Dict[IPAddress, int] = {}
        self._local_nets: List[IPNetwork] = []
        self._routes: List[Route] = []
        # Cache storing last 64 requests
        self._request_cache: LRUCache = LRUCache(64)

        # set a firewall, which controls routing policy
        self._fw = FirewallImpl(env)

        self._span_ports = set()

    @property
    def interfaces(self) -> List[PortImpl]:
        return self._ports

    # Port removal not supported, but they can be overwritten by using already used port index
    # Otherwise the port index is just incremented
    def add_port(self, ip: Union[str, IPAddress] = "", mask: str = "", index: int = -1) -> int:
        new_index = index
        if index == -1:
            new_index = len(self._ports)

        self._ports.append(PortImpl(ip, mask, new_index))
        return new_index

    def port_net(self, index: int) -> Optional[IPNetwork]:
        return self._ports[index].net

    def add_route(self, route: Route) -> None:
        self._routes.append(route)
        self._routes.sort()

    def list_routes(self) -> List[Route]:
        return self._routes

    # Check if IP belongs to local net
    def _is_local_ip(self, ip: IPAddress) -> bool:
        for net in self._local_nets:
            if ip in net:
                return True
        return False

    def _connect_node(self, node: NodeImpl, router_index: int = -1, node_index: int = 0, net: str = "") -> Tuple[bool, str]:
        # If both a specific router index and network designation si provided, bail out
        if router_index != -1 and net:
            return False, "Cannot specify both router index and network designation"

        # No router port was selected, new one is dynamically added
        new_router_index = router_index
        if router_index == -1:
            # Net designation was provided, use it for the port
            if net:
                network = IPNetwork(net)
                new_router_index = self.add_port(next(network.iter_hosts()), str(network.netmask))
            # otherwise add and unconfigured port
            else:
                new_router_index = self.add_port()

        new_node_index = node_index
        router_port = self._ports[new_router_index]
        if new_node_index != -1:
            node_interface = node.interfaces[new_node_index] if node.interfaces else None
        else:
            node_interface = None

        # Get DHCP status
        dhcp = False if node_interface and node_interface.ip else True

        assigned_ip = None

        if dhcp:
            if new_router_index == -1 or not router_port.net:
                return False, "Trying to connect a node to a router port that does not support automatic address assignment"

            # Find a suitable host from router's network
            for h in router_port.net.iter_hosts():
                if h != router_port.ip and h not in self._local_ips:
                    assigned_ip = h
                    break

            if not assigned_ip:
                return False, "Do not have any more addresses to allocate in the range {}".format(str(router_port.net))

            node_interface = InterfaceImpl(assigned_ip, str(router_port.net.netmask))
            new_node_index = node.add_interface(node_interface)

        else:
            # If the router does not have network configured, accept the one by the connected node
            if not router_port.net:
                router_port.set_ip(node_interface.gateway)
                router_port.set_net(node_interface.net)

            # Check if there is a conflict between router's IP and expected IP from connected node
            if node_interface.gateway != router_port.ip:
                return False, "The connected node expects gateway to have an IP {}, but it has an IP {}".format(str(node_interface.gateway), str(router_port.ip))

            assigned_ip = node_interface.ip

        # Add the host ip to the list of local ips and the port net to the list of local networks
        self._local_ips[assigned_ip] = router_port.index
        if router_port.net not in self._local_nets:
            self._local_nets.append(router_port.net)

        # Set endpoints on both ends
        router_port.connect_endpoint(Endpoint(node.id, new_node_index, node_interface.ip))
        node_interface.connect_gateway(router_port.ip, self.id, new_router_index)

        return True, ""

    def _connect_router(self, router: 'Router', remote_port_index: int = -1, local_port_index: int = -1) -> Tuple[bool, str]:

        # Create missing ports if needed
        remote_port = remote_port_index
        local_port = local_port_index

        if remote_port == -1:
            remote_port = router.add_port()

        if local_port == -1:
            local_port = self.add_port()

        self._ports[local_port].connect_endpoint(Endpoint(router.id, remote_port))
        router._ports[remote_port].connect_endpoint(Endpoint(self.id, local_port))

        # After routers' connection, routes must be added manually

        return True, ""

    def add_routing_rule(self, rule: FirewallRule) -> None:
        # This can be brittle, but we assume that FW is always preprocessor no. 1
        self._fw.add_rule(FirewallChainType.FORWARD, rule)

    def remove_routing_rule(self, index) -> None:
        self._fw.remove_rule(FirewallChainType.FORWARD, index)

    def list_routing_rules(self) -> List[Tuple[FirewallChainType, FirewallPolicy, List[FirewallRule]]]:
        return self._fw.list_rules(FirewallChainType.FORWARD)

    def set_default_routing_policy(self, policy: FirewallPolicy) -> None:
        self._fw.set_default_policy(FirewallChainType.FORWARD, policy)

    def get_default_routing_policy(self) -> FirewallPolicy:
        return self._fw.get_default_policy(FirewallChainType.FORWARD)

    def routes(self, src: IPAddress, dst: IPAddress, service: str) -> Optional[PortImpl]:
        # I lost the code, so this may or may not be enough here
        # It is a butchered version of process message
        port = self._local_ips.get(dst, -1)
        if port != -1:
            if src in self._ports[port].net or self._fw.evaluate(src, dst, service)[0]:
                return self._ports[port]
            else:
                return None

        # TODO: i do not understand this check
        elif self._is_local_ip(dst):
            return None

        else:
            for route in self._routes:
                if dst in route.net:
                    return self._ports[route.port]

        return None

    # TODO: This functionality will require much more love. Currently it is a minimum viable implementation
    def set_span_port(self, port_index: int):
        self._span_ports.add(port_index)

    def process_message(self, message: MessageImpl) -> Tuple[bool, int]:
        # All messages are copied into span ports, if there are any
        if self._span_ports:
            for port in self._span_ports:
                message_copy = deepcopy(message)
                message_copy.set_next_hop(Endpoint(self.id, port), self._ports[port].endpoint)
                self._env.send_message(message_copy, 0)

        # Do not process messages that are going on for far too long
        if message.decrease_ttl() == 0:
            m = ResponseImpl(message, status=Status(StatusOrigin.NETWORK, StatusValue.FAILURE), content="TTL expired", session=message.session)
            m.set_next_hop()
            self._env.send_message(m, 1)
            return False, 1

        # If message is still going through a session then pass it along where it should go...
        if message.in_session:
            message.set_next_hop()
            return True, 1

        # ...the same goes for responses, which travel back from whence they came
        if message.type == MessageType.RESPONSE:
            port = self._request_cache.get(message.id, -1)
            if port != -1:
                message.set_next_hop(Endpoint(self.id, port, self._ports[port].ip), self._ports[port].endpoint)
                return True, 1

        # Unless the request vanished from cache - then we have to try to to deliver it the old-fashioned way

        # Check for messages running around in circles
        if message.type == MessageType.REQUEST:
            port = self._request_cache.get(message.id, -1)
            if port != -1:
                m = ResponseImpl(message, status=Status(StatusOrigin.NETWORK, StatusValue.FAILURE),
                                 content="Message stuck in a cycle", session=message.session)
                # The next hop is automatically calculated because it is a response
                m.set_next_hop(Endpoint(self.id, port, self._ports[port].ip), self._ports[port].endpoint)
                self._env.send_message(m, 1)
                return False, 1

        # TODO evaluate permeability between networks!
        # When looking at the current target, the router must also check, if the target is within the same network as
        # is the net of the arriving port
        # The same goes for router's constituency

        # The rule of thumb is - you can cross from local networks to remote networks, but you can't cross between
        # local networks and you can't go from remote network to local networks
        # Port forwarding is in the current state impossible and is ignored to reduce scope
        # Addendum (until more robust solution is found) - the aforementioned holds, but in addition, the FW is
        # consulted to check for explicitly allowed paths for crossing between local networks

        # Check if the target is linked to a router port
        port = self._local_ips.get(message.dst_ip, -1)
        if port != -1:
            # It is and (it is in the same network or have explicit permission in the firewall/routing policy)
            # This would break when the message traversed more routers
            if (self._ports[message.current.port].net and message.dst_ip in self._ports[message.current.port].net) or self._fw.evaluate(message.non_session_path[0].src.ip, message.dst_ip, message.dst_service)[0]:
                src_ip = self._ports[port].ip
                message.set_next_hop(Endpoint(self.id, port, src_ip), self._ports[port].endpoint)
                # Store the info about incoming port to enable pass-through of responses
                if message.type == MessageType.REQUEST:
                    self._request_cache[message.id] = message.current.port
                return True, 1
            # It is, but in another network
            else:
                m = ResponseImpl(message, status=Status(StatusOrigin.NETWORK, StatusValue.FAILURE),
                             content="Host unreachable", session=message.session)
                # The next hop is automatically calculated because it is a response
                m.set_next_hop()
                self._env.send_message(m, 1)
                return False, 1

        # It is not, but belongs to router's constituency
        elif self._is_local_ip(message.dst_ip):
            m = ResponseImpl(message, status=Status(StatusOrigin.NETWORK, StatusValue.FAILURE), content="Host unreachable", session=message.session)
            # The next hop is automatically calculated because it is a response
            m.set_next_hop()
            self._env.send_message(m, 1)
            return False, 1
        # Try to send it somewhere
        else:
            for route in self._routes:
                if message.dst_ip in route.net:
                    message.set_next_hop(Endpoint(self.id, route.port, self._ports[route.port].ip), self._ports[route.port].endpoint)
                    # Store the info about incoming port to enable pass-through of responses
                    if message.type == MessageType.REQUEST:
                        self._request_cache[message.id] = message.current.port
                    return True, 1

            m = ResponseImpl(message, status=Status(StatusOrigin.NETWORK, StatusValue.FAILURE), content="Network address {} not routable".format(message.dst_ip), session=message.session)
            m.set_next_hop()
            self._env.send_message(m, 1)
            return False, 1

    @staticmethod
    def cast_from(o: Node) -> 'Router':
        if isinstance(o, Router):
            return o
        else:
            raise ValueError("Malformed underlying object passed with the Node interface")