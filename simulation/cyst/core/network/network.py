import networkx as nx

from abc import ABC, abstractmethod
from netaddr import IPAddress
from typing import Optional, List, Dict

from cyst.core.network.elements import Connection, Hop, Endpoint, Resolver, InterfaceImpl
from cyst.core.network.router import Router
from cyst.core.network.node import NodeImpl


class Network(Resolver):
    def __init__(self):
        self._nodes_by_id: Dict[str, NodeImpl] = {}
        self._nodes_by_ip: Dict[str, NodeImpl] = {}  # TODO: Does it make sense to have nodes_by_ip?
        self._graph = nx.Graph()

    def add_node(self, node: NodeImpl) -> None:
        # Ignore already present nodes
        if node.id in self._nodes_by_id:
            return

        self._nodes_by_id[node.id] = node

        for ip in node.ips:
            if ip not in self._nodes_by_ip:
                self._nodes_by_ip[ip] = []

            self._nodes_by_ip[ip].append(node)

        self._graph.add_node(node.id, node=node)

    def update_node_ip(self, node: NodeImpl, ip: str):
        self._nodes_by_ip[ip] = node

    def add_connection(self, n1: NodeImpl, n1_port_index: int, n2: NodeImpl, n2_port_index: int, net: str, connection: Connection = None) -> Connection:
        if not n1 or not n2:
            raise Exception("Could not add connection between nonexistent nodes")

        if not connection:
            connection = Connection()

        result = True
        error = ""
        if isinstance(n1, Router):
            if isinstance(n2, Router):
                result, error = n1._connect_router(n2, n2_port_index, n1_port_index)
            else:
                result, error = n1._connect_node(n2, n1_port_index, n2_port_index, net)
        elif isinstance(n2, Router):
            result, error = n2._connect_node(n1, n2_port_index, n1_port_index, net)
        # Direct connection
        else:
            InterfaceImpl.cast_from(n1.interfaces[n1_port_index]).connect_endpoint(Endpoint(n2.id, n2_port_index, n2.interfaces[n2_port_index].ip))
            InterfaceImpl.cast_from(n2.interfaces[n2_port_index]).connect_endpoint(Endpoint(n1.id, n1_port_index, n1.interfaces[n1_port_index].ip))

        if not result:
            raise Exception("Could not add connection between nodes {} and {}. Reason: {}".format(n1.id, n2.id, error))

        connection.hop = Hop(Endpoint(n1.id, n1_port_index), Endpoint(n2.id, n2_port_index))
        self._graph.add_edge(n1.id, n2.id, connection=connection)

        return connection

    def get_node_by_ip(self, ip: str = "") -> Optional[str]:
        if not ip:
            return None
        else:
            return self._nodes_by_ip.get(ip, None)

    # TODO: Is this useful at all?
    def get_neighbor_by_ip(self, node_id: str, ip: str) -> Optional[str]:
        neighbors = self._graph.neighbors(node_id)
        for neighbor in neighbors:
            if ip in neighbor["ips"]:
                return neighbor

    def get_node_by_id(self, id: str = "") -> Optional[NodeImpl]:
        if not id:
            return None
        else:
            return self._nodes_by_id.get(id, None)

    def get_nodes_by_type(self, type: str = "") -> List[NodeImpl]:
        if not type:
            return list(self._nodes_by_id.values())
        else:
            return [x for x in self._nodes_by_id.values() if x.type == type]

    def reset(self) -> None:
        self._nodes_by_id.clear()
        self._graph.clear()

    def resolve_ip(self, id: str, port: int) -> IPAddress:
        node = self.get_node_by_id(id)
        if not node:
            raise ValueError("Nonexistent node id provided for resolving")

        if port >= len(node.interfaces):
            raise ValueError("Nonexistent port id provided for resolving")

        return node.interfaces[port].ip
