"""
This module contains any code necessary to interact with Neo4j's graph database.

Classes:
    AicaNeo4j: The object to instantiate to create a persistent interface with Neo4j
"""

import logging
import os
import py2neo.errors  # type: ignore

from py2neo import Graph, Node, NodeMatcher, Relationship
from urllib.parse import quote_plus
from typing import Any, Dict

# Try to keep these as minimal and orthogonal as possible
defined_node_labels = [
    "Alert",
    "AttackSignature",
    "AttackSignatureCategory",
    "AutonomousSystemNumber",
    "DNSRecord",
    "FilePath",
    "Firmware",
    "PhysicalLocation",
    "Host",
    "HttpRequest",
    "Identity",  # i.e., an actual human
    "IPv4Address",
    "IPv6Address",
    "MACAddress",
    "NetworkInterface",
    "NetworkEndpoint",  # Observed source/destination port/ip pair
    "NetworkPort",  # Static reference to port info
    "NetworkProtocol",
    "NetworkTraffic",
    "Organization",  # e.g., corporation, agency
    "Process",
    "Subnet",
    "Software",
    "User",  # i.e., principal on a system
    "Vendor",
]
defined_relation_labels = [
    "CONNECTED_TO",
    "COMMUNICATES_TO",
    "COMPONENT_OF",
    "HAS_ADDRESS",
    "HAS_PORT",
    "IS_TYPE",
    "LOCATED_IN",
    "MANUFACTURES",
    "MEMBER_OF",
    "RESIDES_IN",
    "RESOLVES_TO",
    "RUNS_ON",
    "STORED_ON",
    "TRIGGERED_BY",
    "USED_BY",
    "WORKS_IN",
]


class AicaNeo4j:
    """
    The object to instantiate to create a persistent interface to Neo4j
    """

    def __init__(
        self, host: str = "", user: str = "", password: str = "", port: int = -1
    ):
        """
        Initialize a new AiceNeo4j object.

        @param host: The Neo4j host, read from environment variable NEO4J_SERVER if not provided
        @type host: str
        @param user: The Neo4j user, read from environment variable NEO4J_USER if not provided
        @type user: str
        @param password: The Neo4j user password, read from environment variable NEO4J_PASS if not provided
        @type password: str
        @param port: The Neo4j server port, read from environment variable NEO4J_PORT or defaults to 7687
        @type port: int
        """

        host = host if host != "" else quote_plus(str(os.getenv("NEO4J_HOST")))
        port = port if port >= 0 else int(quote_plus(str(os.getenv("NEO4J_PORT"))))
        user = user if user != "" else quote_plus(str(os.getenv("NEO4J_USER")))
        password = (
            password if password != "" else quote_plus(str(os.getenv("NEO4J_PASSWORD")))
        )
        uri = f"bolt://{host}:{port}"

        self.graph = Graph(uri, auth=(user, password))

    def create_constraints(self) -> bool:
        """
        Initial function to create Neo4j graph database uniqueness constraints on startup.

        @return: True once complete.
        @rtype: bool
        """

        tx = self.graph.begin()
        for label in defined_node_labels:
            unique_id = f"""CREATE CONSTRAINT unique_id_{label} IF NOT EXISTS
                            FOR (n:{label})
                            REQUIRE n.id IS UNIQUE"""
            tx.run(unique_id)
        self.graph.commit(tx)

        return True

    def add_node(
        self, node_name: str, node_label: str, node_properties: Dict[str, Any]
    ) -> bool:
        """
        Adds a node with specified parameters to the graph database.

        @param node_name: Unique name to use for this node
        @type node_name: str
        @param node_label: Label to use for this node, must be defined in defined_node_labels
        @type node_label: str
        @param node_properties: Any other metadata to store with this node
        @type node_properties: dict
        @return: True if addition was successful, false otherwise.
        @rtype: bool
        @raise: ValueError: if node_label is not a predefined type in defined_node_labels
        """

        if node_label not in defined_node_labels:
            raise ValueError(f"Invalid node label: {node_label}")

        if not node_properties:
            node_properties = dict()

        n = Node(node_label, id=node_name, **node_properties)
        n.__primarylabel__ = node_label
        n.__primarykey__ = "id"
        try:
            self.graph.merge(n)
        except py2neo.errors.ClientError as e:
            logging.error(str(e))
            return False

        return True

    def add_relation(
        self,
        node_a_name: str,
        node_a_label: str,
        node_b_name: str,
        node_b_label: str,
        relation_label: str,
        relation_properties: Dict[str, Any],
    ) -> bool:
        """
        Adds a relation with specified parameters to the graph database.

        @param node_a_name: First (source) node for relation
        @type node_a_name: str
        @param node_a_label: Label of first (source) node, must be defined in defined_relation_labels
        @type node_a_label: str
        @param node_b_name: Second (target) node for relation
        @type node_b_name: str
        @param node_b_label: Label of first (source) node, must be defined in defined_relation_labels
        @type node_b_label: str
        @param relation_label: Label to use for this node, must be defined in defined_relation_labels
        @type relation_label: str
        @param relation_properties: Any other metadata to store with this relation
        @type relation_properties: dict
        @return: True if addition was successful, false otherwise.
        @rtype: bool
        @raise: ValueError: if node or relation labels are not a predefined type in defined_node/relation_labels
        """

        if node_a_label not in defined_node_labels:
            raise ValueError(f"Invalid node A label: {node_a_label}")

        if node_b_label not in defined_node_labels:
            raise ValueError(f"Invalid node B label: {node_a_label}")

        if relation_label not in defined_relation_labels:
            raise ValueError(f"Invalid relation label: {relation_label}")

        if not relation_properties:
            relation_properties = dict()

        n = NodeMatcher(self.graph)
        node_a = n.match(node_a_label, id=node_a_name).first()
        node_b = n.match(node_b_label, id=node_b_name).first()

        if node_a and node_b:
            r = Relationship(node_a, relation_label, node_b, **relation_properties)
            try:
                self.graph.merge(r, label=relation_label)
            except py2neo.errors.ClientError as e:
                logging.error(str(e))
                return False

            return True
        else:
            raise ValueError(
                f"Couldn't find {node_a_name} ({node_a}) "
                f"or {node_b_name} ({node_b})"
            )
