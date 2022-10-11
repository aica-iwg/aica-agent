import logging
import os
import py2neo.errors  # type: ignore

from py2neo import Graph, Node, NodeMatcher, Relationship  # type: ignore
from urllib.parse import quote_plus

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
    "connected-to",
    "communicates-to",
    "component-of",
    "has-address",
    "has-port",
    "is-type",
    "located-in",
    "manufactures",
    "member-of",
    "resides-in",
    "resolves-to",
    "runs-on",
    "stored-on",
    "triggered-by",
    "used-by",
    "works-in",
]


class AicaNeo4j:
    def __init__(self, host=None, user=None, password=None, port=7687):
        host = host if host else quote_plus(str(os.getenv("NEO4J_SERVER")))
        port = port if port else quote_plus(str(os.getenv("NEO4J_SERVER_PORT")))
        user = user if user else quote_plus(str(os.getenv("NEO4J_USER")))
        password = password if password else quote_plus(str(os.getenv("NEO4J_PASS")))
        uri = f"bolt://{host}:{port}"

        self.graph = Graph(uri, auth=(user, password))

    def create_constraints(self) -> bool:
        tx = self.graph.begin()
        for label in defined_node_labels:
            unique_id = f"""CREATE CONSTRAINT unique_id_{label} IF NOT EXISTS
                            FOR (n:{label})
                            REQUIRE n.id IS UNIQUE"""
            tx.run(unique_id)
        self.graph.commit(tx)

        return True

    def add_node(self, node_name: str, node_label: str, node_properties: dict) -> bool:
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
        relation_properties: dict,
    ) -> bool:
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
