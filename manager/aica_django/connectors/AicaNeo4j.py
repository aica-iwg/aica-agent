import os

from py2neo import Graph, Node, NodeMatcher, Relationship
from urllib.parse import quote_plus


class AicaNeo4j:
    def __init__(self, host=None, user=None, password=None, port=7687):
        host = host if host else quote_plus(str(os.getenv("NEO4J_SERVER")))
        port = port if port else quote_plus(str(os.getenv("NEO4J_SERVER_PORT")))
        user = user if user else quote_plus(str(os.getenv("NEO4J_USER")))
        password = password if password else quote_plus(str(os.getenv("NEO4J_PASS")))
        uri = f"bolt://{host}:{port}"

        self.graph = Graph(uri, auth=(user, password))
        self.create_constraints()

    def create_constraints(self):
        infra_name = """CREATE CONSTRAINT infra_type_name IF NOT EXISTS
                        FOR (n:infrastructure)
                        REQUIRE n.name IS UNIQUE"""
        self.graph.run(infra_name)

        interface_mac = """CREATE CONSTRAINT macaddr_value IF NOT EXISTS
                            FOR (n:`mac-addr`)
                            REQUIRE n.name IS UNIQUE"""
        self.graph.run(interface_mac)

        interface_ipv4 = """CREATE CONSTRAINT ipv4_value IF NOT EXISTS
                            FOR (n:`ipv4-addr`)
                            REQUIRE n.name IS UNIQUE"""
        self.graph.run(interface_ipv4)

        domain_name = """CREATE CONSTRAINT domainname_value IF NOT EXISTS
                        FOR (n:`domain-name`)
                        REQUIRE n.name IS UNIQUE"""
        self.graph.run(domain_name)

        software_cpe = """CREATE CONSTRAINT software_cpe IF NOT EXISTS
                            FOR (n:software)
                            REQUIRE n.name IS UNIQUE"""
        self.graph.run(software_cpe)

    def add_node(self, node_name, node_label, node_properties):
        if not node_properties:
            node_properties = dict()

        n = Node(node_label, id=node_name, **node_properties)
        n.__primarylabel__ = node_label
        n.__primarykey__ = "id"
        self.graph.merge(n)

    def add_relation(
        self,
        node_a_name,
        node_a_label,
        node_b_name,
        node_b_label,
        relation_label,
        relation_properties,
    ):
        if not relation_properties:
            relation_properties = dict()

        n = NodeMatcher(self.graph)
        node_a = n.match(node_a_label, id=node_a_name).first()
        node_b = n.match(node_b_label, id=node_b_name).first()

        if node_a and node_b:
            r = Relationship(node_a, relation_label, node_b, **relation_properties)
            self.graph.merge(r, label=relation_label)
        else:
            raise ValueError(
                f"Couldn't find {node_a_name} ({node_a}) "
                f"or {node_b_name} ({node_b})"
            )
