import os

from py2neo import Graph, Node, NodeMatcher, Relationship, RelationshipMatcher
from urllib.parse import quote_plus


def dict_to_cypher_string(input_dict):
    return "{" + ",".join({f'{k}: "{v}"`' for k, v in input_dict.items()}) + "}"


class AicaNeo4j:
    def __init__(self, host=None, user=None, password=None, port=7687):
        host = host if host else quote_plus(str(os.getenv("NEO4J_SERVER")))
        port = port if port else quote_plus(str(os.getenv("NEO4J_SERVER_PORT")))
        user = user if user else quote_plus(str(os.getenv("NEO4J_USER")))
        password = password if password else quote_plus(str(os.getenv("NEO4J_PASS")))
        uri = f"bolt://{host}:{port}"
        self.graph = Graph(uri, auth=(user, password))

    def add_node(self, node_name, node_label, node_properties):
        n = NodeMatcher(self.graph)
        node = n.match(node_label, id=node_name).first()
        if node:
            node.update(**node_properties)
            self.graph.push(node)
        else:
            a = Node(node_label, id=node_name, **node_properties)
            self.graph.create(a)

    def add_relation(
        self, relation_label, node_a_name, node_b_name, relation_properties
    ):
        n = NodeMatcher(self.graph)
        node_a = n.match(node_a_name.split("--")[0], id=node_a_name).first()
        node_b = n.match(node_b_name.split("--")[0], id=node_b_name).first()

        r = RelationshipMatcher(self.graph)
        rel = r.match((node_a, node_b), r_type=relation_label).first()
        if rel:
            rel.update(**relation_properties)
            self.graph.push(rel)
        else:
            r = Relationship(node_a, relation_label, node_b, **relation_properties)
            self.graph.create(r)
