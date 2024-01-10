"""
This module contains any code necessary to interact with Neo4j's graph database.

Classes:
    AicaNeo4j: The object to instantiate to create a persistent interface with Neo4j
"""

import os
import py2neo.errors  # type: ignore

from celery.utils.log import get_task_logger
from py2neo import Graph, Node, Relationship
from urllib.parse import quote_plus
from typing import Any, Dict, List, Union

logger = get_task_logger(__name__)


class AicaNeo4j:
    """
    The object to instantiate to create a persistent interface to Neo4j
    """

    def __init__(
        self, host: str = "", port: int = 0, user: str = "", password: str = ""
    ) -> None:
        """
        Initialize a new AiceNeo4j object.

        @param host: The Neo4j host, read from environment variable N4J_SERVER if not provided
        @type host: str
        @param user: The Neo4j user, read from environment variable N4J_USER if not provided
        @type user: str
        @param password: The Neo4j user password, read from environment variable N4J_PASS if not provided
        @type password: str
        @param port: The Neo4j server port, read from environment variable N4J_PORT or defaults to 7687
        @type port: int
        """

        host = host if host != "" else quote_plus(str(os.getenv("N4J_HOST")))
        port = port if port >= 0 else int(quote_plus(str(os.getenv("N4J_PORT"))))
        user = user if user != "" else quote_plus(str(os.getenv("N4J_USER")))
        password = (
            password if password != "" else quote_plus(str(os.getenv("N4J_PASSWORD")))
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

        unique_id = f"""CREATE CONSTRAINT unique_id IF NOT EXISTS
                        FOR (n)
                        REQUIRE n.id IS UNIQUE"""
        tx.run(unique_id)

        unique_note = f"""CREATE CONSTRAINT unique_abstract_note IF NOT EXISTS
                        FOR (n:note)
                        REQUIRE n.abstract IS UNIQUE"""
        tx.run(unique_note)

        unique_ipv4 = f"""CREATE CONSTRAINT unique_addr_ipv4 IF NOT EXISTS
                        FOR (n:`ipv4-addr`)
                        REQUIRE n.value IS UNIQUE"""
        tx.run(unique_ipv4)

        unique_ipv6 = f"""CREATE CONSTRAINT unique_addr_ipv6 IF NOT EXISTS
                        FOR (n:`ipv6-addr`)
                        REQUIRE n.value IS UNIQUE"""
        tx.run(unique_ipv6)

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

        if not node_properties:
            node_properties = dict()

        n = Node(node_label, id=node_name, **node_properties)
        n.__primarylabel__ = node_label
        n.__primarykey__ = "id"

        if (
            "identifier" not in node_properties.keys()
            and "id" in node_properties.keys()
        ):
            node_properties["identifier"] = node_properties["id"]

        try:
            if node_label.lower() == "note":
                # We use notes as global information references, based on unique abstract values,
                # so they need special handling
                if len(list(node_properties.keys())) > 0:
                    create_property_list = ", ".join(
                        [
                            f"n.{x} = '{node_properties[x]}'"
                            for x in node_properties.keys()
                        ]
                    )
                    create_property_list = f"ON CREATE SET {create_property_list}"
                else:
                    create_property_list = ""

                if "object_refs" in node_properties.keys():
                    match_property_list = f"ON MATCH SET n.object_refs = n.object_refs + {node_properties['object_refs']}"
                else:
                    match_property_list = ""
                query = f"""MERGE (n:note {{abstract: '{node_properties['abstract']}'}})
                            {create_property_list}
                            {match_property_list}
                            RETURN n"""
                self.graph.run(query)
            else:
                self.graph.merge(n)
        except py2neo.errors.ClientError as e:
            logger.error(str(e))
            return False

        return True

    def add_relation(
        self,
        node_a_id: str,
        node_b_id: str,
        relation_label: str,
        relation_properties: Union[None, Dict[str, Any]] = None,
    ) -> bool:
        """
        Adds a relation with specified parameters to the graph database.

        @param node_a_id: First (source) node for relation
        @type node_a_id: str
        @param node_b_id: Second (target) node for relation
        @type node_b_id: str
        @param relation_label: Label to use for this node
        @type relation_label: str
        @param relation_properties: Any other metadata to store with this relation
        @type relation_properties: dict
        @return: True if addition was successful, false otherwise.
        @rtype: bool
        """

        if not relation_properties:
            relation_properties = dict()

        node_a = self.graph.nodes.match(identifier=node_a_id).first()
        node_b = self.graph.nodes.match(identifier=node_b_id).first()

        if not (node_a and node_b):
            raise ValueError(
                f"Unable to find both ends of relationship: {node_a_id} ({node_a}), {node_b_id} ({node_b})"
            )

        r = Relationship(node_a, relation_label, node_b, **relation_properties)
        try:
            self.graph.merge(r, label=relation_label)
        except py2neo.errors.ClientError as e:
            logger.error(str(e))
            return False

        return True

    def get_node_ids_by_label(self, label: str) -> List[Node]:
        """
        Get all nodes from graph with a given label.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        query = f"MATCH (n:{label}) RETURN n"
        results = {result["n"]["identifier"] for result in list(self.graph.run(query))}

        return results

    def get_relation_ids_by_label(self, label: str) -> List[Node]:
        """
        Get all relations from graph with a given label.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        query = f"MATCH ()-[r:{label}]-() RETURN r"
        results = {result["n"]["identifier"] for result in list(self.graph.run(query))}

        return results

    def get_attack_pattern_ids_by_name(self, name: str) -> List[Node]:
        """
        Get all relations from graph with a given label.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        query = f"MATCH (n:AttackPattern WHERE n.name = '{name}') RETURN n"
        results = {result["n"]["identifier"] for result in list(self.graph.run(query))}

        return results

    def get_indicator_ids_by_name(self, name: str) -> List[Node]:
        """
        Get all relations from graph with a given label.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        query = f"MATCH (n:Indicator WHERE n.name = '{name}') RETURN n"
        results = {result["n"]["identifier"] for result in list(self.graph.run(query))}

        return results

    def get_note_ids_by_abstract(self, abstract: str) -> List[Node]:
        """
        Get all port notes from graph with a given port/proto.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        query = f"MATCH (n:note WHERE n.abstract = '{abstract}') RETURN n"
        results = {result["n"]["identifier"] for result in list(self.graph.run(query))}

        return results

    def get_port_note_ids_by_abstract(self, port: int, proto: str) -> List[Node]:
        """
        Get all port notes from graph with a given port/proto.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        return self.get_note_ids_by_abstract(f"{port}/{proto}")

    def get_ipv4_ids_by_addr(self, addr: str) -> List[Node]:
        query = f"MATCH (n:`ipv4-addr` WHERE n.value = '{addr}') RETURN n"
        query_results = list(self.graph.run(query))
        if query_results:
            return {result["n"]["identifier"] for result in query_results}
        else:
            return []

    def get_ipv6_ids_by_addr(self, addr: str) -> List[Node]:
        query = f"MATCH (n:`ipv6-addr` WHERE n.value = '{addr}') RETURN n"
        query_results = list(self.graph.run(query))
        if query_results:
            return {result["n"]["identifier"] for result in query_results}
        else:
            return []
