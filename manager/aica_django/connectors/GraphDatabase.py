"""
This module contains any code necessary to interact with Neo4j's graph database.

Classes:
    AicaNeo4j: The object to instantiate to create a persistent interface with Neo4j
"""

import inspect
import os
import re2 as re  # type: ignore
import stix2  # type: ignore
import time

from celery import current_app
from celery.utils.log import get_task_logger
from neo4j import GraphDatabase  # type: ignore
from stix2.base import _STIXBase  # type: ignore
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote_plus

logger = get_task_logger(__name__)


def sanitize_cypher(text: str) -> str:
    if not isinstance(text, str):
        raise ValueError(f"text must be a string: {text}")

    return str(re.sub("[-:]", "__", str(text)).replace('"', '\\"'))


def dict_to_cypher(input_dict: dict[str, Any]) -> str:
    # Cypher property values are like dicts, but the keys aren't quoted so we can't use json.dumps
    values = []
    for k, v in input_dict.items():
        if type(v) in [float, int]:
            values.append(f"{k}: {v}")
        else:
            clean_val = re.sub("'", '"', str(v))
            values.append(f"{k}: '{clean_val}'")

    return_string = "{" + ", ".join(values) + "}"

    return return_string


class KnowledgeNode:
    def __init__(
        self,
        id: str,
        labels: list[str] = [],
        props: dict[str, Union[str, int, float, bool]] = {},
    ):
        self.set_id(id)
        self.set_labels(labels)
        self.set_props(props)

    def set_id(self, id: str) -> None:
        self._id = sanitize_cypher(id)

    def set_labels(self, labels: list[str]) -> None:
        self._labels = [sanitize_cypher(x) for x in labels]

    def set_props(self, props: dict[str, Union[str, int, float, bool]]) -> None:
        self._props = {
            sanitize_cypher(x): sanitize_cypher(str(props[x])) for x in props
        }

    def get_create_statement(self, name: str = "n") -> str:
        if len(self._labels) == 0:
            raise ValueError(
                "Cannot generate create statement for node of unknown type"
            )
        labels_string = ":".join(self._labels)

        props_string = ",".join(
            [f'{k}: "{v}"' for k, v in {**self._props, "accolade_id": self._id}.items()]
        )

        return f"({name}:{labels_string} {{{props_string}}})"

    def __str__(self) -> str:
        return self.get_create_statement()

    def __unicode__(self) -> str:
        return self.__str__()

    def __repr__(self) -> str:
        return self.__str__()


class KnowledgeRelation:
    def __init__(
        self,
        rel_type: str,
        props: dict[str, Union[str, int, float, bool]],
        src_node_id: str,
        dst_node_id: str,
    ) -> None:
        self.set_type(rel_type)
        self.set_props(props)
        self.src_node_id = src_node_id
        self.dst_node_id = dst_node_id

    def set_type(self, rel_type: str) -> None:
        self._type = sanitize_cypher(rel_type)

    def set_props(self, props: dict[str, Union[str, int, float, bool]]) -> None:
        self._props = {
            sanitize_cypher(x): sanitize_cypher(str(props[x])) for x in props
        }

    def get_create_statement(self, name: str = "r") -> str:
        return f"{name}:{self._type} {dict_to_cypher(self._props)}"

    def __str__(self) -> str:
        return f"({self.src_node_id}) [{self._type} {dict_to_cypher(self._props)}] ({self.dst_node_id})"

    def __unicode__(self) -> str:
        return self.__str__()

    def __repr__(self) -> str:
        return self.__str__()


class AicaNeo4j:
    """
    The object to instantiate to create a persistent interface to Neo4j
    """

    def __init__(
        self,
        host: str = "",
        port: int = 0,
        user: str = "",
        password: str = "",
        create_constraints: bool = True,
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

        self.graph = GraphDatabase.driver(uri, auth=(user, password))

        if create_constraints:
            with self.graph.session() as session:
                with session.begin_transaction() as tx:

                    for label in list(
                        set(
                            [
                                getattr(stix2.v21.sdo, x)._type
                                for x in dir(stix2.v21.sdo)
                                if inspect.isclass(getattr(stix2.v21.sdo, x))
                                and issubclass(getattr(stix2.v21.sdo, x), _STIXBase)
                                and "_type" in dir(getattr(stix2.v21.sdo, x))
                            ]
                            + [
                                getattr(stix2.v21.observables, x)._type
                                for x in dir(stix2.v21.observables)
                                if inspect.isclass(getattr(stix2.v21.observables, x))
                                and issubclass(
                                    getattr(stix2.v21.observables, x), _STIXBase
                                )
                                and "_type" in dir(getattr(stix2.v21.observables, x))
                            ]
                        )
                    ):
                        label_safe = re.sub("[^A-Za-z0-9_]", "_", label)
                        unique_id = (
                            f"CREATE CONSTRAINT {label_safe}_identifier IF NOT EXISTS "
                            + f"FOR (n:`{label}`) REQUIRE n.identifier IS UNIQUE"
                        )
                        tx.run(unique_id)

                    unique_note = (
                        "CREATE CONSTRAINT note_abstract IF NOT EXISTS "
                        + "FOR (n:note) REQUIRE n.abstract IS UNIQUE"
                    )
                    tx.run(unique_note)

                    unique_ap = (
                        "CREATE CONSTRAINT attack_pattern_description IF NOT EXISTS "
                        + "FOR (n:`attack-pattern`) REQUIRE n.description IS UNIQUE"
                    )
                    tx.run(unique_ap)

                    unique_value_labels = [
                        "mac-addr",
                        "ipv4-addr",
                        "ipv6-addr",
                        "domain-name",
                    ]
                    for label in unique_value_labels:
                        label_safe = re.sub("[^A-Za-z0-9_]", "_", label)
                        unique_constraint = (
                            f"CREATE CONSTRAINT {label_safe}_value IF NOT EXISTS "
                            + f"FOR (n:`{label}`) REQUIRE n.value IS UNIQUE"
                        )
                        tx.run(unique_constraint)

                    tx.commit()

    def add_node(
        self, node_id: str, node_label: str, node_properties: Optional[Dict[str, Any]]
    ) -> None:
        if not node_properties:
            node_properties = dict()

        self.add_nodes([node_id], [node_label], [node_properties])

    def add_nodes(
        self,
        node_ids: List[str],
        node_labels: List[str],
        node_properties: List[Dict[str, Any]],
    ) -> None:
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

        queries = []

        for node_id, node_label, node_property in zip(
            node_ids, node_labels, node_properties
        ):
            if not node_property:
                node_property = dict()

            if node_label.lower() == "note":
                # We use notes as global information references, based on unique abstract values,
                # so they need special handling
                if len(list(node_property.keys())) > 0:
                    node_property["identifier"] = node_id
                    create_property_list = ", ".join(
                        [f"n.{x} = '{node_property[x]}'" for x in node_property.keys()]
                    )
                    create_property_list = f"ON CREATE SET {create_property_list}"
                else:
                    create_property_list = ""

                if "object_refs" in node_property.keys():
                    match_property_list = f"ON MATCH SET n.object_refs = n.object_refs + {node_property['object_refs']}"
                else:
                    match_property_list = ""
                queries.append(
                    f"""MERGE (n:note {{abstract: '{node_property['abstract']}'}})
                            {create_property_list}
                            {match_property_list}
                            RETURN n"""
                )
            else:
                queries.append(
                    f"MERGE (n:`{node_label}` {dict_to_cypher(node_property)}) "
                    + f"ON CREATE SET n.identifier = '{node_id}', n.created = timestamp() "
                    + "RETURN n.identifier, n.created"
                )

        with self.graph.session() as session:
            with session.begin_transaction() as tx:
                for query in queries:
                    tx.run(query)

                tx.commit()

    def add_relation(
        self,
        node_a_id: str,
        node_b_id: str,
        relation_label: str,
        relation_properties: Optional[dict[str, Any]] = None,
        directed_tag: bool = True,
    ) -> None:
        if not relation_properties:
            relation_properties = dict()

        self.add_relations(
            [node_a_id],
            [node_b_id],
            [relation_label],
            [relation_properties],
            [directed_tag],
        )

    def add_relations(
        self,
        node_a_ids: List[str],
        node_b_ids: List[str],
        relation_labels: List[str],
        relation_properties: List[dict[str, Any]],
        directed_tags: List[bool],
    ) -> None:
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

        queries = []

        for (
            node_a_id,
            node_b_id,
            relation_label,
            relation_property,
            directed_tag,
        ) in zip(
            node_a_ids, node_b_ids, relation_labels, relation_properties, directed_tags
        ):
            if not relation_property:
                relation_property = dict()

            relation = KnowledgeRelation(
                relation_label, relation_property, node_a_id, node_b_id
            )

            query = f"""MATCH
                            (n1), (n2)
                        WHERE
                            n1.identifier = '{node_a_id}' AND
                            n2.identifier = '{node_b_id}' 
                        MERGE 
                            (n1)-[{relation.get_create_statement()}]-{'>' if directed_tag else ''}(n2)
                        RETURN type(r)"""

            queries.append(query)

        with self.graph.session() as session:
            with session.begin_transaction() as tx:
                for query in queries:
                    tx.run(query)

                tx.commit()

    def get_node_ids_by_label(self, label: str) -> List[str]:
        """
        Get all nodes from graph with a given label.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        query = f"MATCH (n:{label}) RETURN n.identifier as identifier"
        query_results, _, _ = self.graph.execute_query(query)

        try:
            return [result.data()["identifier"] for result in query_results]
        except:
            raise ValueError("Identifier field missing for at least one result")

    def get_relation_ids_by_label(self, label: str) -> List[str]:
        """
        Get all relations from graph with a given label.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        query = f"MATCH ()-[r:{label}]-() RETURN r.identifier as identifier"
        query_results, _, _ = self.graph.execute_query(query)

        try:
            return [result.data()["identifier"] for result in query_results]
        except:
            raise ValueError("Identifier field missing for at least one result")

    def get_attack_pattern_ids_by_name(self, name: str) -> List[str]:
        """
        Get all relations from graph with a given label.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        query = f"MATCH (n:AttackPattern WHERE n.name = '{name}') RETURN n.identifier as identifier"
        query_results, _, _ = self.graph.execute_query(query)

        try:
            return [result.data()["identifier"] for result in query_results]
        except:
            raise ValueError("Identifier field missing for at least one result")

    def get_indicator_ids_by_name(self, name: str) -> List[str]:
        """
        Get all relations from graph with a given label.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        query = f"MATCH (n:Indicator WHERE n.name = '{name}') RETURN n.identifier as identifier"
        query_results, _, _ = self.graph.execute_query(query)

        try:
            return [result.data()["identifier"] for result in query_results]
        except:
            raise ValueError("Identifier field missing for at least one result")

    def get_attack_pattern_ids_by_category(self, category: str) -> List[str]:
        """
        Get all relations from graph with a given label.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        query = f"MATCH (n:`attack-pattern`) WHERE (n.description = '{category}') RETURN n.identifier as identifier"
        query_results, _, _ = self.graph.execute_query(query)

        try:
            return [result.data()["identifier"] for result in query_results]
        except:
            raise ValueError("Identifier field missing for at least one result")

    def get_note_ids_by_abstract(self, abstract: str) -> List[str]:
        """
        Get all port notes from graph with a given port/proto.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        query = f"MATCH (n:note WHERE n.abstract = '{abstract}') RETURN n.identifier as identifier"
        query_results, _, _ = self.graph.execute_query(query)

        try:
            return [result.data()["identifier"] for result in query_results]
        except:
            raise ValueError("Identifier field missing for at least one result")

    def get_port_note_ids_by_abstract(self, port: int, proto: str) -> List[str]:
        """
        Get all port notes from graph with a given port/proto.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return:
        @rtype:
        """
        return self.get_note_ids_by_abstract(f"{port}/{proto}")

    def get_ipv4_ids_by_addr(self, addr: str) -> List[str]:
        query = f"MATCH (n:`ipv4-addr` WHERE n.value = '{addr}') RETURN n.identifier as identifier"
        query_results, _, _ = self.graph.execute_query(query)

        try:
            return [result.data()["identifier"] for result in query_results]
        except:
            raise ValueError("Identifier field missing for at least one result")

    def get_ipv6_ids_by_addr(self, addr: str) -> List[str]:
        query = f"MATCH (n:`ipv6-addr` WHERE n.value = '{addr}') RETURN n.identifier as identifier"
        query_results, _, _ = self.graph.execute_query(query)

        try:
            return [result.data()["identifier"] for result in query_results]
        except:
            raise ValueError("Identifier field missing for at least one result")


@current_app.task(name="prune-netflow-data")
def prune_netflow_data(
    seconds: int = 600, pre_sleep: bool = True, post_sleep: bool = False
) -> None:
    # This function removes all network traffic items that were created at least
    # _minutes_ ago and are not connected to any observations

    graph = AicaNeo4j(create_constraints=False)

    # Not using f-string here since it gets messy with braces in the query.
    # This might get better with Python 3.12+.
    query = (
        "WITH datetime() - duration({seconds:"
        + str(seconds)
        + "}) AS cutoff "
        + "CALL {MATCH (n:`network-traffic`) OPTIONAL MATCH (n)<-[r]-(o:`observed-data`) RETURN n,r,o} "
        + "WITH *, datetime(replace(n.end, ' ', 'T')) AS end "
        + "WHERE o IS NULL AND end < cutoff "
        + "DETACH DELETE n"
    )
    while True:
        if pre_sleep:
            time.sleep(seconds)
        graph.graph.execute_query(query)
        if post_sleep:
            time.sleep(seconds)
