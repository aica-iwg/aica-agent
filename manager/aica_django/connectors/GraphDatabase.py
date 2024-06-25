"""
This module contains any code necessary to interact with Neo4j's graph database.

Classes:
    AicaNeo4j: The object to instantiate to create a persistent interface with Neo4j
"""

import datetime
import inspect
import networkx as nx
import os
import random
import hashlib
import re2 as re  # type: ignore
import stix2  # type: ignore
import time
import numpy as np

from celery import current_app
from celery.app import shared_task
from celery.utils.log import get_task_logger
from io import BytesIO, StringIO
from neo4j import GraphDatabase  # type: ignore
from networkx.readwrite import read_graphml
from scipy.io import mmread, mmwrite  # type: ignore
from sklearn.feature_extraction.text import HashingVectorizer  # type: ignore
from stix2.base import _STIXBase  # type: ignore
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote_plus
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent  # type: ignore
from watchdog.observers import Observer  # type: ignore
import torch
from torch_geometric.data import Data
from torch_geometric import EdgeIndex
import torch_geometric.utils
from torch_geometric.nn import CuGraphSAGEConv
import torch.nn.functional as F
from torch_sparse import SparseTensor
from torch_geometric.profile import count_parameters



logger = get_task_logger(__name__)

graphml_path = "/graph_data/aica.graphml"

# 2^22 is somewhat arbitrary, but is ~4M and intended to balance accuracy with performance
vectorizer = HashingVectorizer(n_features=2**22)


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

def shvvl(tag: str, bpf: int) -> bytes:
    '''
    This is SHVVL. The only important thing is that the "type" of node is the first string in the tag
    '''
    sectors = tag.split("\0")
    typehash = hashlib.md5(bytes(sectors[0], "UTF8"), usedforsecurity=False).digest()

    out = bytearray()
    hashfunc = hashlib.new('shake_256', usedforsecurity=False)
    for sector in sectors:
        hashfunc = hashlib.new('shake_256', usedforsecurity=False)
        
        blockInput = bytearray(sector, "UTF8")
        blockInput = blockInput + typehash
        hashfunc.update(blockInput)
        out += hashfunc.digest(bpf)

    return out

def shvvl_float(tag: str, bpf: int) -> list[float]:
    out = list()
    for bite in shvvl(tag, bpf):
        for l in range(8):
            out.append(1.0 if (bite&(1<<l)) != 0 else 0.0)
        
    return out


class AICASage(torch.nn.Module):
    def __init__(self, in_dim, hidden_dim, out_dim, aggr='mean', dropout=0.2):
        super().__init__()
        self.dropout = dropout
        self.conv1 = CuGraphSAGEConv(in_dim, hidden_dim, aggr=aggr)
        self.conv2 = CuGraphSAGEConv(hidden_dim, hidden_dim, aggr=aggr)
        self.conv3 = CuGraphSAGEConv(hidden_dim, out_dim, aggr=aggr)
          
    def forward(self, data: Data):

        edge_idx = EdgeIndex(data.edge_index) 

        x = self.conv1(data.x, edge_idx)
        x = F.tanh(x)
        x = F.dropout(x, p=self.dropout)
        
        x = self.conv2(x, edge_idx)
        x = F.tanh(x)
        x = F.dropout(x, p=self.dropout)
        
        x = self.conv3(x, edge_idx)
        x = F.tanh(x)
    
        return x

def load_graphml_data(BASEFILE, SHVVL_MAX_FEATURE_LEN=12, SHVVL_BANDWIDTH=20):

    aica_graph = nx.DiGraph = nx.read_graphml(BASEFILE)
    a = 0
    for n in aica_graph.nodes(data=True):
        typedata = n[1]["TYPE"]
        del n[1]["identifier_vec"]

    z = str(typedata) + "\0"
    keys = sorted(n[1].keys())
    for k in range(SHVVL_MAX_FEATURE_LEN):
        z += str(n[1][keys[k]]) + "\0" if k < len(keys) else "\0"
        
    z = z[:-1]


    shoveled_data = shvvl_float(z, SHVVL_BANDWIDTH)
    shvvlsize = len(shoveled_data)
    s : dict = {}

    n[1].clear()
    for x in range(shvvlsize):
        pass
        n[1]["SHVVL_ID" + str(x)] = shoveled_data[x]
        
    a = max(a, len(n[1]))

    n[1]["TYPE"]=typedata
    print(f"SHVVL Feature count: {a}")
    for x in aica_graph.edges(data=True):
        x[2].clear()
        x[2]["dummy"]=0

    data_tensor : Data = torch_geometric.utils.convert.from_networkx(aica_graph, ['SHVVL_ID' + str(x) for x in range(a)])
    print("Checking ordering...")
    z = 0
    for original_node in aica_graph.nodes(data=True):
        if original_node[1]["SHVVL_ID0"] != data_tensor.x[z][0]:
            raise BaseException("ERROR: Ordering not lined up")
            z = -1
            break
        z += 1
    if z != -1:
        print("Likely ordered")

    return data_tensor
    

def run_graphsage(data_tensor, hidden_dim=128, in_dim=-1, out_dim=128): 
    # make hidden_dim size be num_node_types*hidden_dim
    model = AICASage(in_dim=in_dim, 
                    hidden_dim=hidden_dim, 
                    out_dim=out_dim)
    
    if torch.cuda.is_available():
        print("Starting in GPU mode...")
        deviceType =  f'cuda' 
    else:
        print("WARNING: NO VALID CUDA DEVICE FOUND! Defaulting to CPU...")
        deviceType = 'cpu'

    device = torch.device(deviceType)

    model.to(device)
    data_tensor.to(device)
    emb = model(data_tensor) 
    emb = emb.cpu().detach().numpy()

    return emb


class GraphMLHandler(FileSystemEventHandler):  # type: ignore
    def __init__(self, quiesce_period: int = 60) -> None:
        self.quiesce_period = quiesce_period
        self.last_change = 0.0

    def on_created(self, event: FileCreatedEvent) -> None:
        self.on_modified(event)

    def on_modified(self, event: FileModifiedEvent) -> None:
        current_time = time.time()

        # If the file has been modified recently, ignore the event
        if current_time - self.last_change < self.quiesce_period:
            logger.debug(
                f"Not processing GraphML file, last time: {self.last_change}, current time: {current_time}"
            )
        else:
            logger.debug(
                f"Processing changed GraphML file, last time: {self.last_change}, current time: {current_time}"
            )
            process_graphml(graphml_path)

        if current_time > self.last_change:
            self.last_change = current_time


@shared_task(name="poll-graphml")
def poll_graphml() -> None:
    logger.info(f"Running {__name__}: poll_graphml")

    if os.path.isfile(graphml_path):
        process_graphml(graphml_path)

    observer = Observer()
    observer.schedule(GraphMLHandler(), graphml_path)
    observer.start()

    # Should never return
    observer.join()


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
            [f'{k}: "{v}"' for k, v in {**self._props, "identifier": self._id}.items()]
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
        initialize_graph: bool = True,
        poll_graph: bool = False,
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

        if initialize_graph:
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
                        and issubclass(getattr(stix2.v21.observables, x), _STIXBase)
                        and "_type" in dir(getattr(stix2.v21.observables, x))
                    ]
                )
            ):
                # Identifier is determined in STIX2 by the "ID Contributing Properties", so if the Identifier is unique, that
                # automatically enforces uniqueness of constituent properties by way of their creation with the STIX2 library
                label_safe = re.sub("[^A-Za-z0-9_]", "_", label)

                id_index = (
                    f"CREATE TEXT INDEX {label_safe}_identifier_index IF NOT EXISTS "
                    + f"FOR (n:`{label}`) on (n.identifier)"
                )
                self.graph.execute_query(id_index)

                id_unique = (
                    f"CREATE CONSTRAINT {label_safe}_identifier_unique IF NOT EXISTS "
                    + f"FOR (n:`{label}`) REQUIRE n.identifier IS UNIQUE"
                )
                self.graph.execute_query(id_unique)

            # Periodic export of graph to graphML for analysis
            export_freq = str(int(os.getenv("AICA_GRAPHML_EXPORT_FREQ", default=900))) #1800 seconds is default
            export_query = 'CALL apoc.export.graphml.all("/graph_data/aica.graphml", {format:"gephi", useTypes:true})'
            schedule_query = f"CALL apoc.periodic.repeat('export-graphml', '{export_query}', {export_freq});"
            self.graph.execute_query(schedule_query)

    def add_node(
        self,
        node_id: str,
        node_label: str,
        node_property_lists: Optional[Dict[str, Any]],
    ) -> None:
        if not node_property_lists:
            node_property_lists = dict()

        self.add_nodes([node_id], [node_label], [node_property_lists])

    def add_nodes(
        self,
        node_ids: List[str],
        node_labels: List[str],
        node_property_lists: List[Dict[str, Any]],
    ) -> None:
        """
        Adds a node with specified parameters to the graph database.

        @param node_id: Unique name to use for this node
        @type node_id: str
        @param node_label: Label to use for this node, must be defined in defined_node_labels
        @type node_label: str
        @param node_properties: Any other metadata to store with this node
        @type node_properties: dict
        """

        # These are STIX properties that we don't need, and will mess up our MERGE statements
        merge_exclude_properties = ["revoked", "spec_version", "created", "modified"]

        queries = []

        node_id_vectors = vectorizer.fit_transform(node_ids)

        for node_id, node_label, node_property_list, node_id_vector in zip(
            node_ids, node_labels, node_property_lists, node_id_vectors
        ):
            now = int(datetime.datetime.now().timestamp())
            mm_array = BytesIO()
            mmwrite(mm_array, node_id_vector)
            node_property_list["identifier_vec"] = mm_array.getvalue().decode("latin1")
            node_property_list["first_merge"] = now
            node_property_list["last_merge"] = now
            node_property_list["merge_count"] = 1
            node_property_list = {
                k: re.sub("'", '"', str(v))
                for k, v in node_property_list.items()
                if k not in merge_exclude_properties
            }
            create_properties = ", ".join(
                f"n.{k}='{v}'" for k, v in node_property_list.items()
            )
            queries.append(
                f'MERGE (n:`{node_label}` {{identifier: "{node_id}"}}) '
                + f"ON CREATE SET {create_properties} "
                + f"ON MATCH SET n.last_merge={now}, n.merge_count=(toInteger(n.merge_count) + 1) "
                + "RETURN n.identifier"
            )

        # We should figure out how to batch this for efficiency - APOC seems to have options
        # but I haven't figured it out yet.
        for query in queries:
            self.graph.execute_query(query)

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
                        ON CREATE SET r.first_merge=timestamp(), r.merge_count=1
                        ON MATCH SET r.last_merge=timestamp(), r.merge_count=(toInteger(r.merge_count) + 1)
                        RETURN type(r)"""

            queries.append(query)

        # We should figure out how to batch this for efficiency - APOC seems to have options
        # but I haven't figured it out yet.
        for query in queries:
            self.graph.execute_query(query)

    def import_graphml_data(self, import_file: str) -> None:
        query = f"CALL apoc.import.graphml('{import_file}', {{}})"
        self.graph.execute_query(query)

    def poll_graphml(self) -> None:
        logger.info(f"Running {__name__}: poll_graphml")
        export_freq = int(os.getenv("AICA_GRAPHML_EXPORT_FREQ", default=300))

        while True:
            # Periodic export of graph to graphML for analysis
            export_query = 'CALL apoc.export.graphml.all("/graph_data/aica.graphml", {format:"gephi", useTypes:true})'
            self.graph.execute_query(export_query)
            time.sleep(5)  # Wait for file to settle (just in case)
            process_graphml(graphml_path)

            time.sleep(export_freq)

    def get_node_ids_by_label(self, label: str) -> List[str]:
        """
        Get all nodes from graph with a given label.

        @param label: Type (label) of nodes to retrieve.
        @type label: str
        @return: List of ids
        @rtype: List[str]
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
        @return: List of ids
        @rtype: List[str]
        """
        query = f"MATCH ()-[r:{label}]-() RETURN r.identifier as identifier"
        query_results, _, _ = self.graph.execute_query(query)

        try:
            return [result.data()["identifier"] for result in query_results]
        except:
            raise ValueError("Identifier field missing for at least one result")

    def get_attack_pattern_ids_by_name(self, name: str) -> List[str]:
        query = f"MATCH (n:AttackPattern WHERE n.name = '{name}') RETURN n.identifier as identifier"
        query_results, _, _ = self.graph.execute_query(query)

        try:
            return [result.data()["identifier"] for result in query_results]
        except:
            raise ValueError("Identifier field missing for at least one result")

    def get_indicator_ids_by_name(self, name: str) -> List[str]:
        query = f"MATCH (n:Indicator WHERE n.name = '{name}') RETURN n.identifier as identifier"
        query_results, _, _ = self.graph.execute_query(query)

        try:
            return [result.data()["identifier"] for result in query_results]
        except:
            raise ValueError("Identifier field missing for at least one result")

    def get_attack_pattern_ids_by_category(self, category: str) -> List[str]:
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
        @return: List of ids
        @rtype: List[str]
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
        @return: List of ids
        @rtype: List[str]
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

    graph = AicaNeo4j(initialize_graph=False)

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
