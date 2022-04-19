import os
from neo4j import GraphDatabase
from urllib.parse import quote_plus


class AicaNeo4j:
    def __init__(self, host=None, db=None, user=None, password=None, port=7687):
        host = host if host else quote_plus(str(os.getenv("NEO4J_SERVER")))
        port = port if port else quote_plus(str(os.getenv("NEO4J_SERVER_PORT")))
        user = user if user else quote_plus(str(os.getenv("NEO4J_USER")))
        password = password if password else quote_plus(str(os.getenv("NEO4J_PASS")))
        uri = f"bolt://{user}:{password}@{host}:{port}"
        self.driver = GraphDatabase.driver(uri)
