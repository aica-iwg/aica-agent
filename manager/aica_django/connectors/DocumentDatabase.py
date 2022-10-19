"""
This module contains all code relevant to interacting with MongoDB.

Classes:
    AicaMongo: The object to instantiate to create a persistent interface with MongoGB
"""

import os
from typing import Any

from pymongo.database import Database
from pymongo.mongo_client import MongoClient
from urllib.parse import quote_plus


class AicaMongo:
    """
    The object to instantiate to create a persistent interface to MongoDB
    """

    def __init__(
        self,
        host: str = "",
        port: int = -1,
        user: str = "",
        password: str = "",
        db: str = "",
    ):
        """
        Initialize this AicaMongo object.

        @param host: The MongoDB server to connect to, read from environment variable MONGO_SERVER if not provided
        @type host:
        @param port: The MongoDB server port, read from environment variable MONGO_SERVER_PORT if not provided
        @type port: int
        @param user: The MongoDB server user, read from environment variable MONGO_INITDB_USER if not provided
        @type user:
        @param password: The MongoDB server user password, read from environment variable MONGO_INITDB_PASS
        if not provided
        @type password:
        @param db: The MongoDB database name, read from environment variable MONGO_INITDB_DATABASE if not provided
        @type db:
        """

        host = host if host != "" else quote_plus(str(os.getenv("MONGO_SERVER")))
        port = (
            port if port >= 0 else int(quote_plus(str(os.getenv("MONGO_SERVER_PORT"))))
        )
        db = db if db != "" else quote_plus(str(os.getenv("MONGO_INITDB_DATABASE")))
        user = user if user != "" else quote_plus(str(os.getenv("MONGO_INITDB_USER")))
        password = (
            password
            if password != ""
            else quote_plus(str(os.getenv("MONGO_INITDB_PASS")))
        )

        conn = (
            f"mongodb://{user}:{password}@{host}:{port}/"
            f"{db}?retryWrites=true&w=majority"
        )
        self.client: MongoClient = MongoClient(conn)  # type: ignore
        self.scan_collection = self.client[str(os.getenv("MONGO_INITDB_DATABASE"))][
            "scans"
        ]

    def get_client_handle(self) -> MongoClient:  # type: ignore
        """
        Return a handle to the MongoClient object

        @return: A Handle to the MongoClient for this instantiation
        @rtype: MongoClient
        """

        return self.client

    def get_db_handle(self, db: str = "") -> Database:  # type: ignore
        """
        Return handle to a specific DB in the MongoDB instance.

        @param db: The database handle to retrieve
        @type db: str
        @return: A Handle to the MongoClient DB for this instantiation
        @rtype: Database
        """

        db = db if db != "" else str(os.getenv("MONGO_INITDB_DATABASE"))

        return self.client[db]

    def record_network_scan(self, host_hash: str, timestamp: float) -> Any:
        """
        Record a network scan timestamp for rate limiting.

        @param host_hash: Hash of the nmap target value(s)
        @type host_hash:  str
        @param timestamp: Timestamp of the last run for this host
        @type timestamp: float
        @return: The MongoDB ID of the inserted object
        @rtype: Any
        """

        insert_id = self.scan_collection.insert_one(
            {"host_hash": host_hash, "last_scantime": timestamp}
        )
        return insert_id

    def get_last_network_scan_timestamp(self, host_hash: str) -> float:
        """
        Return the timestamp of the last scan for a network scan target(s)

        @param host_hash: Hash of the nmap target value(s)
        @type host_hash:  str
        @return: Timestamp of the last run for this host
        @rtype: float
        """

        result = self.scan_collection.find_one({"host_hash": host_hash})
        if result:
            return float(result["last_scantime"])
        else:
            return 0
