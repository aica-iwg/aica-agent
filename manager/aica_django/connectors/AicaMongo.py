import os
from typing import Any

from pymongo.mongo_client import MongoClient  # type: ignore
from urllib.parse import quote_plus


class AicaMongo:
    def __init__(self, user=None, password=None, db=None):
        host = quote_plus(str(os.getenv("MONGO_SERVER")))
        port = quote_plus(str(os.getenv("MONGO_SERVER_PORT")))
        db = db if db else quote_plus(str(os.getenv("MONGO_INITDB_DATABASE")))
        user = user if user else quote_plus(str(os.getenv("MONGO_INITDB_USER")))
        password = (
            password if password else quote_plus(str(os.getenv("MONGO_INITDB_PASS")))
        )

        conn = (
            f"mongodb://{user}:{password}@{host}:{port}/"
            f"{db}?retryWrites=true&w=majority"
        )
        self.client = MongoClient(conn)
        self.scan_collection = self.client[os.getenv("MONGO_INITDB_DATABASE")]["scans"]

    def get_client_handle(self):
        return self.client

    def get_db_handle(self, db: str = None):
        db = db if db else str(os.getenv("MONGO_INITDB_DATABASE"))

        return self.client[db]

    def record_scan(self, host_hash: str, timestamp: float) -> Any:
        insert_id = self.scan_collection.insert_one(
            {"host_hash": host_hash, "last_scantime": timestamp}
        )
        return insert_id

    def get_last_scan(self, host_hash: str) -> float:
        result = self.scan_collection.find_one({"host_hash": host_hash})
        if result:
            return result["last_scantime"]
        else:
            return 0
