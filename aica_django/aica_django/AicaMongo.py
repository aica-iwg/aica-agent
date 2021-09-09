import os
from pymongo.mongo_client import MongoClient
from urllib.parse import quote_plus


class AicaMongo:
    def __init__(self, host=None, port=27017, db=None, user=None, password=None):
        host = host if host else quote_plus(str(os.getenv('MONGO_SERVER')))
        db = db if db else quote_plus(str(os.getenv('MONGO_INITDB_DATABASE')))
        user = user if user else quote_plus(str(os.getenv('MONGO_INITDB_USER')))
        password = password if password else quote_plus(str(os.getenv('MONGO_INITDB_PASS')))

        conn = f"mongodb://{user}:{password}@{host}:{port}/{db}?retryWrites=true&w=majority"
        self.client = MongoClient(conn)

    def get_client_handle(self):
        return self.client

    def get_db_handle(self, db=None):
        db = db if db else str(os.getenv('MONGO_INITDB_DATABASE'))

        return self.client[db]
