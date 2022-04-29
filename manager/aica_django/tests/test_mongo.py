import datetime
import os

from django.test import TestCase
from urllib.parse import quote_plus

from connectors.AicaMongo import AicaMongo


class GenericMongoDbTestCase(TestCase):
    def setUp(self):
        mongo_client = AicaMongo(
            user=quote_plus(str(os.getenv("MONGO_INITDB_ROOT_USER"))),
            password=quote_plus(str(os.getenv("MONGO_INITDB_ROOT_PASS"))),
            db="admin",
        )
        self.client = mongo_client.get_client_handle()
        self.db = mongo_client.get_db_handle(db="test_db")

    def tearDown(self):
        self.client.drop_database("test_db")
        self.client.close()

    def test_create_collection_and_insert(self):
        self.assertIsNotNone(self.db, "database should not be null")
        collection = self.db["test-collection"]
        post = {
            "author": "Mike",
            "text": "My first blog post!",
            "tags": ["mongodb", "python", "pymongo"],
            "date": datetime.datetime.utcnow(),
        }
        post_id = collection.insert_one(post).inserted_id
        self.assertIsNotNone(post_id, "id should not be null")
        post2 = collection.find_one({"author": "Mike"})
        self.assertIsNotNone(post2, "post2 should not be null")
        result = collection.delete_one({"author": "Mike"})
        self.assertEqual(1, result.deleted_count, "should delete only one")
