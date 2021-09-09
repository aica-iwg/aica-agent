import datetime
import collections
import os

from bson.objectid import ObjectId
from django.test import TestCase
from stix2 import Indicator
from urllib.parse import quote_plus

from aica_django.AicaMongo import AicaMongo


class GenericMongoDbTestCase(TestCase):

    def setUp(self):
        mongo_client = AicaMongo(user=quote_plus(str(os.getenv('MONGO_INITDB_ROOT_USER'))),
                                 password=quote_plus(str(os.getenv('MONGO_INITDB_ROOT_PASS'))),
                                 db="admin")
        self.client = mongo_client.get_client_handle()
        self.db = mongo_client.get_db_handle(db="test_db")

    def tearDown(self):
        self.client.drop_database("test_db")
        self.client.close()

    def test_create_collection_and_insert(self):
        self.assertIsNotNone(self.db, 'database should not be null')
        collection = self.db['test-collection']
        post = {"author": "Mike",
                "text": "My first blog post!",
                "tags": ["mongodb", "python", "pymongo"],
                "date": datetime.datetime.utcnow()}
        post_id = collection.insert_one(post).inserted_id
        self.assertIsNotNone(post_id, 'id should not be null')
        post2 = collection.find_one({"author": "Mike"})
        self.assertIsNotNone(post2, 'post2 should not be null')
        result = collection.delete_one({"author": "Mike"})
        self.assertEqual(1, result.deleted_count, 'should delete only one')

    def test_storing_and_using_stix_objects(self):
        indicator2 = Indicator(type='indicator',
                               pattern_type="stix",
                               pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']")

        doc = collections.OrderedDict()
        doc['id'] = indicator2.id
        doc['type'] = indicator2.type
        doc['spec_version'] = indicator2.spec_version
        doc['pattern_type'] = indicator2.pattern_type
        doc['pattern'] = indicator2.pattern
        doc['pattern_version'] = indicator2.pattern_version
        doc['created'] = indicator2.created
        doc['modified'] = indicator2.modified
        doc['valid_from'] = indicator2.valid_from

        self.assertIsNotNone(self.db, 'database should not be null')
        collection = self.db['test-indicators']
        indicator2_id = collection.insert_one(doc).inserted_id
        self.assertIsNotNone(indicator2_id, 'id should not be null')
        post2 = collection.find_one({"pattern": "[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']"})
        self.assertIsNotNone(post2, 'post2 should not be null')
        result = collection.delete_one({"_id": ObjectId(indicator2_id)})
        self.assertEqual(1, result.deleted_count, 'should delete only one')
