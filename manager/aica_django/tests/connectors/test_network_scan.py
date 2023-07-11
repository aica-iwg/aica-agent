from django.test import TestCase

from aica_django.connectors.NetworkScan import network_scan
from aica_django.connectors.GraphDatabase import AicaNeo4j


class TestNetworkScan(TestCase):
    def setUp(self):
        self.graph = AicaNeo4j()

    def test_network_scan(self):
        host_list_before = self.graph.get_nodes_by_label("Host")
        results = network_scan("target")
        host_list = self.graph.get_nodes_by_label("Host")

        self.assertNotEqual(host_list_before, host_list)
        self.assertEqual(list(results)[0], host_list[0]["n"]["id"])

    # def test_periodic_network_scan(self):
    #     self.fail()
