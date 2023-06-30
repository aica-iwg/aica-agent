import os

from celery import current_app
from celery.utils.log import get_task_logger
from django.test import TestCase
from time import sleep

from aica_django.connectors.Antivirus import parse_clamav_alert, poll_clamav_alerts
from aica_django.connectors.GraphDatabase import AicaNeo4j
from aica_django.connectors.SSH import send_ssh_command

logger = get_task_logger(__name__)


class TestAntiVirus(TestCase):
    def setUp(self):
        self.graph = AicaNeo4j()

    def test010_parse_clamav_found_alert(self):
        fake_alert = (
            "943acdb73f35 clamav: Wed Oct 26 07:20:48 2022 -> /root/quarantine/eica.com.txt: "
            "Eicar-Test-Signature(44d88612fea8a8f36de82e1278abb02f:68) FOUND"
        )
        parsed_alert = parse_clamav_alert(fake_alert)
        self.assertEqual(parsed_alert["hostname"], "943acdb73f35")
        self.assertEqual(parsed_alert["date"], "Wed Oct 26 07:20:48 2022")
        self.assertEqual(parsed_alert["path"], "/root/quarantine/eica.com.txt")
        self.assertEqual(parsed_alert["platform"], "Eicar")
        self.assertEqual(parsed_alert["category"], "Test")
        self.assertEqual(parsed_alert["name"], "Signature")
        self.assertEqual(parsed_alert["signature"], "44d88612fea8a8f36de82e1278abb02f")
        self.assertEqual(parsed_alert["revision"], "68")

    def test020_parse_clamav_non_alert(self):
        fake_alert = {
            "message": "943acdb73f35 clamav: Wed Oct 26 07:20:28 2022 -> Limits: PCRERecMatchLimit limit set to 2000.",
            "source_ip": "127.0.0.1",
        }
        try:
            parse_clamav_alert(fake_alert)
            self.fail()
        except ValueError as e:
            if str(e) != "Invalid ClamAV line encountered":
                self.fail()

    def test030_parse_clamav_bad_alert(self):
        fake_alert = "this is not a real alert"
        try:
            parse_clamav_alert(fake_alert)
            self.fail()
        except ValueError as e:
            if str(e) != "Invalid ClamAV line encountered":
                self.fail()

    def test040_poll_clamav_no_alert(self):
        hosts_before = self.graph.get_nodes_by_label("Host").sort(key=hash)
        alerts_before = self.graph.get_nodes_by_label("Alert").sort(key=hash)
        attack_signatures_before = self.graph.get_nodes_by_label(
            "AttackSignature"
        ).sort(key=hash)
        attack_signature_categories_before = self.graph.get_nodes_by_label(
            "AttackSignatureCategory"
        ).sort(key=hash)
        file_paths_before = self.graph.get_nodes_by_label("FilePath").sort(key=hash)
        triggered_relations_before = self.graph.get_relations_by_label(
            "TRIGGERED_BY"
        ).sort(key=hash)
        storage_relations_before = self.graph.get_relations_by_label("STORED_ON").sort(
            key=hash
        )
        type_relations_before = self.graph.get_relations_by_label("IS_TYPE").sort(
            key=hash
        )

        poll_clamav_alerts(single=True)

        hosts_after = self.graph.get_nodes_by_label("Host").sort(key=hash)
        alerts_after = self.graph.get_nodes_by_label("Alert").sort(key=hash)
        attack_signatures_after = self.graph.get_nodes_by_label("AttackSignature").sort(
            key=hash
        )
        attack_signature_categories_after = self.graph.get_nodes_by_label(
            "AttackSignatureCategory"
        ).sort(key=hash)
        file_paths_after = self.graph.get_nodes_by_label("FilePath").sort(key=hash)
        triggered_relations_after = self.graph.get_relations_by_label(
            "TRIGGERED_BY"
        ).sort(key=hash)
        storage_relations_after = self.graph.get_relations_by_label("STORED_ON").sort(
            key=hash
        )
        type_relations_after = self.graph.get_relations_by_label("IS_TYPE").sort(
            key=hash
        )

        self.assertEqual(hosts_before, hosts_after)
        self.assertEqual(alerts_before, alerts_after)
        self.assertEqual(attack_signatures_before, attack_signatures_after)
        self.assertEqual(
            attack_signature_categories_before, attack_signature_categories_after
        )
        self.assertEqual(file_paths_before, file_paths_after)
        self.assertEqual(triggered_relations_before, triggered_relations_after)
        self.assertEqual(storage_relations_before, storage_relations_after)
        self.assertEqual(type_relations_before, type_relations_after)

    def test050_poll_clamav_found_alert(self):
        # TODO
        pass
        # hosts_before = self.graph.get_nodes_by_label("Host").sort(key=hash)
        # alerts_before = self.graph.get_nodes_by_label("Alert").sort(key=hash)
        # attack_signatures_before = self.graph.get_nodes_by_label(
        #     "AttackSignature"
        # ).sort(key=hash)
        # attack_signature_categories_before = self.graph.get_nodes_by_label(
        #     "AttackSignatureCategory"
        # ).sort(key=hash)
        # file_paths_before = self.graph.get_nodes_by_label("FilePath").sort(key=hash)
        # triggered_relations_before = self.graph.get_relations_by_label(
        #     "TRIGGERED_BY"
        # ).sort(key=hash)
        # storage_relations_before = self.graph.get_relations_by_label("STORED_ON").sort(
        #     key=hash
        # )
        # type_relations_before = self.graph.get_relations_by_label("IS_TYPE").sort(
        #     key=hash
        # )
        #
        # # Make sure the test virus file is present, and access it to trigger ClamAV
        # retval, stdout, stderr = send_ssh_command("target", "cat /tmp/eicar.com.txt")
        # self.assertEqual(retval, 0)
        # self.assertEqual(
        #     stdout,
        #     "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        # )
        # self.assertEqual(stderr, "")
        # sleep(10)
        #
        # # Make sure ClamAV grabbed the file
        # retval, stdout, stderr = send_ssh_command(
        #     "target", "ls /tmp | grep  eicar.com.txt"
        # )
        # self.assertEqual(retval, 1)
        # self.assertEqual(stdout, "")
        # self.assertEqual(stderr, "")
        # retval, stdout, stderr = send_ssh_command(
        #     "target", "ls /root/quarantine | grep  eicar.com.txt"
        # )
        # self.assertEqual(retval, 0)
        # self.assertRegex(stdout, r"eicar\.com\.txt")
        # self.assertEqual(stderr, "")
        #
        # sleep(30)
        #
        # poll_clamav_alerts(single=True)
        #
        # hosts_after = self.graph.get_nodes_by_label("Host").sort(key=hash)
        # alerts_after = self.graph.get_nodes_by_label("Alert").sort(key=hash)
        # attack_signatures_after = self.graph.get_nodes_by_label("AttackSignature").sort(
        #     key=hash
        # )
        # attack_signature_categories_after = self.graph.get_nodes_by_label(
        #     "AttackSignatureCategory"
        # ).sort(key=hash)
        # file_paths_after = self.graph.get_nodes_by_label("FilePath").sort(key=hash)
        # triggered_relations_after = self.graph.get_relations_by_label(
        #     "TRIGGERED_BY"
        # ).sort(key=hash)
        # storage_relations_after = self.graph.get_relations_by_label("STORED_ON").sort(
        #     key=hash
        # )
        # type_relations_after = self.graph.get_relations_by_label("IS_TYPE").sort(
        #     key=hash
        # )
        #
        # self.fail()
