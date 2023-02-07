import re
import socket

from django.test import TestCase

from aica_django.connectors.ssh import send_ssh_command, redirect_to_honeypot_iptables


class TestSsh(TestCase):
    def test010_send_ssh_command(self):
        retval, stdout, stderr = send_ssh_command("target", "whoami")

        self.assertEqual(retval, 0)
        self.assertEqual(stdout, "root\n")
        self.assertEqual(stderr, "")

        retval, stdout, stderr = send_ssh_command("target", "fakecommand")
        self.assertEqual(retval, 127)
        self.assertNotEqual(stderr, "")

        self.assertRaises(socket.gaierror, send_ssh_command, "fakehost", "fakecommand")

    def test020_redirect_to_honeypot_iptables(self):
        retval, _, _ = send_ssh_command("target", "ipset flush honeypot")
        self.assertEqual(retval, 0)

        retval, stdout, stderr = send_ssh_command(
            "target", "ipset list honeypot | grep -A10 '^Members:'"
        )
        self.assertEqual(retval, 0)
        self.assertEqual(stdout, "Members:\n")
        self.assertEqual(stderr, "")

        redirect_to_honeypot_iptables("1.2.3.4", "target")
        retval, stdout, stderr = send_ssh_command(
            "target", "ipset list honeypot | grep -A10 '^Members:'"
        )
        self.assertEqual(retval, 0)
        self.assertRegex(stdout, r"1\.2\.3\.4 timeout 2[89]\d")
        self.assertEqual(stderr, "")

        redirect_to_honeypot_iptables("1.2.3.5", "target", 1230)
        retval, stdout, stderr = send_ssh_command(
            "target", "ipset list honeypot | grep -A10 '^Members:'"
        )
        self.assertEqual(retval, 0)
        self.assertRegex(stdout, r"1\.2\.3\.5 timeout 12[12]\d")
        self.assertEqual(stderr, "")
