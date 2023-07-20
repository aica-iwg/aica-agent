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
    'Content-Type': 'application/json',
    'Origin': f'{config.JUICE_URL}/',
    'Connection': 'keep-alive',
    'Referer': f'{config.JUICE_URL}/',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
}

def test_b2b_xxe():
    login = {
        'email': 'admin@juice-sh.op',
        'password': 'admin123'
    }

    res = r.post(f'{config.JUICE_URL}/rest/user/login', headers=headers, json=login)
    token = json.loads(res.text.strip())['authentication']['token']

    admin_headers = headers
    admin_headers['Authorization'] = f'Bearer {token}'
    admin_headers['Cookie'] = f'token={token}'
    time.sleep(random.random() + random.randint(2,4))

    

