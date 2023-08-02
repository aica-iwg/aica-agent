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

# https://pwning.owasp-juice.shop/appendix/solutions.html#perform-a-dom-xss-attack
def test_dom_xss():
    res = r.get(f"{config.JUICE_URL}")

def test_reflected_xss():
    pass