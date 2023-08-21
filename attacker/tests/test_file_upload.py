import os
import requests as r
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


class TestFileUpload(unittest.TestCase):
    def test_file_upload_bypass(self):
        with open("/root/tests/data/notmalware", "rb") as infile:
            res = r.post(
                f"{juice_url}/file-upload",
                files={"files": infile},
            )
        self.assertEqual(res.status_code, 204)
