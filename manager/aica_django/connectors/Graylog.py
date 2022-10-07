import backoff
import os
import logging
import requests

from requests.auth import HTTPBasicAuth

headers = {"Accept": "application/json", "X-Requested-By": __name__}


# Django starts up faster than Graylog, and given the emu/virt distinction,
# a hard Docker dependency wouldn't make sense, so just retry if it fails.
@backoff.on_exception(
    backoff.expo, (requests.exceptions.Timeout, requests.exceptions.ConnectionError)
)
def make_request(url, method, siem_user, siem_password, params=None):
    siem_auth = HTTPBasicAuth(siem_user, siem_password)

    if method.lower() == "get":
        method_func = requests.get
    elif method.lower() == "post":
        method_func = requests.post
    else:
        raise ValueError("Invalid method")
    r = method_func(url, headers=headers, auth=siem_auth, params=params)

    # Print out the error message before throwing an HTTPError
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logging.error(r.text)
        raise e

    return r.json()


class Graylog:
    def __init__(self, label):
        # Get API Token with username/password
        # Should create a non-admin user for this later...
        siem_host = os.getenv("GRAYLOG_HOST")
        siem_user = os.getenv("GRAYLOG_QUERY_USER")
        siem_password = os.getenv("GRAYLOG_QUERY_PASSWORD")

        # Get Admin UUID
        user_url = f"{siem_host}/api/users/{siem_user}"
        user_res = make_request(user_url, "get", siem_user, siem_password)
        user_id = user_res["id"]

        # Get Token
        token_url = f"{siem_host}/api/users/{user_id}/tokens/aica_{label}"
        params = {"pretty": True}
        token_res = make_request(token_url, "post", siem_user, siem_password, params)
        logging.info("Got token for Graylog API")

        self.query_token = token_res["token"]
        self.query_url = f"{siem_host}/api/search/universal/absolute"

    def query(self, query_params):
        response = requests.get(
            self.query_url,
            headers=headers,
            auth=(self.query_token, "token"),
            params=query_params,
        )

        return response
