"""
This module contains all code relevant to interacting with the Graylog SIEM.

Classes:
    Graylog: The object to instantiate to create a persistent interface with Graylog's API

Functions:
    make_request: A rate limited static function to make requests to Graylog's API, with retry logic.
"""

import backoff  # type: ignore
import os
import logging
import requests

from requests.auth import HTTPBasicAuth
from typing import Any, Dict, List, Union

headers = {"Accept": "application/json", "X-Requested-By": __name__}


@backoff.on_exception(
    backoff.expo, (requests.exceptions.Timeout, requests.exceptions.ConnectionError)
)  # type: ignore
def make_graylog_request(
    url: str,
    method: str,
    siem_user: str,
    siem_password: str,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Static function to make rate-limited query to Graylog with retry logic.
    Django starts up faster than Graylog, and given the emu/virt distinction,
    a hard Docker dependency wouldn't make sense, so just retry if it fails.

    @param url: Graylog API url
    @type url: str
    @param method: HTTP Method for request (GET/POST)
    @type method: str
    @param siem_user: User for Graylog API connection
    @type siem_user: str
    @param siem_password: Password for Graylog API connection user
    @type siem_password: str
    @param params: Query parameters for request, if any
    @type params: dict
    @return: HTTP response to request
    @rtype: dict
    @raise: ValueError: if invalid method provided
    """
    siem_auth = HTTPBasicAuth(siem_user, siem_password)

    if method.lower() == "get":
        r = requests.get(url, headers=headers, auth=siem_auth, params=params)
    elif method.lower() == "post":
        r = requests.post(url, headers=headers, auth=siem_auth, params=params)
    else:
        raise ValueError("Invalid method")

    # Print out the error message before throwing an HTTPError
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logging.error(r.text)
        raise e

    response_json: Dict[str, Any] = r.json()

    return response_json


class Graylog:
    """
    The object to instantiate to create a persistent interface to Graylog
    """

    def __init__(self, label: str):
        """
        Instantiate an instance of Graylog.

        @param label: A label to use for the generated API token, or easier debugging
        @type label: str
        """

        # Get API Token with username/password
        # Should create a non-admin user for this later...
        siem_host = os.getenv("GRAYLOG_HOST")
        siem_user = os.getenv("GRAYLOG_QUERY_USER")
        siem_password = os.getenv("GRAYLOG_QUERY_PASSWORD")

        if not (siem_host and siem_user and siem_password):
            raise ValueError("Missing parameters for Graylog SIEM connection")

        # Get Admin UUID
        user_url = f"{siem_host}/api/users/{siem_user}"
        user_res = make_graylog_request(
            user_url, "get", siem_user, siem_password, params={}
        )
        user_id = user_res["id"]

        # Get Token
        token_url = f"{siem_host}/api/users/{user_id}/tokens/aica_{label}"
        params = {"pretty": True}
        token_res = make_graylog_request(
            token_url, "post", siem_user, siem_password, params
        )
        logging.info("Got token for Graylog API")

        self.query_token = token_res["token"]
        self.query_url = f"{siem_host}/api/search/universal/absolute"

    def query_graylog(
        self, query_params: Dict[str, Union[str, int, List[str]]]
    ) -> requests.Response:
        """
        Make an API query to the Graylog server.

        @param query_params: Parameters for the desired query.
        @type query_params: dict
        @return: HTTP request to query
        @rtype: requests.Response
        """

        response = requests.get(
            self.query_url,
            headers=headers,
            auth=(self.query_token, "token"),
            params=query_params,
        )

        return response
