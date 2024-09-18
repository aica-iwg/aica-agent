"""
This module contains all code relevant to interacting with the Graylog SIEM.

Classes:
    Graylog: The object to instantiate to create a persistent interface with Graylog's API

Functions:
    make_request: A rate limited static function to make requests to Graylog's API, with retry logic.
"""

import json
import os
import requests

from celery.utils.log import get_task_logger
from requests.auth import HTTPBasicAuth
from typing import Dict, Optional, Union


logger = get_task_logger(__name__)

headers = {"Accept": "application/json"}


class SIEM:
    """
    The object to instantiate to create a persistent interface to Graylog
    """

    def __init__(self) -> None:
        """
        Instantiate an instance of Graylog.

        @param label: A label to use for the generated API token, or easier debugging
        @type label: str
        """

        self.siem_host = os.getenv("OS_HOST", "localhost")
        self.siem_port = os.getenv("OS_PORT", "9200")
        self.siem_user = os.getenv("OS_API_USER", None)
        self.siem_password = os.getenv("OS_API_PASS", None)

    def query_siem(
        self,
        queries: Dict[str, str],
        antiqueries: Optional[Dict[str, str]] = None,
        from_timestamp: Optional[int] = None,
        to_timestamp: Optional[int] = None,
    ) -> requests.Response:
        """
        Make an API query to the Graylog server.

        @param query_params: Parameters for the desired query.
        @type query_params: dict
        @return: HTTP request to query
        @rtype: requests.Response
        """

        if not (
            self.siem_host and self.siem_port and self.siem_user and self.siem_password
        ):
            raise ValueError("Missing parameters for SIEM connection")

        siem_auth = HTTPBasicAuth(self.siem_user, self.siem_password)

        query_body = {
            "query": {
                "bool": {
                    "must": [{"match": {k: v}} for k, v in queries.items()],
                }
            },
        }

        if antiqueries:
            query_body["query"]["bool"]["must_not"] = [
                {"match": {k: v}} for k, v in antiqueries.items()
            ]

        if from_timestamp or to_timestamp:
            range_query = dict()

            range_query["range"] = {"@timestamp": {"format": "epoch_second"}}

            if from_timestamp:
                range_query["range"]["@timestamp"]["gte"] = str(from_timestamp)

            if to_timestamp:
                range_query["range"]["@timestamp"]["lte"] = str(to_timestamp)

            query_body["query"]["bool"]["must"].append(range_query)  # type: ignore

        response = requests.get(
            f"https://{self.siem_host}:{self.siem_port}/aica/_search",
            headers=headers,
            auth=siem_auth,
            json=query_body,
            verify="/usr/src/app/rootCA.crt",
        )
        try:
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Failed to run query: {json.dumps(query_body)}")
            raise e

        return response
