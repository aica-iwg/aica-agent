"""
This microagent is responsible for pulling in any external data relevant to decision-
making by the agent and loading/sending it to the knowledge base microagent during
runtime.
"""

import os
import time

from celery import shared_task
from celery.utils.log import get_task_logger
from typing import NoReturn

from aica_django.connectors.GraphDatabase import AicaNeo4j

logger = get_task_logger(__name__)


@shared_task(name="online-learning-trainer")
def periodic_trainer(period_seconds: int = 300) -> NoReturn:
    global_model_server = os.environ.get("AICA_MODEL_SERVER", None)
    graph_db = AicaNeo4j()

    bad_traffic_query = f"""
    MATCH (n:`network-traffic`)<-[:object]-(:`observed-data`)-[:sighting_of]->(:indicator)-[:indicates]->(m:`attack-pattern`)
        WHERE n.graph_embedding IS NOT NULL 
            AND n.last_merge >= (timestamp() / 1000) - {period_seconds}
        RETURN n.graph_embedding AS embedding, m.name AS category"""

    good_traffic_query = f"""
    MATCH (n:`network-traffic`)<-[:object]-(:`observed-data`)-[:sighting_of]->(:indicator)-[:indicates]->(m:`attack-pattern`)
        WHERE n.graph_embedding IS NOT NULL 
            AND n.last_merge >= (timestamp() / 1000) - {period_seconds}
        WITH COLLECT(DISTINCT n) AS all_connected_to_m
        MATCH (n2:`network-traffic`)
            WHERE NOT n2 IN all_connected_to_m
                AND n2.graph_embedding IS NOT NULL
        RETURN n2.graph_embedding AS embedding, "Not Suspicious Traffic" AS category"""

    while True:
        # Fetch data from Neo4j
        bad_traffic, _, _ = graph_db.graph.execute_query(bad_traffic_query)
        good_traffic, _, _ = graph_db.graph.execute_query(good_traffic_query)

        # Update local model
        logger.info("Local model updating not yet implemented")
        # TODO

        # Exchange parameters with global model server
        if global_model_server:
            logger.info("Federation not yet implemented")
            # TODO
        else:
            logger.warning("No global model server IP provided")

        time.sleep(period_seconds)


@shared_task(name="online-learning-predictor")
def periodic_predictor(period_seconds: int = 300) -> NoReturn:
    while True:
        logger.info("Predictor not yet implemented")
        # TODO

        time.sleep(period_seconds)
