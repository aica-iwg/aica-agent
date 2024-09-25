import os
import time
import warnings

from celery import shared_task
from celery.utils.log import get_task_logger
from datetime import datetime
from flwr.client import start_client  # type: ignore
from typing import NoReturn

from aica_django.connectors.GraphDatabase import AicaNeo4j
from aica_django.microagents.AICAFlowerClient import AICAFlowerClient


warnings.filterwarnings("ignore", category=UserWarning)

logger = get_task_logger(__name__)

client = AICAFlowerClient()


@shared_task(name="online-learning-trainer")
def periodic_trainer(period_seconds: int = 300) -> NoReturn:
    global_model_server = os.environ.get("AICA_MODEL_SERVER", None)
    graph_db = AicaNeo4j()
    last_training = 0

    bad_traffic_query = f"""
    MATCH (n:`network-traffic`)<-[:object]-(:`observed-data`)-[:sighting_of]->(:indicator)-[:indicates]->(m:`attack-pattern`)
        WHERE n.graph_embedding IS NOT NULL 
            AND n.last_merge >= {last_training}
        RETURN n.graph_embedding AS embedding, m.name AS category"""

    good_traffic_query = f"""
    MATCH (n:`network-traffic`)<-[:object]-(:`observed-data`)-[:sighting_of]->(:indicator)-[:indicates]->(m:`attack-pattern`)
        WHERE n.graph_embedding IS NOT NULL 
            AND n.last_merge >= {last_training} 
        WITH COLLECT(DISTINCT n) AS all_connected_to_m
        MATCH (n2:`network-traffic`)
            WHERE NOT n2 IN all_connected_to_m
                AND n2.graph_embedding IS NOT NULL
        RETURN n2.graph_embedding AS embedding, "Not Suspicious Traffic" AS category"""

    while True:
        bad_traffic, _, _ = graph_db.graph.execute_query(bad_traffic_query)
        good_traffic, _, _ = graph_db.graph.execute_query(good_traffic_query)
        logger.info(f"Bad traffic length {len(bad_traffic)}")
        logger.info(f"Good traffic length {len(good_traffic)}")

        try:
            client.load_data(good_traffic, bad_traffic, test_size=0.2)

            client.train()
            last_training = int(datetime.now().timestamp())

            if global_model_server:
                start_client(
                    server_address=global_model_server,
                    client=client.to_client(),
                )
            else:
                logger.warning("No global model server IP provided")
        except ValueError as e:
            logger.warning(e)

        time.sleep(period_seconds)


@shared_task(name="online-learning-predictor")
def periodic_predictor(period_seconds: int = 300) -> NoReturn:
    while True:
        logger.info("Predictor not yet implemented")
        # TODO

        time.sleep(period_seconds)
