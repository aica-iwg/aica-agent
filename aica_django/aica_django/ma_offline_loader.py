# This microagent is responsible for pulling in any external data relevant to decision making by the agent
# and loading/sending it to the knowledge base microagent. Per the NCIA SOW this is to include the following undefined
# capabilities:
#
# * World Description
# * Competence
# * Purpose
# * Behavior
#
# It is the initial script called when Celery is started and is responsible for launching other tasks.

import os
import yaml
from celery.execute import send_task
from celery.signals import worker_ready
from celery.utils.log import get_task_logger
from pymongo.mongo_client import MongoClient
from urllib.parse import quote_plus


logger = get_task_logger(__name__)


@worker_ready.connect
def initialize(**kwargs):
    logger.info(f"Running {__name__}: initialize")
    if os.environ.get("SKIP_TASKS"):
        return

    # Load data from static files into MongoDB
    mongo_conn = f"mongodb://{quote_plus(str(os.getenv('MONGO_INITDB_USER')))}:" \
                 f"{quote_plus(str(os.getenv('MONGO_INITDB_PASS')))}@" \
                 f"{quote_plus(str(os.getenv('MONGO_SERVER')))}/" \
                 f"{quote_plus(str(os.getenv('MONGO_INITDB_DATABASE')))}?retryWrites=true&w=majority"
    mongo_client = MongoClient(mongo_conn)
    mongo_db = mongo_client[str(os.getenv('MONGO_INITDB_DATABASE'))]

    with open("response_actions.yml", "r") as actions_file:
        alert_actions = yaml.safe_load(actions_file)["responseActions"]["alerts"]
        mongo_db["alert_response_actions"].insert_many(alert_actions)

    # Start the persistent DB (or file) polling process
    send_task('ma_collaboration-poll_dbs')

    mongo_client.close()
