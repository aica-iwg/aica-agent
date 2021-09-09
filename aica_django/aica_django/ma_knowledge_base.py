# This microagent is responsible for storing facts about external data, past observations, possible actions, and other
# information necessary for the decisioning engine to determine the best course of action in response to an observed
# event. Much of this will be loaded by the offline loader at startup from static configuration, periodically by the
# offline loader, or by the online learning microagent. Per the NCIA SOW, knowledge could include:
#
# * World model
# * World state & history
# * World dynamics model
# * Actions & effects repertoire
# * Goals (missions & limits)
# * Agent states, priorities, rules, plans, and configurations
#
# This information is intended to be stored in the Postgresql Database server attached to the manager, which will
# require tables to be defined and created for each of the above.

import os

from celery.utils.log import get_task_logger
from pymongo.mongo_client import MongoClient
from urllib.parse import quote_plus

logger = get_task_logger(__name__)


def query_action(alert_dict):
    print(f"Running {__name__}: query_action")

    conn_str = f"mongodb://{quote_plus(str(os.getenv('MONGO_INITDB_USER')))}:" \
               f"{quote_plus(str(os.getenv('MONGO_INITDB_PASS')))}@" \
               f"{quote_plus(str(os.getenv('MONGO_SERVER')))}/" \
               f"{quote_plus(str(os.getenv('MONGO_INITDB_DATABASE')))}?retryWrites=true&w=majority"
    client = MongoClient(conn_str)
    db = client[str(os.getenv('MONGO_INITDB_DATABASE'))]

    recommended_actions = []
    if alert_dict["event_type"] == "alert":
        query = {"$and": [
            {"event_type": "alert"},
            {"$or": [{"signature_id": alert_dict["alert"]["signature_id"]},
                     {"signature_id": "*"}]}
        ]}
        recommended_actions = db["alert_response_actions"].find(query)

    return recommended_actions


def query_world_model():
    # TODO
    print(f"Running {__name__}: query_world_model")


def inform_world_model():
    # TODO
    print(f"Running {__name__}: inform_world_model")


def query_world_state():
    # TODO
    print(f"Running {__name__}: query_world_state")


def inform_world_state():
    # TODO
    print(f"Running {__name__}: inform_world_state")


def query_world_dynamics():
    # TODO
    print(f"Running {__name__}: query_world_dynamics")


def inform_world_dynamics():
    # TODO
    print(f"Running {__name__}: inform_world_dynamics")


def query_action_repertoire():
    # TODO
    print(f"Running {__name__}: query_action_repertoire")


def inform_action_repertoire():
    # TODO
    print(f"Running {__name__}: inform_action_repertoire")


def query_goals():
    # TODO
    print(f"Running {__name__}: query_goals")


def inform_goals():
    # TODO
    print(f"Running {__name__}: inform_goals")


def query_agent_parameters():
    # TODO
    print(f"Running {__name__}: query_agent_parameters")


def inform_agent_parameters():
    # TODO
    print(f"Running {__name__}: inform_agent_parameters")
