# This microagent is responsible for storing facts about external data, past
# observations, possible actions, and other information necessary for the decisioning
# engine to determine the best course of action in response to an observed event. Much
# of this will be loaded by the offline loader at startup from static configuration,
# periodically by the offline loader, or by the online learning microagent.
#
# Per the NCIA SOW, knowledge could include:
#
# * World model
# * World state & history
# * World dynamics model
# * Actions & effects repertoire
# * Goals (missions & limits)
# * Agent states, priorities, rules, plans, and configurations
#
# This information is intended to be stored in the Postgresql Database server attached
# to the manager, which will require tables to be defined and created for each of the
# above.

from celery.utils.log import get_task_logger

from connectors.AicaMongo import AicaMongo

logger = get_task_logger(__name__)


def query_action(alert_dict):
    print(f"Running {__name__}: query_action")
    mongo_client = AicaMongo()
    mongo_db = mongo_client.get_db_handle()

    recommended_actions = []
    if alert_dict["event_type"] == "alert":
        query = {
            "$and": [
                {"event_type": "alert"},
                {
                    "$or": [
                        {"signature_id": alert_dict["alert"]["signature_id"]},
                        {"signature_id": "*"},
                    ]
                },
            ]
        }
        recommended_actions = mongo_db["alert_response_actions"].find(query)

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
