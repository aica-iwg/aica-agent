# This microagent is responsible for monitoring the environment and determining the best course of action to take
# when potentially interest events are observed. It may invoke the behavior engine microagent for adjudication on
# acceptable courses of action, the knowledge base microagent to enrich its understanding of an observed event, the
# online learning microagent to apply ML-based methods to evaluating observations, or the collaboration microagent to
# send commands to external devices for the purposes of response. It is invoked by the offline loader after
# initialization. Per the NCIA SOW, capabilities could include:
#
# * Sensing (acquisition)
# * Situational awareness
# * Action planning
# * Action selection
# * Action activation

import time
from celery.decorators import task
from celery.execute import send_task
from celery.utils.log import get_task_logger

from aica_django.ma_knowledge_base import query_action
from aica_django.ma_behaviour_engine import query_rules

logger = get_task_logger(__name__)


@task(name="ma_decision_making_engine-monitor")
def monitor():
    logger.info(f"Running {__name__}: monitor")

    while True:
        time.sleep(1)


@task(name="ma_decision_making_engine-handle_alert")
def handle_alert(alert_dict):
    logger.info(f"Running {__name__}:")

    # Query for recommendation from knowledge base
    recommended_actions = query_action(alert_dict)

    # Check with behavior engine
    approved_actions = []
    for action in recommended_actions:
        if query_rules(alert_dict, action) == "proceed":
            approved_actions.append(action)

    # Here we would apply some scoring as to the best action, using information about goals and world state.
    # For now we just take the first approved action (if any).
    if len(approved_actions) > 0:
        action_to_take = approved_actions[0]

        if action_to_take["action"] == "honeypot":
            logger.info(f"Redirecting traffic from {alert_dict['src_ip']} to {alert_dict['dest_ip']} to honeypot.")
            send_task('ma_collaboration-redirect_to_honeypot_iptables', [alert_dict['src_ip'], alert_dict['dest_ip']])
