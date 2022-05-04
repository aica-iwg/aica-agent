# This microagent is responsible for coordinating external inputs and outputs such
# as communication with other agents, command and control, or human operators. As
# such, the input tasks here will likely consist of either polling of shared
# database tables, or tasks called by Django REST endpoints. Outputs are likely to
# be called by the decision making engine microagent.

from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)
