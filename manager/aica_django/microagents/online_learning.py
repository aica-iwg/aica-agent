# This microagent is responsible for pulling in any external data relevant to decision-
# making by the agent and loading/sending it to the knowledge base microagent during
# runtime. Per the NCIA SOW this is to include the following information:
#
# * World Description
# * Competence
# * Purpose
# * Behavior
#
# It is scheduled to run on a periodic basis via the main celery app.

from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)
