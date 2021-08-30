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
from celery.execute import send_task
from celery.signals import worker_ready
from celery.utils.log import get_task_logger


logger = get_task_logger(__name__)


@worker_ready.connect
def initialize(**kwargs):
    # TODO: Do initialization from static configuration
    logger.info(f"Running {__name__}: initialize")
    if os.environ.get("SKIP_TASKS"):
        return

    send_task('ma_collaboration-poll_dbs')
