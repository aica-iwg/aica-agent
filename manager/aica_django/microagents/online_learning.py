"""
This microagent is responsible for pulling in any external data relevant to decision-
making by the agent and loading/sending it to the knowledge base microagent during
runtime.

This should eventually include:
* World Description
* Competence
* Purpose
* Behavior
"""

from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)
