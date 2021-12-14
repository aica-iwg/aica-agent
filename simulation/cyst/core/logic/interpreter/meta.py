import sys

from typing import List, Tuple

from environment.action import Action, ActionList
from environment.environment import environment_interpreters
from environment.message import Response, Request, Status, StatusValue, StatusOrigin
from environment.node import Node


ActionList().add_action(Action("meta:node_info:get_interfaces"))


def evaluate(names: List[str], message: Request, node: Node, env: 'Environment'):
    if not names:
        return 0, None

    # Gah... changing it back and forth.
    tag = "_".join(names)

    fn = getattr(sys.modules[__name__], "process_" + tag, process_default)
    return fn(message, node, env)


environment_interpreters["meta"] = evaluate


def process_default(message, node, env) -> Tuple[int, Response]:
    return 0, Response(message, Status(StatusOrigin.SYSTEM, StatusValue.ERROR),
                       "Could not evaluate message. Tag {} in `meta` namespace unknown.".format(message.action.tags[0].name),
                       session=message.session, authorization=message.authorization)


def process_node_info_get_interfaces(message: Request, node: Node, env: 'Environment') -> Tuple[int, Response]:
    # Interface information is provided in case the node is the same as the origin, or when there is a session to the
    # target node
    error = ""
    if message.origin != node.id and (message.session and message.session.endpoint.id != node.id):
        error = "Cannot get interface information of a node without local access"

    if error:
        return 1, Response(message, Status(StatusOrigin.NODE, StatusValue.ERROR), error, session=message.session)

    return 1, Response(message, Status(StatusOrigin.NODE, StatusValue.SUCCESS), node.interfaces, session=message.session)
