from typing import Tuple

from cyst.api.logic.action import ActionDescription, ActionToken, ActionParameterType, ActionParameter
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.environment.configuration import EnvironmentConfiguration
from cyst.api.environment.policy import EnvironmentPolicy
from cyst.api.environment.interpreter import ActionInterpreter, ActionInterpreterDescription
from cyst.api.environment.message import Request, Response
from cyst.api.network.node import Node


class NCIAInterpreter(ActionInterpreter):
    def __init__(self, configuration: EnvironmentConfiguration, resources: EnvironmentResources,
                 policy: EnvironmentPolicy, messaging: EnvironmentMessaging) -> None:

        self._configuration = configuration
        self._action_store = resources.action_store
        self._exploit_store = resources.exploit_store
        self._policy = policy
        self._messaging = messaging

        self._action_store.add(ActionDescription("ncia:communicate",
                                                 "Pass information between active services.",
                                                 [ActionParameter(ActionParameterType.NONE, "data",
                                                                  configuration.action.create_action_parameter_domain_any())],
                                                 [(ActionToken.NONE, ActionToken.NONE)]))

        self._action_store.add(ActionDescription("ncia:redirect",
                                                 "Ensure redirection of all communication from source to target",
                                                 [ActionParameter(ActionParameterType.NONE, "src_ip",
                                                                  configuration.action.create_action_parameter_domain_any()),
                                                  ActionParameter(ActionParameterType.NONE, "dst_ip",
                                                                  configuration.action.create_action_parameter_domain_any())],
                                                 [(ActionToken.NONE, ActionToken.NONE)]))

    def evaluate(self, message: Request, node: Node) -> Tuple[int, Response]:
        raise RuntimeError("All actions in the NCIA namespace must be directed towards active services, which process them on their own. Passive processing not supported")


def create_ncia_interpreter(configuration: EnvironmentConfiguration, resources: EnvironmentResources,
                            policy: EnvironmentPolicy, messaging: EnvironmentMessaging) -> ActionInterpreter:
    interpreter = NCIAInterpreter(configuration, resources, policy, messaging)
    return interpreter


action_interpreter_description = ActionInterpreterDescription(
    "ncia",
    "Placeholder for actions related to the AICAProto21 demo.",
    create_ncia_interpreter
)