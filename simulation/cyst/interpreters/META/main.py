from dataclasses import dataclass
from typing import Tuple, Dict
from netaddr import IPAddress

from cyst.api.logic.access import AuthenticationToken, AuthenticationTarget, Authorization
from cyst.api.logic.action import ActionDescription, ActionToken, ActionParameterType, ActionParameter
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.environment.configuration import EnvironmentConfiguration
from cyst.api.environment.policy import EnvironmentPolicy
from cyst.api.environment.interpreter import ActionInterpreter, ActionInterpreterDescription
from cyst.api.environment.message import Request, Response, Status, StatusOrigin, StatusValue, StatusDetail
from cyst.api.network.node import Node

@dataclass
class AuthenticationTracker:
    src_ip: str
    src_service: str
    dst_ip: str
    dst_service: str
    identity: str
    step: int
    time: int
    attempts: int


class METAInterpreter(ActionInterpreter):
    def __init__(self, configuration: EnvironmentConfiguration, resources: EnvironmentResources,
                 policy: EnvironmentPolicy, messaging: EnvironmentMessaging) -> None:

        self._configuration = configuration
        self._action_store = resources.action_store
        self._exploit_store = resources.exploit_store
        self._policy = policy
        self._messaging = messaging
        self._authentications: Dict[Tuple[str, str, str, str, str], AuthenticationTracker] = {}

        self._action_store.add(ActionDescription("meta:inspect:node",
                                                 "Discovery of hosts in a network. Equivalent to ping scanning.",
                                                 [],
                                                 [(ActionToken.SESSION, ActionToken.NONE)]))

        self._action_store.add(ActionDescription("meta:authenticate",
                                                 "Authentication against a service.",
                                                 [ActionParameter(ActionParameterType.TOKEN, "auth_token", configuration.action.create_action_parameter_domain_any())],
                                                 [(ActionToken.NONE, ActionToken.NONE)])) # Tokens are wrong, I know that

    def evaluate(self, message: Request, node: Node) -> Tuple[int, Response]:
        if not message.action:
            raise ValueError("Action not provided")

        action_name = "_".join(message.action.fragments)
        fn = getattr(self, "process_" + action_name, self.process_default)
        return fn(message, node)

    def process_default(self, message: Request, node: Node) -> Tuple[int, Response]:
        print("Could not evaluate message. Tag in `meta` namespace unknown. " + str(message))
        return 0, self._messaging.create_response(message, status=Status(StatusOrigin.SYSTEM, StatusValue.ERROR), session=message.session)

    def process_inspect_node(self, message: Request, node: Node) -> Tuple[int, Response]:
        error = ""
        if message.src_ip != IPAddress("127.0.0.1"):  # Local IP has a free pass
            if not message.session:
                error = "Session not provided"
            elif message.session.end not in [x.ip for x in node.interfaces]:
                error = "Session does not end in required node"

        if error:
            return 0, self._messaging.create_response(message, Status(StatusOrigin.NETWORK, StatusValue.FAILURE), error, session=message.session)

        return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.SUCCESS),
                                                  node, session=message.session, auth=message.auth)

    def process_authenticate(self, message: Request, node: Node) -> Tuple[int, Response]:
        # To authenticate, an actor has to go through all the phases in the authentication scheme.
        # After each factor in authentication scheme is passed, the actor is given an authorization, which enables them
        # to attempt a next step. If it is the last step, the full authorization for this authentication scheme is
        # given.

        src_node = str(message.src_ip)
        src_service = message.src_service
        dst_node = str(message.dst_ip)
        dst_service = message.dst_service

        # First of all, check if the message contains authentication token
        token_found = False
        token = None
        t = message.action.parameters.get("auth_token", None)
        if t:
            if not isinstance(t, ActionParameter):
                raise RuntimeError("Wrong object type supplied as action parameter. Type: " + str(type(t)))

            if t.type == ActionParameterType.TOKEN and t.value:
                token_found = True
                token = t.value

        if not token_found:
            return 0, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE, StatusDetail.AUTHENTICATION_NOT_PROVIDED),
                                                      "No auth token provided", session=message.session, auth=message.auth)

        #  check if node has the target service
        s = node.services.get(dst_service)
        if s is None:
            return 0, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE,
                                                                      StatusDetail.AUTHENTICATION_NOT_PROVIDED),
                                                      "Service does not exist on this node", session=message.session,
                                                      auth=message.auth)


        #  evaluate the token
        result = self._configuration.access.evaluate_token_for_service(s, token, node, message.dst_ip)

        if result is None:
            return 0, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE,
                                                                      StatusDetail.AUTHENTICATION_NOT_APPLICABLE),
                                                      "Token invalid for this service", session=message.session,
                                                      auth=message.auth)

        if isinstance(result, AuthenticationTarget):
            return 0, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE,
                                                                      StatusDetail.AUTHENTICATION_NEXT),
                                                      "Continue with next factor", session=message.session,
                                                      auth=result)

        if isinstance(result, Authorization):
            return 0, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                                                      "Authorized", session=message.session,
                                                      auth=result)




def create_meta_interpreter(configuration: EnvironmentConfiguration, resources: EnvironmentResources,
                            policy: EnvironmentPolicy, messaging: EnvironmentMessaging) -> ActionInterpreter:
    interpreter = METAInterpreter(configuration, resources, policy, messaging)
    return interpreter


action_interpreter_description = ActionInterpreterDescription(
    "meta",
    "Interpreter for auxiliary actions needed to supplement",
    create_meta_interpreter
)