import sys
import uuid

from typing import List, Tuple

from cyst.api.logic.access import Authorization, AccessLevel
from cyst.api.logic.action import ActionDescription, ActionToken, ActionParameterType, ActionParameter
from cyst.api.logic.exploit import ExploitParameterType, ExploitLocality, ExploitCategory
from cyst.api.host.service import PassiveService
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.environment.configuration import EnvironmentConfiguration
from cyst.api.environment.policy import EnvironmentPolicy
from cyst.api.environment.interpreter import ActionInterpreter, ActionInterpreterDescription
from cyst.api.environment.message import Request, Response, Status, StatusOrigin, StatusValue
from cyst.api.network.node import Node
from cyst.api.utils.counter import Counter

# Actions to do
# ActionList().add_action(Action("rit:privilege_escalation:network_sniffing_ca"))
# ActionList().add_action(Action("rit:privilege_escalation:brute_force_ca"))
# ActionList().add_action(Action("rit:privilege_escalation:account_manipulation"))
# ActionList().add_action(Action("rit:targeted_exploits:trusted_organization_exploitation"))
# ActionList().add_action(Action("rit:targeted_exploits:exploit_public_facing_application"))
# ActionList().add_action(Action("rit:targeted_exploits:exploit_remote_services"))
# ActionList().add_action(Action("rit:targeted_exploits:spearphishing"))
# ActionList().add_action(Action("rit:targeted_exploits:service_specific_exploitation"))
# ActionList().add_action(Action("rit:targeted_exploits:arbitrary_code_execution"))
# ActionList().add_action(Action("rit:ensure_access:defense_evasion"))
# ActionList().add_action(Action("rit:zero_day:privilege_escalation"))
# ActionList().add_action(Action("rit:zero_day:targeted_exploit"))
# ActionList().add_action(Action("rit:zero_day:ensure_access"))
# ActionList().add_action(Action("rit:disrupt:end_point_dos"))
# ActionList().add_action(Action("rit:disrupt:network_dos"))
# ActionList().add_action(Action("rit:disrupt:service_stop"))
# ActionList().add_action(Action("rit:disrupt:resource_hijacking"))
# ActionList().add_action(Action("rit:destroy:content_wipe"))
# ActionList().add_action(Action("rit:distort:data_encryption"))
# ActionList().add_action(Action("rit:distort:defacement"))
# ActionList().add_action(Action("rit:distort:data_manipulation"))
# ActionList().add_action(Action("rit:delivery:data_delivery"))


class AIFInterpreter(ActionInterpreter):

    def __init__(self, configuration: EnvironmentConfiguration, resources: EnvironmentResources,
                 policy: EnvironmentPolicy, messaging: EnvironmentMessaging) -> None:

        self._action_store = resources.action_store
        self._exploit_store = resources.exploit_store
        self._messaging = messaging
        self._policy = policy
        self._configuration = configuration

        self._action_store.add(ActionDescription("aif:active_recon:host_discovery",
                                                 "Discovery of hosts in a network. Equivalent to ping scanning.",
                                                 [],
                                                 [(ActionToken.NONE, ActionToken.NONE)]))

        self._action_store.add(ActionDescription("aif:active_recon:service_discovery",
                                                 "Discovery of services on a host. Equivalent to TCP/SYN scanning.",
                                                 [],
                                                 [(ActionToken.NONE, ActionToken.NONE)]))

        self._action_store.add(ActionDescription("aif:active_recon:vulnerability_discovery",
                                                 "Discovery of information pertaining to a chosen service. Can be used as a base for exploit selection",
                                                 [],
                                                 [(ActionToken.NONE, ActionToken.NONE)]))

        self._action_store.add(ActionDescription("aif:active_recon:information_discovery",
                                                 "Discovery of publicly available information. Can be used to get data or auth.",
                                                 [],
                                                 [(ActionToken.NONE, ActionToken.NONE),
                                                  (ActionToken.NONE, ActionToken.AUTH),
                                                  (ActionToken.NONE, ActionToken.DATA),
                                                  (ActionToken.NONE, ActionToken.AUTH | ActionToken.DATA)]))

        self._action_store.add(ActionDescription("aif:privilege_escalation:user_privilege_escalation",
                                                 "Obtain privileges of another user of the same access level.",
                                                 [],
                                                 [(ActionToken.SESSION, ActionToken.AUTH),
                                                  (ActionToken.EXPLOIT | ActionToken.SESSION, ActionToken.AUTH)]))

        self._action_store.add(ActionDescription("aif:privilege_escalation:root_privilege_escalation",
                                                 "Obtain privileges of another user with elevated access level.",
                                                 [],
                                                 [(ActionToken.SESSION, ActionToken.AUTH),
                                                  (ActionToken.EXPLOIT | ActionToken.SESSION, ActionToken.AUTH)]))

        self._action_store.add(ActionDescription("aif:ensure_access:command_and_control",
                                                 "Get session to the target service.",
                                                 [],
                                                 [(ActionToken.AUTH, ActionToken.SESSION),
                                                  (ActionToken.EXPLOIT, ActionToken.SESSION)]))

        self._action_store.add(ActionDescription("aif:disclosure:data_exfiltration",
                                                 "Gather data from the target.",
                                                 [],
                                                 [(ActionToken.AUTH, ActionToken.DATA),
                                                  (ActionToken.AUTH | ActionToken.SESSION, ActionToken.DATA),
                                                  (ActionToken.EXPLOIT | ActionToken.SESSION, ActionToken.DATA)]))

        self._action_store.add(ActionDescription("aif:destroy:data_destruction",
                                                 "Destroy data at the target.",
                                                 [ActionParameter(ActionParameterType.IDENTIFIER, "id",
                                                                  self._configuration.action.create_action_parameter_domain_any())],
                                                 [(ActionToken.AUTH, ActionToken.NONE),
                                                  (ActionToken.AUTH | ActionToken.SESSION, ActionToken.NONE),
                                                  (ActionToken.EXPLOIT | ActionToken.SESSION, ActionToken.NONE)]))

        self._action_store.add(ActionDescription("aif:ensure_access:lateral_movement",
                                                 "Spawn an instance of active service on a target host",
                                                 [ActionParameter(ActionParameterType.IDENTIFIER, "id",
                                                                  self._configuration.action.create_action_parameter_domain_any())],
                                                 [(ActionToken.AUTH | ActionToken.SESSION, ActionToken.NONE),
                                                  (ActionToken.EXPLOIT | ActionToken.SESSION, ActionToken.NONE),
                                                  (ActionToken.EXPLOIT, ActionToken.NONE)]))

        self._action_store.add(ActionDescription("aif:targeted_exploits:exploit_remote_services",
                                                 "Get access to session provided by an exploitable service",
                                                 [],
                                                 [(ActionToken.EXPLOIT | ActionToken.SESSION, ActionToken.SESSION)]))

    def evaluate(self, message: Request, node: Node) -> Tuple[int, Response]:
        if not message.action:
            raise ValueError("Action not provided")

        action_name = "_".join(message.action.fragments)
        fn = getattr(self, "process_" + action_name, self.process_default)
        return fn(message, node)

    def process_default(self, message: Request, node: Node) -> Tuple[int, Response]:
        print("Could not evaluate message. Tag in `aif` namespace unknown. " + str(message))
        return 0, self._messaging.create_response(message, status=Status(StatusOrigin.SYSTEM, StatusValue.ERROR), session=message.session)

    def process_active_recon_host_discovery(self, message: Request, node: Node) -> Tuple[int, Response]:
        return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.SUCCESS),
                                                  None, session=message.session, auth=message.auth)

    def process_active_recon_service_discovery(self, message: Request, node: Node) -> Tuple[int, Response]:
        # TODO Only show services, which are opened to outside
        return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.SUCCESS),
                                                  [x for x in node.services], session=message.session, auth=message.auth)

    def process_active_recon_vulnerability_discovery(self, message: Request, node: Node) -> Tuple[int, Response]:
        # TODO Only works on services, which are opened to outside
        if message.dst_service and message.dst_service in node.services:
            service_tags = [message.dst_service + "-" + str(node.services[message.dst_service].version)]
            service_tags.extend(node.services[message.dst_service].tags)
            return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                                                      service_tags, session=message.session, auth=message.auth)
        else:
            return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.ERROR),
                                                      "No/wrong service specified for vulnerability discovery", session=message.session,
                                                      auth=message.auth)

    def process_active_recon_information_discovery(self, message: Request, node: Node) -> Tuple[int, Response]:
        # TODO Only works on services, which are opened to outside
        if message.dst_service and message.dst_service in node.services:
            public_data = self._configuration.service.public_data(node.services[message.dst_service].passive_service)
            public_authorizations = self._configuration.service.public_authorizations(node.services[message.dst_service].passive_service)
            private_authorizations = []

            # TODO: this needs to be extended for data manipulation and I must decided what to do when user presents
            #       authorization. The situation is not clear-cut especially if the target service is a shell
            #       Also exploit locality must be considered
            es = message.action.exploit
            if es:
                if es and es.category == ExploitCategory.AUTH_MANIPULATION:
                    if self._exploit_store.evaluate_exploit(es, message, node):
                        # successful exploit
                        # TODO: should it be possible to limit access to private authorizations based on the id?
                        private_authorizations.extend(self._configuration.service.private_authorizations(node.services[message.dst_service].passive_service))

            if public_authorizations or public_data or private_authorizations:
                return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                                                          public_data + public_authorizations + private_authorizations, session=message.session,
                                                          auth=message.auth)
            else:
                return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                                                          None, session=message.session,
                                                          auth=message.auth)

        return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.ERROR),
                                                  "No/wrong service specified for vulnerability discovery", session=message.session,
                                                  auth=message.auth)

    def process_ensure_access_command_and_control(self, message: Request, node: Node) -> Tuple[int, Response]:
        # TODO Only works on services, which are opened to outside

        # Check if the service is running on the target
        error = ""
        if not message.dst_service:
            error = "Service for session creation not specified"
        # ... and if the attacker provided either an authorization, or an exploit
        elif not message.auth and not message.action.exploit:
            error = "Neither authorization token nor exploit specified to ensure command and control"

        if error:
            return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.ERROR), error, session=message.session)

        # First of all, if the attacker provided an authorization token, it is tried first as it should not trigger
        # a defensive reaction
        if message.auth:
            # Authorization without enabled session creation does not work
            if not node.services[message.dst_service].passive_service.enable_session:
                error = "Service {} at node {} does not enable session creation.".format(message.dst_service, message.dst_ip)

            # check authorization and eventually create a session object to return
            # TODO: decide on session creation via configuration and via interpreters
            elif self._policy.decide(node, message.dst_service, node.services[message.dst_service].passive_service.session_access_level, message.auth)[0]:
                return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                                                          node, session=self._configuration.network.create_session_from_message(message),
                                                          auth=message.auth)
        if message.action.exploit:
            # Successful exploit creates a new authorization, which has a service_access_level and user = service name
            if self._exploit_store.evaluate_exploit(message.action.exploit, message, node)[0]:
                access_level = node.services[message.dst_service].service_access_level
                param = message.action.exploit.parameters.get(ExploitParameterType.ENABLE_ELEVATED_ACCESS, None)
                if param and param.value == "TRUE":
                    access_level = AccessLevel.ELEVATED
                auth = self._policy.create_authorization(message.dst_service, [node], [message.dst_service, node.shell],
                                                         access_level, "evil_one")
                return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS),
                                                          node, session=self._configuration.network.create_session_from_message(message),
                                                          auth=auth)
            else:
                error = "Service {} not exploitable using the exploit {}".format(message.dst_service, message.action.exploit.id)

        return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE), error, session=message.session, auth=message.auth)

    def process_privilege_escalation(self, message: Request, node: Node, mode: str) -> Tuple[int, Response]:
        # To successfully manage a user privilege escalation, the attacker must already have an active session on the
        # target and must try to impersonate a user with same or lower access level on a service they have auth for.

        # Check if the service is running on the target
        error = ""
        if not message.dst_service:
            error = "Service for session creation not specified"

        if error:
            return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.ERROR), error, session=message.session, auth=message.auth)

        # Check if exploit is correctly provided
        error = ""
        if message.action.exploit.locality != ExploitLocality.LOCAL:
            error = "User privilege escalation can only be done by a local exploit"
        elif message.action.exploit.category != ExploitCategory.AUTH_MANIPULATION:
            error = "User privilege escalation requires auth manipulation exploit"

        user_required = "root"
        impersonate_any = False
        nodes = []
        services = []

        # The parameters were changed from list to a dict, but the iteration was kept as-is, because it makes the processing
        # easier and more direct. But it should probably be revised, if the number of parameters for exploits starts to
        # grow considerably.
        for param in message.action.exploit.parameters.values():
            if param.type == ExploitParameterType.IDENTITY:
                user_required = param.value
            elif param.type == ExploitParameterType.IMPACT_IDENTITY and param.value == "ALL":
                impersonate_any = True
            elif param.type == ExploitParameterType.IMPACT_NODE and param.value == "ALL":
                nodes = ["*"]
            elif param.type == ExploitParameterType.IMPACT_SERVICE and param.value == "ALL":
                services = ["*"]

        if not nodes:
            nodes = [node]

        if not services:
            services = [message.dst_service]

        error = ""
        if mode == "user":
            if not message.action.exploit.parameters:
                error = "User privilege escalation requires one parameter - resulting user id"
            elif not impersonate_any and user_required == "root":
                error = "Either root was specified contrary to action designation or no user was provided"

        if error:
            self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE), error, session=message.session)

        # Check if a service is to exploit is accessible
        # TODO: session endpoint is compared on an IP basis. This could theoretically lead to session spoofing, need to check

        if not message.session or message.session.end not in node.ips:
            error = "No session opened to the node {} to apply local exploit".format(node)
            return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.ERROR), error,
                                                      session=message.session)

        if not message.auth or (message.dst_service not in self._policy.get_services(message.auth) and self._policy.get_services(message.auth) != ["*"]):
            error = "No proper authorization for service {} available".format(message.dst_service)
            return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE), error,
                                                      session=message.session)

        # Check if the exploit is applicable
        result, error = self._exploit_store.evaluate_exploit(message.action.exploit, message, node)

        if not result:
            return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE), error, session=message.session)

        # Check if the provided user id is applicable
        if mode == "user" and not impersonate_any:
            user_found = False
            auths = self._policy.get_authorizations(node, message.dst_service, AccessLevel.LIMITED)
            for auth in auths:
                if auth.identity == user_required:
                    user_found = True
                    break

            if not user_found:
                return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
                                                          "Attempting to switch to a user {} who is not available at the service".format(user_required), session=message.session)

        if impersonate_any:
            user_required = "*"

        # Root exploit adds a new root user even if the user was not pre-existing
        new_auth = self._policy.create_authorization(user_required, nodes, services,
                                                     access_level=AccessLevel.LIMITED if mode == "user" else AccessLevel.ELEVATED,
                                                     id="evil_one")

        return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), "",
                                                  session=message.session, auth=new_auth)

    def process_privilege_escalation_root_privilege_escalation(self, message: Request, node: Node) -> Tuple[int, Response]:
        return self.process_privilege_escalation(message, node, "root")

    def process_privilege_escalation_user_privilege_escalation(self, message: Request, node: Node) -> Tuple[int, Response]:
        return self.process_privilege_escalation(message, node, "user")

    def process_disclosure_data_exfiltration(self, message: Request, node: Node) -> Tuple[int, Response]:
        # Check if the service is running on the target
        error = ""
        if not message.dst_service:
            error = "Service for session creation not specified"
            return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.ERROR), error,
                                                      session=message.session)

        service = node.services[message.dst_service].passive_service

        if service.local and (not message.session or not message.session.end in node.ips):
            error = "Trying to access local service without a session to the node"
            return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.ERROR), error,
                                                      session=message.session)

        # Gather public data
        # TODO Public data are extracted with the information discovery action. Should it be included here?
        result = list()
        result.extend(self._configuration.service.public_data(service))

        # Go through the private data
        # Made them accessible only if the attacker has a valid authorization for given service and the authorization
        # lists them as an owner of the data
        if message.auth:
            authorized_services = self._policy.get_services(message.auth)
            if (message.auth and
                ("*" in authorized_services or message.dst_service in authorized_services)):

                for datum in self._configuration.service.private_data(service):
                    if message.auth.identity == '*' or message.auth.identity == datum.owner:
                        result.append(datum)

        return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), result, session=message.session)

    def process_destroy_data_destruction(self, message: Request, node: Node) -> Tuple[int, Response]:
        # Check if the service is running on the target
        error = ""
        if not message.dst_service:
            error = "Service for session creation not specified"
        elif node.services[message.dst_service].passive_service.local and (not message.session or not message.session.end in node.ips):
            error = "Trying to access local service without a session to the node"

        if error:
            return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.ERROR), error, session=message.session)

        service = node.services[message.dst_service].passive_service

        # Data destruction only with authorization
        if (not message.auth or
            message.dst_service not in self._policy.get_services(message.auth) or
            # TODO Replace this check with some sane policy decision
            node.id not in self._policy.get_nodes(message.auth)):

            return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE),
                                                      "Unauthorized attempt to delete data", session=message.session)

        # This function silently does nothing if there are no data specified for destruction
        # TODO Decide what to do, if user has an elevated access level or is a root
        if message.action.parameters:
            delete_ids = []
            new_data = []

            if "id" in message.action.parameters:
                for item in message.action.parameters["id"].value:
                    # There is no checking...
                    temp = item
                    if not isinstance(temp, uuid.UUID):
                        temp = uuid.UUID(item)
                    delete_ids.append(temp)

            # Check public data
            for datum in self._configuration.service.public_data(service):
                if datum.id not in map(str, delete_ids) or datum.owner != message.auth.identity:
                    new_data.append(datum)

            self._configuration.service.public_data(service).clear()
            self._configuration.service.public_data(service).extend(new_data)

            # Check private data
            new_data.clear()

            for datum in self._configuration.service.private_data(service):
                if datum.id not in map(str, delete_ids) or datum.owner != message.auth.identity:
                    new_data.append(datum)

            self._configuration.service.private_data(service).clear()
            self._configuration.service.private_data(service).extend(new_data)

        return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), "", session=message.session)

    def process_ensure_access_lateral_movement(self, message: Request, node: Node) -> Tuple[int, Response]:
        # Sanity checks - having a session here and having correct parameters
        error = ""
        if not message.session or message.session.end not in node.ips:
            error = "Could not do a lateral movement without a correct session"

        # Should we reuse the ID for a name?
        attacker_name = ""
        if "id" in message.action.parameters:
            attacker_name = message.action.parameters["id"].value

        if not attacker_name:
            error = "Name of attacker not specified"

        if error:
            return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.ERROR), error, session=message.session)

        attacker_id = attacker_name + "_" + str(Counter().get(attacker_name))
        # TODO Attacker service is currently expected to require elevated access. This has to be reasonable configurable
        attacker_service = self._configuration.service.create_active_service(attacker_name, "attacker", attacker_id, node, AccessLevel.ELEVATED)

        if not attacker_service:
            return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.ERROR),
                                                      "Could not find attacker with name {}".format(attacker_id), session=message.session)

        # Check if the permissions are ok
        if attacker_service.service_access_level > self._policy.get_access_level(message.auth):
            return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.FAILURE),
                                                      "Insufficient privileges to run attacker {}".format(attacker_id), session=message.session)

        # Currently, there is no way to instruct environment to pause on actions of new attacker instances
        self._configuration.node.add_service(node, attacker_service)

        return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.SUCCESS), node, session=message.session)

    def process_targeted_exploits_exploit_remote_services(self, message: Request, node: Node) -> Tuple[int, Response]:
        # Remote services exploitation works by abusing existing tunnels to get access to remote machines

        # Sanity checks
        error = ""
        if not message.dst_service:
            error = "Service for session creation not specified"
        elif not message.session or message.session.end not in [x.ip for x in node.interfaces]:
            if node.services[message.dst_service].passive_service.local:
                error = "Trying to access local service without a session to the node"
            else:
                error = "Could not do a remote service exploit without a correct session"
        elif not message.action.exploit:
            error = "No exploit provided for remote service exploitation"

        if error:
            return 1, self._messaging.create_response(message, Status(StatusOrigin.NODE, StatusValue.ERROR), error,
                                                      session=message.session, auth=message.auth)

        result, error = self._exploit_store.evaluate_exploit(message.action.exploit, message, node)

        if not result:
            return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.FAILURE), error,
                                                      session=message.session, auth=message.auth)

        result_sessions = []
        for s in self._configuration.service.sessions(node.services[message.dst_service].passive_service):
            # Do not allow cycles
            if message.session.end != s.end:
                new_session = self._configuration.network.append_session(message.session, s)
                result_sessions.append(new_session)

        return 1, self._messaging.create_response(message, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), result_sessions,
                                                  session=message.session, auth=message.auth)


def create_aif_interpreter(configuration: EnvironmentConfiguration, resources: EnvironmentResources,
                           policy: EnvironmentPolicy, messaging: EnvironmentMessaging) -> ActionInterpreter:
    interpreter = AIFInterpreter(configuration, resources, policy, messaging)
    return interpreter


action_interpreter_description = ActionInterpreterDescription(
    "aif",
    "Interpreter for action in the Adversary-Intent Framework",
    create_aif_interpreter
)
