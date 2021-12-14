import argparse
import importlib
import uuid
import os
import time

from heapq import heappush, heappop
from itertools import product
from time import struct_time, localtime
from typing import Tuple, List, Union, Optional, Any, Dict, Type
from uuid import uuid4
import copy

from netaddr import IPAddress, IPNetwork

from cyst.api.environment.environment import Environment
from cyst.api.environment.clock import Clock
from cyst.api.environment.control import EnvironmentState, EnvironmentControl
from cyst.api.environment.configuration import EnvironmentConfiguration, GeneralConfiguration, NodeConfiguration, \
    ServiceConfiguration, NetworkConfiguration, ServiceParameter, ExploitConfiguration, ActiveServiceInterfaceType, \
    AccessConfiguration, ActionConfiguration
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.metadata_provider import MetadataProvider, MetadataProviderDescription
from cyst.api.environment.policy import EnvironmentPolicy
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.environment.message import Message, MessageType, Request, StatusValue, StatusOrigin, Status, Response, \
    StatusDetail, Timeout
from cyst.api.environment.interpreter import ActionInterpreterDescription
from cyst.api.environment.stores import ActionStore, ExploitStore
from cyst.api.environment.stats import Statistics
from cyst.api.network.elements import Interface, Route
from cyst.api.network.node import Node
from cyst.api.logic.metadata import Metadata
from cyst.api.logic.access import Authorization, AccessLevel, AuthenticationToken, AuthenticationProvider, \
    AuthenticationTokenSecurity, AuthenticationTokenType, AuthenticationProviderType, AccessScheme, AuthenticationTarget
from cyst.api.logic.action import Action, ActionParameter, ActionParameterType, ActionParameterDomain
from cyst.api.logic.data import Data
from cyst.api.logic.exploit import VulnerableService, ExploitParameter, ExploitParameterType, ExploitLocality, \
    ExploitCategory, Exploit
from cyst.api.network.session import Session
from cyst.api.network.firewall import FirewallRule, FirewallPolicy
from cyst.api.host.service import ActiveServiceDescription, Service, PassiveService, ActiveService
from cyst.api.configuration.configuration import ConfigItem

from cyst.core.environment.configuration import Configuration, ConfigItemCloner, RuntimeConfiguration
from cyst.core.environment.data_store import DataStore
from cyst.core.environment.message import MessageImpl, RequestImpl, ResponseImpl, TimeoutImpl
from cyst.core.environment.proxy import EnvironmentProxy
from cyst.core.environment.stores import ActionStoreImpl, ServiceStoreImpl, ExploitStoreImpl
from cyst.core.environment.stats import StatisticsImpl
from cyst.core.host.service import ServiceImpl, PassiveServiceImpl
from cyst.core.logic.action import ActionParameterDomainImpl
from cyst.core.logic.access import AuthenticationTokenImpl, AuthenticationProviderImpl, AuthorizationImpl, \
    AccessSchemeImpl, AuthenticationTargetImpl
from cyst.core.logic.policy import Policy
from cyst.core.logic.data import DataImpl
from cyst.core.logic.exploit import VulnerableServiceImpl, ExploitImpl, ExploitParameterImpl
from cyst.core.network.elements import Endpoint, Connection, InterfaceImpl, Hop
from cyst.core.network.firewall import service_description as firewall_service_description
from cyst.core.network.network import Network
from cyst.core.network.node import NodeImpl
from cyst.core.network.router import Router
from cyst.core.network.session import SessionImpl
from cyst.api.utils.counter import Counter
from cyst.core.utils.file import root_dir


# Environment is unlike other core implementation given an underscore-prefixed name to let python complain about
# it being private if instantiated otherwise than via the create_environment()
class _Environment(Environment, EnvironmentControl, EnvironmentMessaging, EnvironmentResources, EnvironmentConfiguration,
                   NodeConfiguration, NetworkConfiguration, ServiceConfiguration, ExploitConfiguration, ActionConfiguration,
                   Clock, AccessConfiguration):

    def __init__(self) -> None:
        self._network = Network()
        self._time = 0
        self._start_time = localtime()
        self._tasks = []
        self._pause = False
        self._terminate = False
        self._initialized = False
        self._state = EnvironmentState.INIT

        self._run_id = ""

        self._pause_on_request = []
        self._pause_on_response = []

        self._action_store = ActionStoreImpl()
        self._service_store = ServiceStoreImpl(self.messaging, self.resources)
        self._exploit_store = ExploitStoreImpl()

        self._interpreters = {}
        # TODO currently, there can be only on metadata provider for one namespace
        self._metadata_providers: Dict[str, MetadataProvider] = {}

        self._policy = Policy(self)

        self._sessions_to_add = []

        self._register_services()
        self._register_actions()
        self._register_metadata_providers()

        self._configuration = Configuration(self)
        self._runtime_configuration = RuntimeConfiguration()
        self._configure_runtime()

        self._data_store = DataStore(self._runtime_configuration.data_backend, self._runtime_configuration.data_backend_params)

        self._statistics = StatisticsImpl()

    # Runtime parameters can be passed via command-line, configuration file, or through environment variables
    # In case of multiple definitions of one parameter, the order is, from the most important to least:
    #                                                            command line, configuration file, environment variables
    def _configure_runtime(self) -> None:
        # Environment
        data_backend = os.environ.get('CYST_DATA_BACKEND')
        data_backend_params = []
        if data_backend:
            data_backend_params_serialized = os.environ.get('CYST_DATA_BACKEND_PARAMS')
            # we expect parameters to be given in the form "param1_name","param1_value","param2_name","param2_value",...
            if data_backend_params_serialized:
                data_backend_params = dict(tuple(x) for x in data_backend_params_serialized.split(',').islice(2))
        run_id = os.environ.get('CYST_RUN_ID')
        config_id = os.environ.get('CYST_CONFIG_ID')
        config_filename = os.environ.get('CYST_CONFIG_FILENAME')

        # Command line (only parsing)
        cmdline_parser = argparse.ArgumentParser(description="CYST runtime configuration")

        cmdline_parser.add_argument("-c", "--config_file", type=str, help="Path to a file storing the configuration. Commandline overrides the items in configuration file.")
        cmdline_parser.add_argument("-b", "--data_backend", type=str, help="The type of a backend to use. Currently supported are: REDIS")
        cmdline_parser.add_argument("-p", "--data_backend_parameter", action="append", nargs=2, type=str, metavar=('NAME', 'VALUE'), help="Parameters to be passed to data backend.")
        cmdline_parser.add_argument("-r", "--run_id", type=str, help="A unique identifier of a simulation run. If not specified, a UUID will be generated instead.")
        cmdline_parser.add_argument("-i", "--config_id", type=str, help="A unique identifier of simulation run configuration, which can be obtained from the data store.")

        args = cmdline_parser.parse_args()
        if args.config_file:
            config_filename = args.config_file

        # --------------------------------------------------------------------------------------------------------------
        # Config file TODO
        if config_filename:
            pass
        # --------------------------------------------------------------------------------------------------------------

        # Command line argument override
        if args.data_backend:
            data_backend = args.data_backend

        if args.data_backend_parameter:
            # Convert from list of lists into a list of tuples
            data_backend_params = dict(tuple(x) for x in args.data_backend_parameter)

        if args.run_id:
            run_id = args.run_id

        if args.config_id:
            config_id = args.config_id

        # --------------------------------------------------------------------------------------------------------------
        if data_backend:  # Fuck, I miss oneliners
            self._runtime_configuration.data_backend = data_backend
        if data_backend_params:
            self._runtime_configuration.data_backend_params = data_backend_params
        if config_filename:
            self._runtime_configuration.config_filename = config_filename
        if run_id:
            self._runtime_configuration.run_id = run_id
        if config_id:
            self._runtime_configuration.config_id = config_id

    # ------------------------------------------------------------------------------------------------------------------
    # Environment. Currently everything points back to self
    @property
    def configuration(self) -> EnvironmentConfiguration:
        return self

    @property
    def control(self) -> EnvironmentControl:
        return self

    @property
    def messaging(self) -> EnvironmentMessaging:
        return self

    @property
    def resources(self) -> EnvironmentResources:
        return self

    @property
    def policy(self) -> EnvironmentPolicy:
        return self._policy

    def configure(self, *config_item: ConfigItem) -> Environment:
        return self._configuration.configure(*[copy.deepcopy(x) for x in config_item])

    # ------------------------------------------------------------------------------------------------------------------
    # EnvironmentMessaging
    def create_request(self, dst_ip: Union[str, IPAddress], dst_service: str = "",
                       action: Action = None, session: Session = None,
                       auth: Optional[Union[Authorization, AuthenticationToken]] = None) -> Request:
        request = RequestImpl(dst_ip, dst_service, action, session, auth)
        return request

    def create_response(self, request: Request, status: Status, content: Optional[Any] = None,
                        session: Optional[Session] = None,
                        auth: Optional[Union[Authorization, AuthenticationTarget]] = None) -> Response:
        # Let's abuse the duck typing and "cast" Request to RequestImpl
        if isinstance(request, RequestImpl):
            response = ResponseImpl(request, status, content, session, auth)
            return response
        else:
            raise ValueError("Malformed request passed to create a response from")

    def send_message(self, message: MessageImpl, delay: int = 0) -> None:
        # set a first hop for a message
        source = self._network.get_node_by_id(message.origin.id)
        # Find a next hop for messages without one
        if source and not message.next_hop:
            # New request with session should follow the session first
            # Response should either follow newly established session, or route to session endpoint
            # TODO rearrange it to reflect changes in response set_next_hop handling
            if message.type == MessageType.REQUEST and message.session:
                message.set_next_hop()
                # Not a pretty thing, but I am not sure how to make it better
                # it = SessionImpl.cast_from(message.session).forward_iterator
                # hop = next(it)
                # port = hop.src.port
                # iface = source.interfaces[port]

                # If this works it is a proof that the entire routing must be reviewed
                message.set_src_ip(message.path[0].src.ip)
            elif message.type == MessageType.RESPONSE:
                if message.session and message.current == SessionImpl.cast_from(message.session).endpoint:
                    # This is stupid, but it complains...
                    if isinstance(message, ResponseImpl):
                        message.set_in_session(True)
                message.set_next_hop()
            # Others go to a gateway
            else:
                target = message.dst_ip
                localhost = IPAddress("127.0.0.1")

                # Shortcut for localhost request
                if target == localhost:
                    message.set_src_ip(localhost)
                    message.set_next_hop(Endpoint(message.origin.id, 0, localhost), Endpoint(message.origin.id, 0, localhost))

                else:
                    gateway, port = source.gateway(target)
                    if not gateway:
                        raise Exception("Could not send a message, no gateway to route it through.")

                    iface = InterfaceImpl.cast_from(source.interfaces[port])
                    message.set_src_ip(iface.ip)

                    message.set_origin(Endpoint(source.id, port, iface.ip))

                    # First sending is specific, because the current value is set to origin
                    message.set_next_hop(message.origin, iface.endpoint)

        # metadata are appended only for requests ATM. This is to test waters, as there are many different design
        # holes and things which need clarification
        if isinstance(message, Request) and not message.metadata:
            action = message.action

            if action.namespace in self._metadata_providers:
                provider = self._metadata_providers[action.namespace]
                if provider:
                    metadata = provider.get_metadata(action)
                else:
                    metadata = Metadata()

                metadata.dst_ip = message.dst_ip
                metadata.dst_service = message.dst_service
                metadata.src_ip = message.src_ip
            else:
                metadata = Metadata()

            message.set_metadata(metadata)

        try:
            heappush(self._tasks, (self._time + delay, message))
        except Exception as e:
            print("Error sending a message, reason: {}".format(e))

        message.sent = True

        print("Sending a message: " + str(message))

        if message.origin.id in self._pause_on_request:
            self._pause = True

    # ------------------------------------------------------------------------------------------------------------------
    # EnvironmentControl
    @property
    def state(self):
        return self._state

    def reset(self, run_id: str = str(uuid.uuid4())) -> Tuple[bool, EnvironmentState]:
        if self._state != EnvironmentState.FINISHED and self._state != EnvironmentState.TERMINATED:
            return False, self._state

        self._network.reset()
        self._time = 0
        self._start_time = localtime()
        self._tasks.clear()
        self._pause = False
        self._terminate = False
        self._run_id = run_id
        self._state = EnvironmentState.INIT

        return True, self._state

    def _establish_sessions(self) -> None:
        for session in self._sessions_to_add:
            owner = session[0]
            waypoints = session[1]
            parent = session[2]
            service = session[3]
            reverse = session[4]

            # It is a questionable thing to create a deferred session and not to pass it to anyone, but in case it
            # is used/needed later, I will create it anyway
            session = self._create_session(owner, waypoints, parent, reverse)
            if service:
                node: Node
                if isinstance(waypoints[0], str):
                    node = self._network.get_node_by_id(waypoints[0])
                else:
                    node = waypoints[0]
                ServiceImpl.cast_from(node.services[service]).add_session(session)

    def init(self, run_id: str = str(uuid.uuid4())) -> Tuple[bool, EnvironmentState]:
        if self._initialized:
            return True, self._state

        if self._state == EnvironmentState.RUNNING or self._state == EnvironmentState.PAUSED:
            return False, self._state

        self._pause = False
        self._terminate = False
        self._run_id = run_id
        self._state = EnvironmentState.INIT

        self._establish_sessions()

        # Set basic statistics
        self._statistics.run_id = self._runtime_configuration.run_id if self._runtime_configuration.run_id else self._run_id
        self._statistics.configuration_id = self._runtime_configuration.config_id
        self._statistics.start_time_real = time.time()

        self._initialized = True

        return True, self._state

    def run(self) -> Tuple[bool, EnvironmentState]:

        if not self._initialized:
            return False, self._state

        # if paused, unpause
        if self._state == EnvironmentState.PAUSED:
            self._pause = False

        # if this is the first run() after init, call all run() methods of active services
        if self._state == EnvironmentState.INIT:
            for n in self._network.get_nodes_by_type("Node"):
                for s in n.services.values():
                    if isinstance(s, ServiceImpl) and not s.passive:
                        s.active_service.run()
                for s in n.traffic_processors:
                    s.run()
        # Run
        self._state = EnvironmentState.RUNNING
        self._process()

        return True, self._state

    def pause(self) -> Tuple[bool, EnvironmentState]:

        if self._state != EnvironmentState.RUNNING:
            return False, self._state

        self._pause = True
        # This will return True + running state, but it will be returned to an actor other than the one who called
        # Environment.run() in the first place. Or I hope so...
        return True, self._state

    def terminate(self) -> Tuple[bool, EnvironmentState]:

        if self._state != EnvironmentState.RUNNING:
            return False, self._state

        self._terminate = True
        return True, self._state

    def commit(self) -> None:
        self._statistics.end_time_real = time.time()
        self._statistics.end_time_virtual = self._time

        self._data_store.set(self._run_id, self._statistics, Statistics)

    def add_pause_on_request(self, id: str) -> None:
        self._pause_on_request.append(id)

    def remove_pause_on_request(self, id: str) -> None:
        self._pause_on_request = [x for x in self._pause_on_request if x != id]

    def add_pause_on_response(self, id: str) -> None:
        self._pause_on_response.append(id)

    def remove_pause_on_response(self, id: str) -> None:
        self._pause_on_response = [x for x in self._pause_on_response if x != id]

    # ------------------------------------------------------------------------------------------------------------------
    @property
    def action_store(self) -> ActionStore:
        return self._action_store

    @property
    def exploit_store(self) -> ExploitStore:
        return self._exploit_store

    # ------------------------------------------------------------------------------------------------------------------
    # EnvironmentConfiguration
    # ------------------------------------------------------------------------------------------------------------------
    # Just point on itself
    @property
    def general(self) -> GeneralConfiguration:
        return self._configuration

    @property
    def node(self) -> NodeConfiguration:
        return self

    @property
    def service(self) -> ServiceConfiguration:
        return self

    @property
    def network(self) -> NetworkConfiguration:
        return self

    @property
    def exploit(self) -> ExploitConfiguration:
        return self

    @property
    def action(self) -> ActionConfiguration:
        return self

    @property
    def access(self) -> AccessConfiguration:
        return self

    # ------------------------------------------------------------------------------------------------------------------
    # NodeConfiguration
    def create_node(self, id: str, ip: Union[str, IPAddress] = "", mask: str = "", shell: Service = None) -> Node:
        return NodeImpl(id, "Node", ip, mask, shell)

    def create_router(self, id: str, messaging: EnvironmentMessaging) -> Node:
        return Router(id, messaging)

    def create_interface(self, ip: Union[str, IPAddress] = "", mask: str = "", index: int = 0):
        return InterfaceImpl(ip, mask, index)

    def create_route(self, net: IPNetwork, port: int, metric: int) -> Route:
        return Route(net, port, metric)

    def add_interface(self, node: Node, interface: Interface, index: int = -1) -> int:
        if node.type == "Router":
            return Router.cast_from(node).add_port(interface.ip, interface.mask, index)
        else:
            return NodeImpl.cast_from(node).add_interface(InterfaceImpl.cast_from(interface))

    def set_interface(self, interface: Interface, ip: Union[str, IPAddress] = "", mask: str = "") -> None:
        iface = InterfaceImpl.cast_from(interface)

        if ip:
            iface.set_ip(ip)

        if mask:
            iface.set_mask(mask)

    def add_service(self, node: Node, *service: Service) -> None:
        node = NodeImpl.cast_from(node)

        for srv in service:
            node.add_service(ServiceImpl.cast_from(srv))

    def add_traffic_processor(self, node: Node, processor: ActiveService) -> None:
        node = NodeImpl.cast_from(node)

        node.add_traffic_processor(processor)

    def set_shell(self, node: Node, service: Service) -> None:
        NodeImpl.cast_from(node).set_shell(service)

    def add_route(self, node: Node, *route: Route) -> None:
        if node.type != "Router":
            raise RuntimeError("Attempting to add route to non-router node")

        for r in route:
            Router.cast_from(node).add_route(r)

    def add_routing_rule(self, node: Node, rule: FirewallRule) -> None:
        if node.type != "Router":
            raise RuntimeError("Attempting to add route to non-router node")

        Router.cast_from(node).add_routing_rule(rule)

    def set_routing_policy(self, node: Node, policy: FirewallPolicy) -> None:
        if node.type != "Router":
            raise RuntimeError("Attempting to set routing policy to non-router node")

        Router.cast_from(node).set_default_routing_policy(policy)

    def list_routes(self, node: Node) -> List[Route]:
        if node.type != "Router":
            raise RuntimeError("Attempting to add route to non-router node")

        return Router.cast_from(node).list_routes()

    def set_span_port(self, node: Node, port_index: int) -> None:
        if node.type != "Router":
            raise RuntimeError("Attempting to set a span port on non-router node")

        Router.cast_from(node).set_span_port(port_index)

    # ------------------------------------------------------------------------------------------------------------------
    # ServiceConfiguration
    def create_active_service(self, id: str, owner: str, name: str, node: Node,
                              service_access_level: AccessLevel = AccessLevel.LIMITED,
                              configuration: Optional[Dict[str, Any]] = None) -> Optional[Service]:
        return self._service_store.create_active_service(id, owner, name, node, service_access_level, configuration)

    def get_service_interface(self, service: ActiveService,
                              interface_type: Type[ActiveServiceInterfaceType]) -> ActiveServiceInterfaceType:
        if isinstance(service, interface_type):
            return service
        else:
            raise RuntimeError("Given active service does not provide control interface of given type.")

    def create_passive_service(self, id: str, owner: str, version: str = "0.0.0", local: bool = False,
                               service_access_level: AccessLevel = AccessLevel.LIMITED) -> Service:
        return PassiveServiceImpl(id, owner, version, local, service_access_level)

    def update_service_version(self, service: PassiveService, version: str = "0.0.0") -> None:
        service = PassiveServiceImpl.cast_from(service)
        service.version = version

    def set_service_parameter(self, service: PassiveService, parameter: ServiceParameter, value: Any) -> None:
        service = PassiveServiceImpl.cast_from(service)
        if parameter == ServiceParameter.ENABLE_SESSION:
            service.set_enable_session(value)
        elif parameter == ServiceParameter.SESSION_ACCESS_LEVEL:
            service.set_session_access_level(value)

    def create_data(self, id: Optional[str], owner: str, description: str) -> Data:
        return DataImpl(id, owner, description)

    def public_data(self, service: PassiveService) -> List[Data]:
        return PassiveServiceImpl.cast_from(service).public_data

    def private_data(self, service: PassiveService) -> List[Data]:
        return PassiveServiceImpl.cast_from(service).private_data

    def public_authorizations(self, service: PassiveService) -> List[Authorization]:
        return PassiveServiceImpl.cast_from(service).public_authorizations

    def private_authorizations(self, service: PassiveService) -> List[Authorization]:
        return PassiveServiceImpl.cast_from(service).private_authorizations

    def sessions(self, service: PassiveService) -> List[Session]:
        return PassiveServiceImpl.cast_from(service).sessions

    def provides_auth(self, service: Service, auth_provider: AuthenticationProvider):
        if isinstance(service, PassiveService):
            return PassiveServiceImpl.cast_from(service).add_provider(auth_provider)

    def set_scheme(self, service: PassiveService, scheme: AccessScheme):
        return PassiveServiceImpl.cast_from(service).add_access_scheme(scheme)

    # ------------------------------------------------------------------------------------------------------------------
    # NetworkConfiguration
    def add_node(self, node: Node) -> None:
        self._network.add_node(NodeImpl.cast_from(node))

    def add_connection(self, source: Node, target: Node, source_port_index: int = -1, target_port_index: int = -1,
                       net: str = "", connection: Connection = None) -> Connection:
        return self._network.add_connection(NodeImpl.cast_from(source), source_port_index, NodeImpl.cast_from(target),
                                            target_port_index, net, connection)

    # TODO: Decide if we want to have service association a part of the session creation, or if we rather leave it
    #       to service interface
    def create_session(self, owner: str, waypoints: List[Union[str, Node]], parent: Optional[Session] = None,
                       defer: bool = False, service: Optional[str] = None, reverse: bool = False) -> Optional[Session]:

        if defer:
            self._sessions_to_add.append((owner, waypoints, parent, service, reverse))
            return None
        else:
            session = self._create_session(owner, waypoints, parent, reverse)
            if service:
                node: Node
                if isinstance(waypoints[0], str):
                    node = self._network.get_node_by_id(waypoints[0])
                else:
                    node = waypoints[0]
                ServiceImpl.cast_from(node.services[service]).add_session(session)
            return session

    def create_session_from_message(self, message: Message) -> Session:
        message = MessageImpl.cast_from(message)

        if message.auth:
            owner = message.auth.identity
        else:
            owner = message.dst_service
        path = message.non_session_path
        parent = message.session

        # In case someone attempts to create another session in the endpoint of already provided session, just return
        # that session instead.
        # TODO: Document this behavior
        if not path:
            return parent

        return SessionImpl(owner, parent, path, self._network)

    def append_session(self, original_session: Session, appended_session: Session) -> Session:
        original = SessionImpl.cast_from(original_session)
        appended = SessionImpl.cast_from(appended_session)

        return SessionImpl(appended.owner, original, appended.path_id)

    # ------------------------------------------------------------------------------------------------------------------
    # Exploit configuration
    def create_vulnerable_service(self, id: str, min_version: str = "0.0.0",
                                  max_version: str = "0.0.0") -> VulnerableService:
        return VulnerableServiceImpl(id, min_version, max_version)

    def create_exploit_parameter(self, exploit_type: ExploitParameterType, value: str = "",
                                 immutable: bool = False) -> ExploitParameter:
        return ExploitParameterImpl(exploit_type, value, immutable)

    def create_exploit(self, id: str = "", services: List[VulnerableService] = None, locality:
    ExploitLocality = ExploitLocality.NONE, category: ExploitCategory = ExploitCategory.NONE,
                       *parameters: ExploitParameter) -> Exploit:
        return ExploitImpl(id, services, locality, category, *parameters)

    def add_exploit(self, *exploits: Exploit) -> None:
        self._exploit_store.add_exploit(*exploits)

    def clear_exploits(self) -> None:
        self._exploit_store.clear()

    # ------------------------------------------------------------------------------------------------------------------
    # Access configuration
    def create_authentication_provider(self, provider_type: AuthenticationProviderType,
                                       token_type: AuthenticationTokenType, security: AuthenticationTokenSecurity,
                                       ip: Optional[IPAddress], timeout: int) -> AuthenticationProvider:
        return AuthenticationProviderImpl(provider_type, token_type, security, ip, timeout)

    def create_authentication_token(self, type: AuthenticationTokenType, security: AuthenticationTokenSecurity,
                                    identity: str, is_local: bool) -> AuthenticationToken:
        return AuthenticationTokenImpl(type, security, identity, is_local)._set_content(uuid.uuid4())
                # contetn setting is temporary until encrypted/hashed data is implemented

    def register_authentication_token(self, provider: AuthenticationProvider, token: AuthenticationToken) -> bool:
        if isinstance(provider, AuthenticationProviderImpl):
            provider.add_token(token)
            return True

        return False

    def create_and_register_authentication_token(self, provider: AuthenticationProvider, identity: str) -> Optional[AuthenticationToken]:
        if isinstance(provider, AuthenticationProviderImpl):
            token = self.create_authentication_token(provider.token_type, provider.security, identity,
                                                True if provider.type == AuthenticationProviderType.LOCAL else False)
            self.register_authentication_token(provider, token)
            return token

        return None

    def create_authorization(self, identity: str, access_level: AccessLevel, id: str, nodes: Optional[List[str]] = None,
                             services: Optional[List[str]] = None) -> Authorization:
        return AuthorizationImpl(
            identity=identity,
            access_level=access_level,
            id=id,
            nodes=nodes,
            services=services
        )

    def create_access_scheme(self) -> AccessScheme:
        scheme = AccessSchemeImpl()
        return scheme

    def add_provider_to_scheme(self, provider: AuthenticationProvider, scheme: AccessScheme):
        if isinstance(scheme, AccessSchemeImpl):
            scheme.add_provider(provider)
            return True
        return False

    def add_authorization_to_scheme(self, auth: Authorization, scheme: AccessScheme):
        if isinstance(scheme, AccessSchemeImpl):
            scheme.add_authorization(auth)
            scheme.add_identity(auth.identity)
            return True
        return False

    def assess_token(self, scheme: AccessScheme, token: AuthenticationToken) \
            -> Optional[Union[Authorization, AuthenticationTarget]]:

        for i in range(0, len(scheme.factors)):
            if scheme.factors[i][0].token_is_registered(token):
                if i == len(scheme.factors) - 1:
                    return next(filter(lambda auth: auth.identity == token.identity, scheme.authorizations), None)
                else:
                    return scheme.factors[i + 1][0].target
        return None

    def evaluate_token_for_service(self, service: Service, token: AuthenticationToken, node: Node,
                                   fallback_ip: Optional[IPAddress]) \
            -> Optional[Union[Authorization, AuthenticationTarget]]:
        # check if node has the service is in interpreter
        if isinstance(service, PassiveServiceImpl):
            for scheme in service.access_schemes:
                result = self.assess_token(scheme, token)
                if isinstance(result, Authorization):
                    return self.user_auth_create(result, service, node)
                if isinstance(result, AuthenticationTargetImpl):
                    if result.address is None:
                        result.address = fallback_ip
                    return result

        return None

    def user_auth_create(self, authorization: Authorization, service: Service, node: Node):
        if isinstance(authorization, AuthorizationImpl):
            if (authorization.nodes == ['*'] or node.id in authorization.nodes) and \
                    (authorization.services == ['*'] or service.name in authorization.services):

                ret_auth = AuthorizationImpl(
                    identity=authorization.identity,
                    nodes=[node.id],
                    services=[service.name],
                    access_level=authorization.access_level,
                    id=str(uuid4())
                )

                if isinstance(service, PassiveServiceImpl):
                    service.add_active_authorization(ret_auth)  # TODO: check if this can go to public/private auths
                return ret_auth
        return None

    # ------------------------------------------------------------------------------------------------------------------
    # Action configuration
    def create_action_parameter_domain_any(self) -> ActionParameterDomain:
        return ActionParameterDomainImpl()

    def create_action_parameter_domain_range(self, default: int, range_min: int, range_max: int, range_step: int = 1) -> ActionParameterDomain:
        return ActionParameterDomainImpl.bind_range(default, range_min, range_max, range_step)

    def create_action_parameter_domain_options(self, default: Any, options: List[Any]) -> ActionParameterDomain:
        return ActionParameterDomainImpl.bind_options(default, options)

    # ------------------------------------------------------------------------------------------------------------------
    # Clock functions
    @property
    def clock(self) -> Clock:
        return self

    def simulation_time(self) -> int:
        return self._time

    def hybrid_time(self) -> struct_time:
        # TODO this should be local time + self._time miliseconds
        return self._start_time

    def timeout(self, service: ActiveService, delay: int, content: Any) -> None:
        m = TimeoutImpl(service, self._time, delay, content)
        heappush(self._tasks, (self._time + delay, m))

    # ------------------------------------------------------------------------------------------------------------------
    # Internal functions
    @property
    def _get_network(self) -> Network:
        return self._network

    # When creating sessions from nodes, there are two options - either nodes are connected directly, or they
    # go through a router. So correct hops are evaluated either in N-R*-N form or N-N
    # TODO: If one direction fails, session should try constructing itself in reverse order and then restructure hops
    #       so that the origin is always at the first waypoint.
    def _create_session(self, owner: str, waypoints: List[Union[str, Node]], parent: Optional[Session],
                        reverse: bool) -> Session:
        path: List[Hop] = []
        source: NodeImpl
        session_reversed = False

        if len(waypoints) < 2:
            raise ValueError("The session path needs at least two ids")

        session_constructed = True
        for direction in ("forward", "reverse"):

            if direction == "reverse":
                if not session_constructed:
                    path.clear()
                    waypoints.reverse()
                    session_reversed = True
                    session_constructed = True
                else:
                    break

            i = 0
            while i < len(waypoints) - 1:
                # There was an error in partial session construction
                if not session_constructed:
                    break

                node0 = None
                node1 = None
                node2 = None

                def get_node_from_waypoint(self, i: int) -> Node:
                    if isinstance(waypoints[i], str):
                        node = self._network.get_node_by_id(waypoints[i])
                    else:
                        node = waypoints[i]
                    return node

                # Get the nodes
                node0 = get_node_from_waypoint(self, i)
                node1 = get_node_from_waypoint(self, i + 1)

                routers = []
                # N-R*-N
                if node1.type == "Router":
                    router = Router.cast_from(node1)

                    routers.append(router)
                    node2 = get_node_from_waypoint(self, i + len(routers) + 1)

                    while node2.type == "Router":
                        routers.append(Router.cast_from(node2))
                        node2 = get_node_from_waypoint(self, i + len(routers) + 1)

                    path_candidate = []
                    for elements in product(node0.interfaces, node2.interfaces):
                        node0_iface = InterfaceImpl.cast_from(elements[0])
                        node2_iface = InterfaceImpl.cast_from(elements[1])

                        path_candidate.clear()

                        # Check if the next router is connected to the first node
                        if node0_iface.endpoint.id != routers[0].id:
                            continue

                        # It is, so it's a first hop
                        path_candidate.append(
                            Hop(Endpoint(NodeImpl.cast_from(node0).id, node0_iface.index, node0_iface.ip),
                                node0_iface.endpoint))

                        # Check for every router if it routes the source and destination
                        for j, r in enumerate(routers):
                            # Find if there is a forward port
                            # Ports are returned in order of priority: local IPs, remote IPs sorted by specificity (CIDR)
                            port = r.routes(node0_iface.ip, node2_iface.ip, "*")

                            # No suitable port found, try again
                            if not port:
                                break

                            path_candidate.append(Hop(Endpoint(r.id, port.index, port.ip), port.endpoint))

                        if len(path_candidate) == len(routers) + 1:
                            path.extend(path_candidate)
                            break

                    i += len(routers) + 1

                    if len(path) < i:
                        session_constructed = False
                        break
                        # raise RuntimeError("Could not find connection between {} and {} to establish a session".format(NodeImpl.cast_from(node0).id, NodeImpl.cast_from(node2).id))
                else:
                    # N-N
                    for iface in node0.interfaces:
                        node0_iface = InterfaceImpl.cast_from(iface)

                        if node0_iface.endpoint.id == NodeImpl.cast_from(node1).id:
                            path.append(Hop(Endpoint(NodeImpl.cast_from(node0).id, node0_iface.index, node0_iface.ip),
                                            node0_iface.endpoint))
                            break

                    i += 1
                    if len(path) < i:
                        session_constructed = False
                        break
                        # raise RuntimeError("Could not find connection between {} and {} to establish a session".format(NodeImpl.cast_from(node0).id, NodeImpl.cast_from(node1).id))

        if not session_constructed:
            # Sessions are always tried to be constructed in both directions, so we need to reverse the waypoints again
            waypoints.reverse()
            raise RuntimeError(
                "Could not find connection between the following waypoints to establish a session".format(waypoints))

        # If the session was constructed from the end to front, we need to reverse the path
        if session_reversed:
            path.reverse()
            for i in range(0, len(path)):
                path[i] = path[i].swap()

        return SessionImpl(owner, parent, path, self._network)

    def _process_passive(self, message: Request, node: Node):
        time = 0
        response = None

        message = RequestImpl.cast_from(message)

        # TODO: auto-authentication here, maybe??
        if message.auth and isinstance(message.auth, AuthenticationToken):
            if not AuthenticationTokenImpl.is_local_instance(message.auth):
                return time, self.messaging.create_response(message, Status(StatusOrigin.SERVICE,
                                                                            StatusValue.FAILURE,
                                                                            StatusDetail.AUTHENTICATION_NOT_APPLICABLE),
                                                            "Auto-authentication does not work with non-local tokens",
                                                            session=message.session, auth=message.auth)
            # TODO: assess if locality check makes sense
            original_action = message.action
            auth_action = self.action_store.get("meta:authenticate").copy()
            auth_action.parameters["auth_token"].value = message.auth
            message.action = auth_action  # swap to authentication
            auth_time, auth_response = self._interpreters["meta"].evaluate(message, node)

            if auth_response.status.value == StatusValue.FAILURE:  # not authorized
                return auth_time, auth_response

            message.auth = auth_response.auth  # if authentication successful, swap auth token for authorization
            message.action = original_action   # swap back original action
        #  and continue to action

        # TODO: In light of tags abandonment, how to deal with splitting id into namespace and action name
        if message.action.namespace in self._interpreters:
            time, response = self._interpreters[message.action.namespace].evaluate(message, node)

        return time, response

    def _send_message(self, message: MessageImpl) -> None:
        message_type = "request" if isinstance(message, Request) else "response"

        # shortcut for wakeup messages
        if message.type == MessageType.TIMEOUT:
            self._network.get_node_by_id(message.origin.id).process_message(message)
            return

        # Store it into the history
        self._data_store.set(self._run_id, message, Message, self._time)

        # Move message to a next hop
        message.hop()
        current_node: NodeImpl = self._network.get_node_by_id(message.current.id)

        processing_time = 0

        if current_node.type == "Router":
            for processor in current_node.traffic_processors:
                result, delay = processor.process_message(message)
                if not result:
                    return
            result, processing_time = current_node.process_message(message)
            if result:
                heappush(self._tasks, (self._time + processing_time, message))

            return

        # Message has a session
        if message.session:
            local_processing = False
            # Message still in session, pass it along
            if message.in_session:
                message.set_next_hop()
                heappush(self._tasks, (self._time + processing_time, message))
                return
            # The session ends in the current node
            elif message.session.endpoint.id == current_node.id or message.session.startpoint.id == current_node.id:
                # TODO bi-directional session complicate the situation soooo much
                end_port = None
                if message.session.endpoint.id == current_node.id:
                    end_port = message.session.endpoint.port
                elif message.session.startpoint.id == current_node.id:
                    end_port = message.session.startpoint.port

                # Check if the node is the final destination
                for iface in current_node.interfaces:
                    if iface.index == end_port and iface.ip == message.dst_ip:
                        local_processing = True
                        break
                # It is not, this means the node was only a proxy to some other target
                if not local_processing:
                    # Find a way to nearest switch
                    gateway, port = current_node.gateway(message.dst_ip)
                    # ##################
                    dest_node_endpoint = current_node.interfaces[port].endpoint
                    dest_node = self._network.get_node_by_id(dest_node_endpoint.id)
                    dest_node_ip = dest_node.interfaces[dest_node_endpoint.port].ip
                    message.set_next_hop(Endpoint(current_node.id, port, current_node.interfaces[port].ip),
                                         Endpoint(dest_node_endpoint.id, dest_node_endpoint.port, dest_node_ip))
                    # ##################
                    print("Proxying {} to {} via {} on a node {}".format(message_type, message.dst_ip,
                                                                         message.next_hop.id, current_node.id))
                    heappush(self._tasks, (self._time + processing_time, message))
                    return

        # Message has to be processed locally
        print("Processing {} on a node {}. {}".format(message_type, current_node.id, message))

        # Before a message reaches to services within, it is evaluated by all traffic processors
        # While they are returning true, everything is ok. Once they return false, the message processing stops
        # Traffic processors are free to send any reply as they see fit
        for processor in current_node.traffic_processors:
            result, delay = processor.process_message(message)
            if not result:
                return

        # Service is requested
        response = None
        if message.dst_service:
            # Check if the requested service exists on the current node
            if message.dst_service not in current_node.services:
                # There is a theoretical chance for response not finding dst service for responses, if e.g. attacker
                # shut down the service after firing request and before receiving the response. In such case the
                # error is silently dropped
                if message_type == "response":
                    return

                processing_time = 1
                response = ResponseImpl(message, Status(StatusOrigin.NODE, StatusValue.ERROR),
                                        "Nonexistent service {} at node {}".format(message.dst_service, message.dst_ip),
                                        session=message.session, auth=message.auth)
                self.send_message(response, processing_time)

            # Service exists and it is passive
            elif current_node.services[message.dst_service].passive:
                # Passive services just discard the responses and only process the requests
                if message_type == "response":
                    return

                processing_time, response = self._process_passive(message, current_node)
                if response.status.origin == StatusOrigin.SYSTEM and response.status.value == StatusValue.ERROR:
                    print("Could not process the request, unknown semantics.")
                else:
                    self.send_message(response, processing_time)

            # Service exists and it is active
            else:
                # An active service does not necessarily produce Responses, so we should just move time
                # somehow and be done with it.
                # TODO How to move time?
                result, delay = current_node.services[message.dst_service].active_service.process_message(message)

                if message_type == "response" and current_node.id + "." + message.dst_service in self._pause_on_response:
                    self._pause = True

        # If no service is specified, it is a message to a node, but still, it is processed as a request for
        # passive service and processed with the interpreter
        # No service is specified
        else:
            # If there is response arriving without destination service, just drop it
            if message_type == "response":
                return

            # If it is a request, then it is processed as a request for passive service and processed with the interpreter
            processing_time, response = self._process_passive(message, current_node)
            if response.status.origin == StatusOrigin.SYSTEM and response.status.value == StatusValue.ERROR:
                print("Could not process the request, unknown semantics.")
            else:
                self.send_message(response, processing_time)

    def _process(self) -> Tuple[bool, EnvironmentState]:

        while self._tasks and not self._pause and not self._terminate:
            next_time = self._tasks[0][0]
            delta = next_time - self._time

            # TODO singular timestep handling
            self._time = next_time

            current_tasks: List[MessageImpl] = []
            while self._tasks and self._tasks[0][0] == self._time:
                current_tasks.append(heappop(self._tasks)[1])

            for task in current_tasks:
                if task.type == MessageType.TIMEOUT:
                    # Yay!
                    timeout = TimeoutImpl.cast_from(task.cast_to(Timeout))
                    timeout.service.process_message(task)
                else:
                    self._send_message(task)

        # Pause causes the system to stop processing and to keep task queue intact
        if self._pause:
            self._state = EnvironmentState.PAUSED

        # Terminate clears the task queue and sets the clock back to zero
        elif self._terminate:
            self._state = EnvironmentState.TERMINATED
            self._time = 0
            self._tasks.clear()

        else:
            self._state = EnvironmentState.FINISHED

        return True, self._state

    def _register_services(self) -> None:
        # Check subdirectories in the cyst/services/ directory
        path = root_dir() / 'cyst' / 'services'
        if not path.exists():
            raise RuntimeError(
                "Cannot find 'cyst/services/' path. This indicate corruption of the simulator. Please check...")

        for x in path.iterdir():
            if x.is_dir():
                # Attempt to import main of the services and get the service descriptions
                try:
                    module_name = 'cyst.services.' + x.parts[-1] + '.main'
                    module = importlib.import_module(module_name)
                    service_description: ActiveServiceDescription = getattr(module, "service_description")

                    if self._service_store.get_service(service_description.name):
                        print(
                            "Service with name {} already registered, skipping the one in 'cyst/services/{}' directory".format(
                                service_description.name, x.parts[-1]))
                    else:
                        self._service_store.add_service(service_description)
                except ModuleNotFoundError:
                    # Given service does not provide a main
                    print("Service {} does not provide the 'main.py' module".format(x.parts[-1]))
                    pass
                except AttributeError:
                    # Given service does not provide a service description
                    print("Service {} does not provide its description in the 'main.py' module".format(x.parts[-1]))
                    pass

        # Explicit addition of built-in active services
        self._service_store.add_service(firewall_service_description)

    def _register_actions(self) -> None:
        # Check subdirectories in the cyst/interpreters/ directory
        path = root_dir() / 'cyst' / 'interpreters'
        if not path.exists():
            raise RuntimeError(
                "Cannot find 'cyst/interpreters/' path. This indicate corruption of the simulator. Please check...")

        for x in path.iterdir():
            if x.is_dir():
                # Attempt to import main of the interpreters and get the action interpreter descriptions
                try:
                    module_name = 'cyst.interpreters.' + x.parts[-1] + '.main'
                    module = importlib.import_module(module_name)
                    intp_description: ActionInterpreterDescription = getattr(module, "action_interpreter_description")

                    if intp_description.namespace in self._interpreters:
                        print(
                            "Action interpreter with namespace {} already registered, skipping the one in 'cyst/interpreters/{}' directory".format(
                                intp_description.namespace, x.parts[-1]))
                    else:
                        interpreter = intp_description.creation_fn(self, self, self._policy, self)
                        self._interpreters[intp_description.namespace] = interpreter
                except ModuleNotFoundError:
                    # Given service does not provide a main
                    print("Action interpreter {} does not provide the 'main.py' module".format(x.parts[-1]))
                    pass
                except AttributeError as err:
                    # Given service does not provide a service description
                    print(
                        "Action interpreter {} does not provide its description in the 'main.py' module. Reason: {}".format(
                            x.parts[-1], err))
                    pass

    def _register_metadata_providers(self) -> None:
        # Check subdirectories in the cyst/metadata_providers/ directory
        path = root_dir() / 'cyst' / 'metadata_providers'
        if not path.exists():
            raise RuntimeError(
                "Cannot find 'cyst/metadata_providers/' path. This indicate corruption of the simulator. Please check...")

        for x in path.iterdir():
            if x.is_dir():
                # Attempt to import main of the interpreters and get the action interpreter descriptions
                try:
                    module_name = 'cyst.metadata_providers.' + x.parts[-1] + '.main'
                    module = importlib.import_module(module_name)
                    provider_description: MetadataProviderDescription = getattr(module, "metadata_provider_description")

                    if provider_description.namespace in self._metadata_providers:
                        print("Metadata provider with namespace {} already registered, skipping the one in 'cyst/metadata_providers/{}' directory".format(provider_description.namespace, x.parts[-1]))
                    else:
                        provider = provider_description.creation_fn(self.action_store, self)
                        self._metadata_providers[provider_description.namespace] = provider
                        provider.register_action_parameters()
                except ModuleNotFoundError:
                    # Given service does not provide a main
                    print("Metadata provider {} does not provide the 'main.py' module".format(x.parts[-1]))
                    pass
                except AttributeError as err:
                    # Given service does not provide a service description
                    print("Metadata provider {} does not provide its description in the 'main.py' module. Reason: {}".format(x.parts[-1], err))
                    pass

    def create_service(self, name: str, id: str, node: Node, args: Optional[Dict[str, Any]]) -> ServiceImpl:
        if name not in self._service_descriptions:
            raise AttributeError("Service '{}' not registered.".format(name))

        if not id:
            service_name = "service-" + name + "-" + str(Counter().get("services"))
        else:
            service_name = id

        proxy = EnvironmentProxy(self, NodeImpl.cast_from(node).id, service_name)

        # TODO add ownership into equation
        act = self._service_descriptions[name].creation_fn("", proxy, args)
        srv = ServiceImpl(service_name, act, name, "")

        return srv


def create_environment() -> Environment:
    e = _Environment()
    return e
