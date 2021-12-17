from abc import ABC, abstractmethod
from typing import Any, List, Optional, Union, Dict, TypeVar, Type
from netaddr import IPAddress, IPNetwork
from flags import Flags

from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.message import Message
from cyst.api.host.service import Service, PassiveService, ActiveService
from cyst.api.logic.action import ActionParameterDomain
from cyst.api.logic.access import Authorization, AccessLevel, AuthenticationTokenType, AuthenticationTokenSecurity,\
    AuthenticationToken, AuthenticationProviderType, AuthenticationProvider, AccessScheme, AuthenticationTarget
from cyst.api.logic.data import Data
from cyst.api.logic.exploit import VulnerableService, ExploitCategory, ExploitLocality, ExploitParameter, ExploitParameterType, Exploit
from cyst.api.network.elements import Connection, Interface, Route
from cyst.api.network.firewall import FirewallRule, FirewallPolicy
from cyst.api.network.session import Session
from cyst.api.network.node import Node


ActiveServiceInterfaceType = TypeVar('ActiveServiceInterfaceType')
ConfigurationObjectType = TypeVar('ConfigurationObjectType')
ObjectType = TypeVar('ObjectType')


class GeneralConfiguration(ABC):
    @abstractmethod
    def get_configuration_by_id(self, id: str, configuration_type: Type[ConfigurationObjectType]) -> ConfigurationObjectType:
        pass

    @abstractmethod
    def get_object_by_id(self, id: str, object_type: Type[ObjectType]) -> ObjectType:
        pass


class NodeConfiguration(ABC):
    @abstractmethod
    def create_node(self, id: str, ip: Union[str, IPAddress] = "", mask: str = "", shell: Service = None) -> Node:
        pass

    @abstractmethod
    def create_router(self, id: str, messaging: EnvironmentMessaging) -> Node:
        pass

    @abstractmethod
    def create_interface(self, ip: Union[str, IPAddress] = "", mask: str = "", index: int = 0) -> Interface:
        pass

    @abstractmethod
    def create_route(self, net: IPNetwork, port: int, metric: int) -> Route:
        pass

    @abstractmethod
    def add_interface(self, node: Node, interface: Interface, index: int = -1) -> int:
        pass

    @abstractmethod
    def set_interface(self, interface: Interface, ip: Union[str, IPAddress] = "", mask: str = "") -> None:
        pass

    @abstractmethod
    def add_service(self, node: Node, *service: Service) -> None:
        pass

    @abstractmethod
    def set_shell(self, node: Node, service: Service) -> None:
        pass

    @abstractmethod
    def add_traffic_processor(self, node: Node, processor: ActiveService) -> None:
        pass

    @abstractmethod
    def add_route(self, node: Node, *route: Route) -> None:
        pass

    # TODO: This is only temporary - first, it is leaking   implementation detail to outside and second, it is
    #       completely stupid, as router should be a designated active service and should provide configuration
    #       interface
    @abstractmethod
    def add_routing_rule(self, node: Node, rule: FirewallRule) -> None:
        pass

    @abstractmethod
    def set_routing_policy(self, node: Node, policy: FirewallPolicy) -> None:
        pass

    @abstractmethod
    def list_routes(self, node: Node) -> List[Route]:
        pass

    @abstractmethod
    def set_span_port(self, node: Node, port_index: int) -> None:
        pass


class ServiceParameter(Flags):
    ENABLE_SESSION = ()
    SESSION_ACCESS_LEVEL = ()


class ServiceConfiguration(ABC):
    @abstractmethod
    def create_active_service(self, id: str, owner: str, name: str, node: Node,
                              service_access_level: AccessLevel = AccessLevel.LIMITED,
                              configuration: Optional[Dict[str, Any]] = None) -> Optional[Service]:
        pass

    @abstractmethod
    def get_service_interface(self, service: ActiveService, control_interface_type: Type[ActiveServiceInterfaceType]) -> ActiveServiceInterfaceType:
        pass

    @abstractmethod
    def create_passive_service(self, id: str, owner: str, version: str = "0.0.0", local: bool = False,
                               service_access_level: AccessLevel = AccessLevel.LIMITED) -> Service:
        pass

    @abstractmethod
    def update_service_version(self, service: PassiveService, version: str = "0.0.0") -> None:
        pass

    @abstractmethod
    def set_service_parameter(self, service: PassiveService, parameter: ServiceParameter, value: Any) -> None:
        pass

    @abstractmethod
    def create_data(self, id: Optional[str], owner: str, description: str) -> Data:
        pass

    @abstractmethod
    def public_data(self, service: PassiveService) -> List[Data]:
        pass

    @abstractmethod
    def private_data(self, service: PassiveService) -> List[Data]:
        pass

    @abstractmethod
    def public_authorizations(self, service: PassiveService) -> List[Authorization]:
        pass

    @abstractmethod
    def private_authorizations(self, service: PassiveService) -> List[Authorization]:
        pass

    @abstractmethod
    def sessions(self, service: PassiveService) -> List[Session]:
        pass

    @abstractmethod
    def provides_auth(self, service: Service, auth_provider: AuthenticationProvider):
        pass

    @abstractmethod
    def set_scheme(self, service: PassiveService, scheme: AccessScheme):
        pass


class NetworkConfiguration(ABC):
    @abstractmethod
    def add_node(self, node: Node) -> None:
        pass

    @abstractmethod
    def add_connection(self, source: Node, target: Node, source_port_index: int = -1, target_port_index: int = -1,
                       net: str = "", connection: Connection = None) -> Connection:
        pass

    @abstractmethod
    def create_session(self, owner: str, waypoints: List[Union[str, Node]], parent: Optional[Session] = None,
                       defer: bool = False, service: Optional[str] = None, reverse: bool = False) -> Optional[Session]:
        pass

    @abstractmethod
    def append_session(self, original_session: Session, appended_session: Session) -> Session:
        pass

    @abstractmethod
    def create_session_from_message(self, message: Message) -> Session:
        pass


class ExploitConfiguration(ABC):
    @abstractmethod
    def create_vulnerable_service(self, id: str, min_version: str = "0.0.0", max_version: str = "0.0.0") -> VulnerableService:
        pass

    @abstractmethod
    def create_exploit_parameter(self, exploit_type: ExploitParameterType, value: str = "", immutable: bool = False) -> ExploitParameter:
        pass

    @abstractmethod
    def create_exploit(self, id: str = "", services: List[VulnerableService] = None, locality:
                       ExploitLocality = ExploitLocality.NONE, category: ExploitCategory = ExploitCategory.NONE,
                       *parameters: ExploitParameter) -> Exploit:
        pass

    @abstractmethod
    def add_exploit(self, *exploits: Exploit) -> None:
        pass

    @abstractmethod
    def clear_exploits(self) -> None:
        pass


class ActionConfiguration(ABC):
    @abstractmethod
    def create_action_parameter_domain_any(self) -> ActionParameterDomain:
        pass

    @abstractmethod
    def create_action_parameter_domain_range(self, default: int, min: int, max: int, step: int = 1) -> ActionParameterDomain:
        pass

    @abstractmethod
    def create_action_parameter_domain_options(self, default: Any, options: List[Any]) -> ActionParameterDomain:
        pass


class AccessConfiguration(ABC):

    @abstractmethod
    def create_authentication_provider(self, provider_type: AuthenticationProviderType,
                                       token_type: AuthenticationTokenType, security: AuthenticationTokenSecurity,
                                       ip: Optional[IPAddress], timeout: int) -> AuthenticationProvider:
        pass

    @abstractmethod
    def create_authentication_token(self, type: AuthenticationTokenType, security: AuthenticationTokenSecurity,
                                    identity: str, is_local: bool) -> AuthenticationToken:
        pass

    @abstractmethod
    def register_authentication_token(self, provider: AuthenticationProvider, token: AuthenticationToken) -> bool:
        pass

    @abstractmethod
    def create_and_register_authentication_token(self, provider: AuthenticationProvider, identity: str) -> Optional[AuthenticationToken]:
        pass

    @abstractmethod
    def create_authorization(self, identity: str, access_level: AccessLevel, id: str, nodes: Optional[List[str]] = None, services: Optional[List[str]] = None):
        pass

    @abstractmethod
    def create_access_scheme(self) -> AccessScheme:
        pass

    @abstractmethod
    def add_provider_to_scheme(self, provider : AuthenticationProvider, scheme: AccessScheme):
        pass

    @abstractmethod
    def add_authorization_to_scheme(self, auth: Authorization, scheme: AccessScheme):
        pass

    @abstractmethod
    def evaluate_token_for_service(self, service: Service, token: AuthenticationToken, node: Node,
                                   fallback_ip: Optional[IPAddress])\
            -> Optional[Union[Authorization, AuthenticationTarget]]:
        pass


class EnvironmentConfiguration(ABC):

    @property
    @abstractmethod
    def general(self) -> GeneralConfiguration:
        pass

    @property
    @abstractmethod
    def node(self) -> NodeConfiguration:
        pass

    @property
    @abstractmethod
    def service(self) -> ServiceConfiguration:
        pass

    @property
    @abstractmethod
    def network(self) -> NetworkConfiguration:
        pass

    @property
    @abstractmethod
    def exploit(self) -> ExploitConfiguration:
        pass

    @property
    @abstractmethod
    def action(self) -> ActionConfiguration:
        pass

    @property
    @abstractmethod
    def access(self) -> AccessConfiguration:
        pass
