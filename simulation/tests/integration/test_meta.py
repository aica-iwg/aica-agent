import unittest
import uuid

from netaddr import IPAddress, IPNetwork

from cyst.api.configuration import AuthenticationProviderConfig, PassiveServiceConfig, AccessSchemeConfig, \
    AuthorizationDomainConfig, AuthorizationDomainType, AuthorizationConfig, NodeConfig, InterfaceConfig, \
    ActiveServiceConfig, RouterConfig, ConnectionConfig
from cyst.api.host.service import Service
from cyst.api.logic.access import AccessLevel, AuthenticationProviderType, AuthenticationTokenType, \
    AuthenticationTokenSecurity, AuthenticationProvider, Authorization
from cyst.api.environment.environment import Environment
from cyst.api.environment.control import EnvironmentState
from cyst.api.environment.configuration import ServiceParameter
from cyst.api.environment.message import StatusOrigin, StatusValue, Status
from cyst.api.logic.action import ActionParameter, ActionParameterType
from cyst.api.network.node import Node
from cyst.api.network.session import Session
from cyst.core.logic.access import AuthenticationProviderImpl, AuthenticationTokenImpl

from cyst.services.scripted_attacker.main import ScriptedAttackerControl

local_password_auth = AuthenticationProviderConfig \
        (
        provider_type=AuthenticationProviderType.LOCAL,
        token_type=AuthenticationTokenType.PASSWORD,
        token_security=AuthenticationTokenSecurity.SEALED,
        timeout=30
    )

ssh_service = PassiveServiceConfig(
    type="openssh",
    owner="ssh",
    version="8.1.0",
    local=False,
    access_level=AccessLevel.ELEVATED,
    authentication_providers=[local_password_auth("openssh_local_auth_id")],
    access_schemes=[AccessSchemeConfig(
        authentication_providers=["openssh_local_auth_id"],
        authorization_domain=AuthorizationDomainConfig(
            type=AuthorizationDomainType.LOCAL,
            authorizations=[
                AuthorizationConfig("root", AccessLevel.ELEVATED)
            ]
        )
    )],
    parameters=[
                    (ServiceParameter.ENABLE_SESSION, True),
                    (ServiceParameter.SESSION_ACCESS_LEVEL, AccessLevel.LIMITED)
                ]
)

target1 = NodeConfig(id="target1", active_services=[], passive_services=[ssh_service],
                    shell="bash", interfaces=[InterfaceConfig(IPAddress("192.168.0.3"), IPNetwork("192.168.0.1/24"))])

attacker1 = NodeConfig(
    active_services=[
        ActiveServiceConfig(
            "scripted_attacker",
            "scripted_attacker",
            "attacker",
            AccessLevel.LIMITED,
            id="attacker_service"
        )
    ],
    passive_services=[],
    interfaces=[
        InterfaceConfig(IPAddress("192.168.0.5"), IPNetwork("192.168.0.1/24"))
    ],
    shell="",
    id="attacker_node"
)

router1 = RouterConfig(
    interfaces=[
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=0),
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=1)
    ],
    id="router1"
)

connections = [
    ConnectionConfig("attacker_node", 0, "router1", 0),
    ConnectionConfig("target1", 0, "router1", 1),
]


class TestMETAIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._env = Environment.create().configure(target1, attacker1, router1, *connections)
        cls._env.control.init()

        cls._action_list = cls._env.resources.action_store.get_prefixed("meta")
        cls._actions = {}
        for action in cls._action_list:
            cls._actions[action.id] = action

        # Many META action are tied to other action for effects, so we have to use meta and something
        cls._action_list = cls._env.resources.action_store.get_prefixed("aif")
        for action in cls._action_list:
            cls._actions[action.id] = action

        cls._env.control.add_pause_on_response("attacker_node.scripted_attacker")

        cls._target = cls._env.configuration.general.get_object_by_id("target1", Node)
        attacker_service = cls._env.configuration.general.get_object_by_id("attacker_service", Service)
        cls._attacker: ScriptedAttackerControl = cls._env.configuration.service.get_service_interface(
            attacker_service.active_service, ScriptedAttackerControl)

        provider = cls._env.configuration.general.get_object_by_id("openssh_local_auth_id",
                                                                   AuthenticationProvider)
        cls._ssh_token = AuthenticationTokenImpl(AuthenticationTokenType.PASSWORD,
                                                 AuthenticationTokenSecurity.OPEN, "root", True)._set_content(uuid.uuid4())

    def test_0000_inspect_node(self) -> None:

        # Local inspection
        self._attacker.execute_action("127.0.0.1", "", self._actions["meta:inspect:node"])

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((result, state), (True, EnvironmentState.PAUSED), "Task ran and was successfully paused.")
        self.assertEqual(message.status, Status(StatusOrigin.NODE, StatusValue.SUCCESS), "Acction was successful")
        self.assertTrue(message.content and isinstance(message.content, Node), "Received a node description back")

        # Remote inspection
        # Connect the attacker to the target
        action = self._actions["meta:authenticate"]
        action.parameters["auth_token"].value = self._ssh_token
        target = self._target.interfaces[0].ip

        self._attacker.execute_action(str(target), "openssh", action, auth=self._ssh_token)

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((result, state), (True, EnvironmentState.PAUSED), "Task ran and was successfully paused.")
        self.assertEqual(message.status, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), "Acction was successful")
        self.assertTrue(message.auth and isinstance(message.auth, Authorization), "Received a session back")

        auth = message.auth

        action = self._actions["aif:ensure_access:command_and_control"]
        target = self._target.interfaces[0].ip

        self._attacker.execute_action(str(target), "openssh", action, auth=auth)

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((result, state), (True, EnvironmentState.PAUSED), "Task ran and was successfully paused.")
        self.assertEqual(message.status, Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), "Acction was successful")
        self.assertTrue(message.session and isinstance(message.session, Session), "Received a session back")

        session = message.session
        action = self._actions["meta:inspect:node"]

        self._attacker.execute_action(str(target), "", action, session=session)

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((result, state), (True, EnvironmentState.PAUSED), "Task ran and was successfully paused.")
        self.assertEqual(message.status, Status(StatusOrigin.NODE, StatusValue.SUCCESS), "Acction was successful")
        self.assertTrue(message.content and isinstance(message.content, Node), "Received a node back")

        node: Node = message.content
        self.assertEqual(IPAddress("192.168.0.3"), node.interfaces[0].ip, "Got correct IP address back")
