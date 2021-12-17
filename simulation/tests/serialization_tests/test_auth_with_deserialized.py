import unittest

from cyst.api.configuration import *
from cyst.api.environment.control import EnvironmentState
from cyst.api.environment.environment import Environment
from cyst.api.environment.message import Status, StatusOrigin, StatusValue, StatusDetail
from cyst.api.host.service import Service

from cyst.api.logic.access import AuthenticationProviderType, AuthenticationTokenType, AuthenticationTokenSecurity, \
    AuthenticationProvider, AuthenticationTarget, Authorization
from cyst.api.logic.action import ActionParameterType, ActionParameter
from cyst.core.logic.access import AuthenticationProviderImpl, AuthenticationTokenImpl
from cyst.services.scripted_attacker.main import ScriptedAttackerControl

from tools.serde_engines.configuration_serializer_engine import serialize_toml
from tools.serde_engines.configuration_deserializer_engine import deserialize_toml


"""Environment configuration"""
local_password_auth = AuthenticationProviderConfig \
        (
        provider_type=AuthenticationProviderType.LOCAL,
        token_type=AuthenticationTokenType.PASSWORD,
        token_security=AuthenticationTokenSecurity.SEALED,
        timeout=30
    )

remote_email_auth = AuthenticationProviderConfig \
        (
        provider_type=AuthenticationProviderType.REMOTE,
        token_type=AuthenticationTokenType.PASSWORD,
        token_security=AuthenticationTokenSecurity.SEALED,
        ip=IPAddress("192.168.0.2"),
        timeout=60
    )

proxy_sso = AuthenticationProviderConfig \
        (
        provider_type=AuthenticationProviderType.PROXY,
        token_type=AuthenticationTokenType.PASSWORD,
        token_security=AuthenticationTokenSecurity.SEALED,
        ip=IPAddress("192.168.0.3"),
        timeout=30
    )

# authentication_providers = [local_password_auth, remote_email_auth, proxy_sso]

ssh_service = PassiveServiceConfig(
    type="ssh",
    owner="ssh",
    version="5.1.4",
    local=False,
    access_level=AccessLevel.LIMITED,
    authentication_providers=[local_password_auth("ssh_service_local_auth_id")],
    access_schemes=[AccessSchemeConfig(
        authentication_providers=["ssh_service_local_auth_id"],
        authorization_domain=AuthorizationDomainConfig(
            type=AuthorizationDomainType.LOCAL,
            authorizations=[
                AuthorizationConfig("user1", AccessLevel.LIMITED),
                AuthorizationConfig("user2", AccessLevel.LIMITED),
                AuthorizationConfig("root", AccessLevel.ELEVATED)
            ]
        )
    )]
)

email_srv = PassiveServiceConfig(
    type="email_srv",
    owner="email",
    version="3.3.3",
    local=False,
    access_level=AccessLevel.LIMITED,
    authentication_providers=[remote_email_auth]
)

my_custom_service = PassiveServiceConfig(
    type="my_custom_service",
    owner="custom",
    version="1.0.0",
    local=True,
    access_level=AccessLevel.LIMITED,
    authentication_providers=[local_password_auth("my_custom_service_auth_id")],
    access_schemes=[
        AccessSchemeConfig(
            authentication_providers=["my_custom_service_auth_id", remote_email_auth.id],
            authorization_domain=AuthorizationDomainConfig(
                type=AuthorizationDomainType.LOCAL,
                authorizations=[
                    AuthorizationConfig("user1", AccessLevel.LIMITED),
                    AuthorizationConfig("user2", AccessLevel.LIMITED),
                    AuthorizationConfig("root", AccessLevel.ELEVATED)
                ]
            )
        )
    ]
)

my_sso_domain = AuthorizationDomainConfig(
    type=AuthorizationDomainType.FEDERATED,
    authorizations=[
        FederatedAuthorizationConfig(
            "user1", AccessLevel.LIMITED, ["node1", "node2"], ["lighttpd"]
        )
    ],
    id="my_sso_domain"
)

sso_service = PassiveServiceConfig(
    type="sso_service",
    owner="sso",
    version="1.2.3",
    local=False,
    access_level=AccessLevel.LIMITED,
    authentication_providers=[proxy_sso]
)

web_server = PassiveServiceConfig(
    type="lighttpd",
    owner="lighttpd",
    version="8.1.4",
    local=False,
    access_level=AccessLevel.LIMITED,
    authentication_providers=[],
    access_schemes=[
        AccessSchemeConfig(
            authentication_providers=[proxy_sso.id],
            authorization_domain=my_sso_domain
        )
    ]
)

email_server = NodeConfig(id="email_server_node", active_services=[], passive_services=[email_srv], shell="bash",
                          interfaces=[InterfaceConfig(IPAddress("192.168.0.2"), IPNetwork("192.168.0.1/24"))])
sso_server = NodeConfig(id="sso_server_node", active_services=[], passive_services=[sso_service], shell="bash",
                        interfaces=[InterfaceConfig(IPAddress("192.168.0.3"), IPNetwork("192.168.0.1/24"))])
target = NodeConfig(id="target_node", active_services=[], passive_services=[ssh_service, my_custom_service, web_server],
                    shell="bash", interfaces=[InterfaceConfig(IPAddress("192.168.0.4"), IPNetwork("192.168.0.1/24"))])

router1 = RouterConfig(
    interfaces=[
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=0),
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=1),
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=2),
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=3)
    ],
    id="router1"
)

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

connections = [
    ConnectionConfig("attacker_node", 0, "router1", 0),
    ConnectionConfig("target_node", 0, "router1", 1),
    ConnectionConfig("sso_server_node", 0, "router1", 2),
    ConnectionConfig("email_server_node", 0, "router1", 3)
]


class SerializeTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        with open("./for_use.toml", "w") as f:
            serialize_toml(f, email_server, sso_server, target, router1, attacker1, *connections)

        cls._back = []
        with open("./for_use.toml", "r") as f:
            cls._back = deserialize_toml(f)

            #  create environment from config
            cls._env = Environment.create().configure(*cls._back)

            # due to the fact that we don't yet have the exploits/means to extract tokens from providers,
            # get the tokens directly
            provider = cls._env.configuration.general.get_object_by_id("ssh_service_local_auth_id",
                                                                       AuthenticationProvider)
            ssh_token = None
            if isinstance(provider, AuthenticationProviderImpl):
                ssh_token = next(iter(provider._tokens))

            provider = cls._env.configuration.general.get_object_by_id("my_custom_service_auth_id",
                                                                       AuthenticationProvider)
            custom_token = None
            if isinstance(provider, AuthenticationProviderImpl):
                custom_token = next(iter(provider._tokens))

            assert None not in [ssh_token, custom_token]

            cls._ssh_token = ssh_token
            cls._custom_token = custom_token

            # init the environment
            cls._env.control.init()

            cls._actions = {}

            _action_list = cls._env.resources.action_store.get_prefixed("meta")
            for action in _action_list:
                cls._actions[action.id] = action.copy()

            _action_list = cls._env.resources.action_store.get_prefixed("aif")
            for action in _action_list:
                cls._actions[action.id] = action.copy()

            # create attacker
            attacker_service = cls._env.configuration.general.get_object_by_id("attacker_service", Service)
            assert attacker_service is not None
            cls._attacker: ScriptedAttackerControl = cls._env.configuration.service.get_service_interface(
                attacker_service.active_service, ScriptedAttackerControl)

            cls._env.control.add_pause_on_response("attacker_node.scripted_attacker")

    def test_000_no_token_provided(self):

        action = self._actions["meta:authenticate"].copy()

        self.assertIsNotNone(action, "Authentication action unavailable")

        self._attacker.execute_action(
            "192.168.0.2",
            "email_srv",
            action,
            auth=None
        )

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((True, EnvironmentState.PAUSED), (result, state), "Task run failed.")
        self.assertEqual(message.status, Status(StatusOrigin.SERVICE,
                                                StatusValue.FAILURE,
                                                StatusDetail.AUTHENTICATION_NOT_PROVIDED),
                         "Bad state")
        self.assertEqual(message.content, "No auth token provided", "Bad error message")

    def test_001_bad_service(self):

        action = self._actions["meta:authenticate"].copy()

        self.assertIsNotNone(action, "Authentication action unavailable")

        self._attacker.execute_action(
            "192.168.0.2",
            "ssh",
            action
        )

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((True, EnvironmentState.PAUSED), (result, state), "Task run failed.")

        # Seemingly the node-service combination ischecked before the process
        # self.assertEqual(message.status, Status(StatusOrigin.SERVICE,
        #                                       StatusValue.FAILURE,
        #                                      StatusDetail.AUTHENTICATION_NOT_PROVIDED),
        #              "Authenticated when shouldnt")
        # self.assertEqual(message.content, "Service does not exist on this node", "Bad error message")

    def test_002_wrong_token(self):

        action = self._actions["meta:authenticate"].copy()

        self.assertIsNotNone(action, "Authentication action unavailable")
        action.parameters["auth_token"].value = AuthenticationTokenImpl(
                                                  AuthenticationTokenType.PASSWORD,
                                                  AuthenticationTokenSecurity.OPEN,
                                                  identity="user1",
                                                  is_local=True
                                              )

        self._attacker.execute_action(
            "192.168.0.4",
            "ssh",
            action,
        )

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((True, EnvironmentState.PAUSED), (result, state), "Task run failed.")

        self.assertEqual(message.status, Status(StatusOrigin.SERVICE,
                                                StatusValue.FAILURE,
                                                StatusDetail.AUTHENTICATION_NOT_APPLICABLE),
                         "Bad state")
        self.assertEqual(message.content, "Token invalid for this service", "Bad error message")

    def test_003_good_token_get_auth(self):

        action = self._actions["meta:authenticate"].copy()
        self.assertIsNotNone(action, "Authentication action unavailable")
        action.parameters["auth_token"].value = self._ssh_token

        self._attacker.execute_action(
            "192.168.0.4",
            "ssh",
            action,
        )

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((True, EnvironmentState.PAUSED), (result, state), "Task run failed.")

        self.assertEqual(message.status, Status(StatusOrigin.SERVICE,
                                                StatusValue.SUCCESS),
                         "Bad state")
        self.assertIsInstance(message.auth, Authorization, "Bad object type")
        self.assertEqual(message.auth.identity, self._ssh_token.identity, "Bad identity")
        self.assertEqual(message.content, "Authorized", "Bad error message")

    def test_004_good_token_get_next_target(self):

        action = self._actions["meta:authenticate"].copy()
        self.assertIsNotNone(action, "Authentication action unavailable")
        action.parameters["auth_token"].value = self._custom_token

        self._attacker.execute_action(
            "192.168.0.4",
            "my_custom_service",
            action,
        )

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((True, EnvironmentState.PAUSED), (result, state), "Task run failed.")

        self.assertEqual(message.status, Status(StatusOrigin.SERVICE,
                                                StatusValue.FAILURE,
                                                StatusDetail.AUTHENTICATION_NEXT),
                         "Bad state")
        self.assertIsInstance(message.auth, AuthenticationTarget, "Bad object type")
        self.assertEqual(message.auth.address, remote_email_auth.ip, "Bad target address")
        self.assertEqual(message.content, "Continue with next factor", "Bad error message")

    def test_005_auto_authentication_bad_token(self):

        action = self._actions["aif:ensure_access:command_and_control"].copy()
        self.assertIsNotNone(action, "Action unavailable")

        self._attacker.execute_action(
            "192.168.0.4",
            "ssh",
            action,
            auth=AuthenticationTokenImpl(
                AuthenticationTokenType.PASSWORD,
                AuthenticationTokenSecurity.OPEN,
                identity="user1",
                is_local=True
            )

        )

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((True, EnvironmentState.PAUSED), (result, state), "Task run failed.")

        self.assertEqual(message.status, Status(StatusOrigin.SERVICE,
                                                StatusValue.FAILURE,
                                                StatusDetail.AUTHENTICATION_NOT_APPLICABLE),
                         "Bad state")
        self.assertEqual(message.content, "Token invalid for this service", "Bad error message")

    def test_006_auto_authentication_good_token(self):

        action = self._actions["aif:ensure_access:command_and_control"].copy()
        self.assertIsNotNone(action, "Action unavailable")

        self._attacker.execute_action(
            "192.168.0.4",
            "ssh",
            action,
            auth=self._ssh_token
        )

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((True, EnvironmentState.PAUSED), (result, state), "Task run failed.")
        self.assertIsInstance(message.auth, Authorization, "AuthenticationToken was not swapped for authorization")
        self.assertEqual(message.content, "Service ssh at node 192.168.0.4 does not enable session creation.",
                         "bad description")

    def test_007_auto_good_token_more_factors_remaining(self):

        action = self._actions["aif:ensure_access:command_and_control"].copy()
        self.assertIsNotNone(action, "Action unavailable")

        self._attacker.execute_action(
            "192.168.0.4",
            "my_custom_service",
            action,
            auth=self._custom_token
        )

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((True, EnvironmentState.PAUSED), (result, state), "Task run failed.")

        self.assertEqual(message.status, Status(StatusOrigin.SERVICE,
                                                StatusValue.FAILURE,
                                                StatusDetail.AUTHENTICATION_NEXT),
                         "Bad state")
        self.assertIsInstance(message.auth, AuthenticationTarget, "Bad object type")
        self.assertEqual(message.auth.address, remote_email_auth.ip, "Bad target address")
        self.assertEqual(message.content, "Continue with next factor", "Bad error message")

    def test_008_auto_authentication_non_local_token(self):

        action = self._actions["aif:ensure_access:command_and_control"].copy()
        self.assertIsNotNone(action, "Action unavailable")

        self._attacker.execute_action(
            "192.168.0.4",
            "ssh",
            action,
            auth=AuthenticationTokenImpl(
                AuthenticationTokenType.PASSWORD,
                AuthenticationTokenSecurity.OPEN,
                identity="user1",
                is_local=False
            )

        )

        result, state = self._env.control.run()
        message = self._attacker.get_last_response()

        self.assertEqual((True, EnvironmentState.PAUSED), (result, state), "Task run failed.")

        self.assertEqual(message.status, Status(StatusOrigin.SERVICE,
                                                StatusValue.FAILURE,
                                                StatusDetail.AUTHENTICATION_NOT_APPLICABLE),
                         "Bad state")
        self.assertEqual(message.content, "Auto-authentication does not work with non-local tokens",
                         "Bad error message")

