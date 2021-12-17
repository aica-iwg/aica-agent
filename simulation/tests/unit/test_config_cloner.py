import unittest

from netaddr import IPAddress, IPNetwork

from cyst.api.configuration import *
from cyst.api.configuration.configuration import ConfigItemCloner
from cyst.api.environment.environment import Environment
from cyst.api.logic.access import AuthenticationProviderType, AuthenticationTokenType, AuthenticationTokenSecurity

from cyst.api.network.node import Node
from cyst.api.logic.access import AuthenticationProvider, Authorization, AuthenticationTarget
from cyst.core.logic.access import AuthenticationProviderImpl
from cyst.core.logic.access import AuthenticationTokenImpl

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


class CloneTest(unittest.TestCase):

    def test_000_basic(self):

        clone = ConfigItemCloner.clone(email_server)
        self.assertIsNot(email_server, clone, "objects are the same, not clones")
        self.assertIsNot(email_server.passive_services[0], clone.passive_services[0])


