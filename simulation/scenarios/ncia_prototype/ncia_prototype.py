import unittest

from pathlib import Path

from cyst.api.configuration import *
from cyst.api.environment.environment import Environment
from cyst.api.environment.message import Message
from cyst.api.network.node import Node
from cyst.api.host.service import Service
from cyst.api.logic.access import AuthenticationProviderType, AuthenticationTokenType, AuthenticationTokenSecurity

from cyst.services.scripted_attacker.main import ScriptedAttackerControl, ActionQueueItem

# The following scenario is an implementation of the use case provided in the NCIA AICA prototype report.
# It consists of the following steps:
# - the attacker scans a network
# - the IDS identifies the scan and alerts the agent
# - the agent redirects the communication to the honeypot
#
# The defending AICA agent, implementing the MASCARA architecture, runs in a separate docker container and communicates
# with the simulation engine via a proxy

# ----------------------------------------------------------------------------------------------------------------------
# Attacker configuration
# ----------------------------------------------------------------------------------------------------------------------
attacker = NodeConfig(
    active_services=[
        ActiveServiceConfig(
            type="scripted_attacker",
            name="scripted_attacker",
            owner="attacker",
            access_level=AccessLevel.LIMITED,
            id="attacker_service"
        )
    ],
    passive_services=[],
    traffic_processors=[],
    shell="bash",
    interfaces=[
        InterfaceConfig(
            ip=IPAddress("192.168.0.101"),
            net=IPNetwork("192.168.0.1/24")
        )
    ],
    id="attacker"
)

# ----------------------------------------------------------------------------------------------------------------------
# Server configuration
#
# Within this scenario, the attacker is not going to get further than scanning, so there will be two servers with some
# services, but without any associated exploits. To enable their exploitation and continuation of the attack, another
# exploits would have to be added. To get an idea of how it should look like, check tests/integration/test_aif.py.
#
# server1 also contains an SSH service, which could be theoretically used by the attacker for session establishment,
# but the credentials will be nowhere to found. It is only for illustration purposes.
# ----------------------------------------------------------------------------------------------------------------------
local_password_auth = AuthenticationProviderConfig(
    provider_type=AuthenticationProviderType.LOCAL,
    token_type=AuthenticationTokenType.PASSWORD,
    token_security=AuthenticationTokenSecurity.SEALED,
    timeout=30
)

server1 = NodeConfig(
    active_services=[],
    traffic_processors=[],
    passive_services=[
        PassiveServiceConfig(
            type="openssh",
            owner="bash",
            version="8.1.0",
            local=False,
            access_level=AccessLevel.ELEVATED,
            authentication_providers=[local_password_auth("server1_local_pwd_auth")],
            parameters=[
                (ServiceParameter.ENABLE_SESSION, True),
                (ServiceParameter.SESSION_ACCESS_LEVEL, AccessLevel.LIMITED)
            ],
            access_schemes=[AccessSchemeConfig(
                    authentication_providers=["server1_local_pwd_auth"],
                    authorization_domain=AuthorizationDomainConfig(
                        type=AuthorizationDomainType.LOCAL,
                        authorizations=[
                            AuthorizationConfig("user1", AccessLevel.LIMITED, id="ssh_auth_1"),
                            AuthorizationConfig("user2", AccessLevel.LIMITED, id="ssh_auth_2"),
                            AuthorizationConfig("root", AccessLevel.ELEVATED)
                        ]
                    )
                )]
        ),
        PassiveServiceConfig(
            type="lighttpd",
            owner="lighttpd",
            version="1.4.59",
            local=False,
            access_level=AccessLevel.LIMITED
        )
    ],
    shell="bash",
    interfaces=[
        InterfaceConfig(
            ip=IPAddress("192.168.0.11"),
            net=IPNetwork("192.168.0.1/24")
        )
    ],
    id="server1"
)

server2 = NodeConfig(
    active_services=[],
    traffic_processors=[],
    passive_services=[
        PassiveServiceConfig(
            type="postgresql",
            owner="postgres",
            version="10.19.0",
            local=False,
            access_level=AccessLevel.LIMITED
        )
    ],
    shell="bash",
    interfaces=[
        InterfaceConfig(
            ip=IPAddress("192.168.0.12"),
            net=IPNetwork("192.168.0.1/24")
        )
    ],
    id="server2"
)

# ----------------------------------------------------------------------------------------------------------------------
# Honeypot configuration
#
# Honeypot implements an active service which just returns a service.success to all requests
# ----------------------------------------------------------------------------------------------------------------------
honeypot = NodeConfig(
    active_services=[
        ActiveServiceConfig(
            type="ncia_honeypot",
            name="ncia_honeypot",
            owner="bash",
            access_level=AccessLevel.LIMITED,
            id="honeypot_service"
        )
    ],
    traffic_processors=[],
    passive_services=[],
    shell="bash",
    interfaces=[
        InterfaceConfig(
            ip=IPAddress("192.168.0.201"),
            net=IPNetwork("192.168.0.1/24")
        )
    ],
    id="honeypot"
)

# ----------------------------------------------------------------------------------------------------------------------
# PC configuration
#
# PCs here are present only to act as dummy targets, as such they only have one RDP service running
# ----------------------------------------------------------------------------------------------------------------------
pc1 = NodeConfig(
    active_services=[],
    traffic_processors=[],
    passive_services=[
        PassiveServiceConfig(
            type="rdp",
            owner="Administrator",
            version="10.0.19041",
            local=False,
            access_level=AccessLevel.LIMITED
        )
    ],
    shell="cmd",
    interfaces=[
        InterfaceConfig(
            ip=IPAddress("192.168.0.51"),
            net=IPNetwork("192.168.0.1/24")
        )
    ],
    id="pc1"
)

pc2 = NodeConfig(
    active_services=[],
    traffic_processors=[],
    passive_services=[
        PassiveServiceConfig(
            type="rdp",
            owner="Administrator",
            version="10.0.19041",
            local=False,
            access_level=AccessLevel.LIMITED
        )
    ],
    shell="cmd",
    interfaces=[
        InterfaceConfig(
            ip=IPAddress("192.168.0.52"),
            net=IPNetwork("192.168.0.1/24")
        )
    ],
    id="pc2"
)

# ----------------------------------------------------------------------------------------------------------------------
# IDS and agent's node configuration
#
# IDS takes messages from router via a span port
# ----------------------------------------------------------------------------------------------------------------------
ids = NodeConfig(
    active_services=[],
    traffic_processors=[
        ActiveServiceConfig(
            type="ncia_ids",
            name="ncia_ids",
            owner="bash",
            access_level=AccessLevel.LIMITED,
            id="ids_service",
            configuration={"defender_ip": "192.168.0.78"}
        )
    ],
    passive_services=[],
    shell="cmd",
    interfaces=[
        InterfaceConfig(
            ip=IPAddress("192.168.0.76"),
            net=IPNetwork("192.168.0.1/24")
        ),
        InterfaceConfig(
            ip=IPAddress("192.168.0.77"),
            net=IPNetwork("192.168.0.1/24")
        ),
    ],
    id="ids"
)

defender = NodeConfig(
    active_services=[
        ActiveServiceConfig(
            type="ncia_defender",
            name="ncia_defender",
            owner="bash",
            access_level=AccessLevel.LIMITED,
            id="defender_service",
            configuration={"honeypot": "192.168.0.201"}
        )
    ],
    traffic_processors=[],
    passive_services=[],
    shell="cmd",
    interfaces=[
        InterfaceConfig(
            ip=IPAddress("192.168.0.78"),
            net=IPNetwork("192.168.0.1/24")
        )
    ],
    id="defender"
)

# ----------------------------------------------------------------------------------------------------------------------
# Router configuration
#
# The router connects all nodes into a star pattern
# ----------------------------------------------------------------------------------------------------------------------
router = RouterConfig(
    interfaces=[
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=0),
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=1),
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=2),
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=3),
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=4),
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=5),
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=6),
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=7),
        InterfaceConfig(IPAddress("192.168.0.1"), IPNetwork("192.168.0.1/24"), index=8)
    ],
    id="router"
)

connections = [
    ConnectionConfig("router", 0, "attacker", 0),
    ConnectionConfig("router", 1, "server1", 0),
    ConnectionConfig("router", 2, "server2", 0),
    ConnectionConfig("router", 3, "pc1", 0),
    ConnectionConfig("router", 4, "pc2", 0),
    ConnectionConfig("router", 5, "honeypot", 0),
    ConnectionConfig("router", 6, "defender", 0),
    ConnectionConfig("router", 7, "ids", 0),
    ConnectionConfig("router", 8, "ids", 1)
]


# ----------------------------------------------------------------------------------------------------------------------
# The scenario is realized as a test case to make it simpler to run and control
# ----------------------------------------------------------------------------------------------------------------------
class NCIAPrototype(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._env = Environment.create().configure(attacker, server1, server2, pc1, pc2, honeypot, router, ids, defender, *connections)
        cls._attacker = cls._env.configuration.service.get_service_interface(
            cls._env.configuration.general.get_object_by_id("attacker_service", Service).active_service,
            ScriptedAttackerControl)

        # Manually set router's port 8 as span, so that IDS is fed all the traffic in the network
        r = cls._env.configuration.general.get_object_by_id("router", Node)
        cls._env.configuration.node.set_span_port(r, 8)

        cls._action_list = cls._env.resources.action_store.get_prefixed("aif")
        cls._actions = {}
        for action in cls._action_list:
            cls._actions[action.id] = action

    def test_prototype(self) -> None:
        # Let the attacker do a delayed scan of the entire 192.168.0.1/24 network
        action = self._actions["aif:active_recon:host_discovery"]
        net = IPNetwork("192.168.0.1/24")

        time = 0
        for ip in net:
            self._attacker.enqueue_action(ActionQueueItem(time, str(ip), "", action))
            time += 2

        self._env.control.init()
        self._env.control.run()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._env.control.commit()

        f = open("messages.json", "w")
        f.write("{\"messages\": [\n")

        # Data is accessed directly here in violation of public APIs, because those APIs are not stabilized yet
        first = True
        for m in cls._env._data_store._backend._store[cls._env._run_id]["Message"]:
            if not first:
                f.write(",")
            else:
                first = False
            f.write("{{\"ID\": {}, \"Type\": \"{}\", \"Origin\": \"{}\", \"Source\": \"{}\", \"Target\": \"{}\", \"Destination service\": \"{}\", \"Source service\": \"{}\", \"Action\": \"{}\", \"Session\": \"{}\", \"Authorization\": \"{}\", \"timestamp\": {} }}\n".format(
                m["id"], m["type"], m["src_ip"], m["hop_src_id"], m["hop_dst_id"], m["dst_service"], m["src_service"], m["action"], "", "", m["timestamp"]))

        f.write("]}")
        f.close()


if __name__ == '__main__':
    unittest.main()