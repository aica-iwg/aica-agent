import unittest
import random

from cyst.api.environment.environment import Environment
from cyst.api.logic.access import AccessLevel

from cyst.services.scripted_attacker.main import ScriptedAttackerControl


class ActionTests(unittest.TestCase):

    def test_0000_blocking(self) -> None:
        env = Environment.create()

        # Function aliases to make it more readable
        create_node = env.configuration.node.create_node
        create_router = env.configuration.node.create_router
        create_active_service = env.configuration.service.create_active_service
        create_passive_service = env.configuration.service.create_passive_service
        add_service = env.configuration.node.add_service
        add_traffic_processor = env.configuration.node.add_traffic_processor
        set_service_parameter = env.configuration.service.set_service_parameter
        create_interface = env.configuration.node.create_interface
        add_node = env.configuration.network.add_node
        add_connection = env.configuration.network.add_connection
        add_route = env.configuration.node.add_route
        add_interface = env.configuration.node.add_interface
        create_session = env.configuration.network.create_session
        public_data = env.configuration.service.public_data
        private_data = env.configuration.service.private_data
        sessions = env.configuration.service.sessions
        create_data = env.configuration.service.create_data
        create_authorization = env.policy.create_authorization
        #add_authorization = env.policy.add_authorization
        private_authorizations = env.configuration.service.private_authorizations
        add_exploit = env.configuration.exploit.add_exploit
        create_exploit = env.configuration.exploit.create_exploit
        create_vulnerable_service = env.configuration.exploit.create_vulnerable_service
        create_exploit_parameter = env.configuration.exploit.create_exploit_parameter
        set_shell = env.configuration.node.set_shell
        add_routing_rule = env.configuration.node.add_routing_rule

        # Attacker
        attacker_node = create_node("attacker_node")
        attacker_service = create_active_service("scripted_attacker", "attacker", "attacker_omniscient", attacker_node)
        add_service(attacker_node, attacker_service)
        attacker: ScriptedAttackerControl = env.configuration.service.get_service_interface(attacker_service.active_service, ScriptedAttackerControl)
        attacker_port = add_interface(attacker_node, create_interface("10.0.0.1", "255.255.255.0"))

        add_node(attacker_node)

        # Target
        target_node = create_node("target_node")
        postfix = create_passive_service("postfix", owner="mail", version="3.5.0", local=False)
        bash = create_passive_service("bash", owner="bash", version="5.0.0", local=True, service_access_level=AccessLevel.LIMITED)
        add_service(target_node, postfix, bash)
        target_port = add_interface(target_node, create_interface("10.0.0.2", "255.255.255.0"))

        # Add traffic processing IDS
        ids_service = create_active_service("event_driven_host_ids", "target", "ids_0", target_node)
        add_traffic_processor(target_node, ids_service.active_service)

        add_node(target_node)

        add_connection(attacker_node, target_node, attacker_port, target_port)

        env.control.init()

        # --------------------------------------------------------------------------------------------------------------
        action = env.resources.action_store.get("aif:active_recon:host_discovery")
        action.parameters["scanning_technique"].value = "TCP SYN"

        attacker.execute_action("10.0.0.2", "postfix", action)

        env.control.run()