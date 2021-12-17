from typing import Any, Dict, List, NamedTuple, Optional, Tuple
from netaddr import IPAddress, IPNetwork

from cyst.api.host.service import ActiveService, ActiveServiceDescription
from cyst.api.environment.message import Message
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.network.firewall import Firewall, FirewallChainType, FirewallRule, FirewallPolicy


class FirewallImpl(ActiveService, Firewall):

    class FirewallChain:
        def __init__(self, type: FirewallChainType, policy: FirewallPolicy = FirewallPolicy.DENY) -> None:
            self._type = type
            self._default_policy = policy
            self._rules = []

        @property
        def default_policy(self) -> FirewallPolicy:
            return self._default_policy

        @property
        def type(self) -> FirewallChainType:
            return self._type

        def set_default_policy(self, policy: FirewallPolicy) -> None:
            self._default_policy = policy

        def add_rule(self, rule: FirewallRule) -> None:
            self._rules.append(rule)

        def remove_rule(self, index: int) -> None:
            del self._rules[index]

        def list_rules(self) -> List[FirewallRule]:
            return self._rules

        def evaluate(self, src_ip: IPAddress, dst_ip: IPAddress, dst_service: str) -> Tuple[bool, int]:
            for rule in self._rules:
                if src_ip in rule.src_net and dst_ip in rule.dst_net and (rule.service == "*" or dst_service == rule.service):
                    if rule.policy == FirewallPolicy.ALLOW:
                        return True, 0
                    elif rule.policy == FirewallPolicy.DENY:
                        return False, 0

            if self._default_policy == FirewallPolicy.ALLOW:
                return True, 0

            return False, 0

    def __init__(self, env: EnvironmentMessaging = None, args: Optional[Dict[str, Any]] = None) -> None:
        default_policy = FirewallPolicy.DENY
        if args:
            default_policy = args.get("default_policy", FirewallPolicy.DENY)

        self._chains = {
            FirewallChainType.INPUT: FirewallImpl.FirewallChain(FirewallChainType.INPUT, default_policy),
            FirewallChainType.OUTPUT: FirewallImpl.FirewallChain(FirewallChainType.OUTPUT, default_policy),
            FirewallChainType.FORWARD: FirewallImpl.FirewallChain(FirewallChainType.FORWARD, default_policy)
        }

        self._local_ips = []

    def run(self):
        pass

    def add_local_ip(self, ip: IPAddress) -> None:
        self._local_ips.append(ip)

    def remove_local_ip(self, ip: IPAddress) -> None:
        self._local_ips.remove(ip)

    def add_rule(self, chain: FirewallChainType, rule: FirewallRule) -> None:
        self._chains[chain].add_rule(rule)

    def remove_rule(self, chain: FirewallChainType, index: int) -> None:
        self._chains[chain].remove_rule(index)

    def list_rules(self, chain: Optional[FirewallChainType] = None) -> List[Tuple[FirewallChainType, FirewallPolicy, List[FirewallRule]]]:
        if not chain:
            return [(x.type, x.default_policy, x.list_rules()) for x in self._chains.values()]

    def set_default_policy(self, chain: FirewallChainType, policy: FirewallPolicy) -> None:
        self._chains[chain].set_default_policy(policy)

    def get_default_policy(self, chain: FirewallChainType) -> FirewallPolicy:
        return self._chains[chain].default_policy

    def evaluate(self, src_ip: IPAddress, dst_ip: IPAddress, dst_service: str) -> Tuple[bool, int]:
        local_src = src_ip in self._local_ips
        local_dst = dst_ip in self._local_ips

        # By convention allow all communication between local IPs (usually loopback)
        chain = None
        if local_src and local_dst:
            return True, 0
        elif local_src:
            chain = FirewallChainType.OUTPUT
        elif local_dst:
            chain = FirewallChainType.INPUT
        else:
            chain = FirewallChainType.FORWARD

        return self._chains[chain].evaluate(src_ip, dst_ip, dst_service)

    def process_message(self, message: Message) -> Tuple[bool, int]:
        return self.evaluate(message.src_ip, message.dst_ip, message.dst_service)


def create_firewall(msg: EnvironmentMessaging, res: EnvironmentResources, args: Optional[Dict[str, Any]]) -> ActiveService:
    fw = FirewallImpl(msg, args)
    return fw


service_description = ActiveServiceDescription(
    "firewall",
    "An implementation of a firewall service",
    create_firewall
)