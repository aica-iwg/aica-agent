from dataclasses import dataclass, field
from typing import List
from uuid import uuid4
from tools.serde_customized import serialize

from cyst.api.configuration.configuration import ConfigItem
from cyst.api.network.firewall import FirewallRule, FirewallChainType, FirewallPolicy


@serialize
@dataclass
class FirewallChainConfig(ConfigItem):
    type: FirewallChainType
    policy: FirewallPolicy
    rules: List[FirewallRule]
    id: str = field(default_factory=lambda: str(uuid4()))


@serialize
@dataclass
class FirewallConfig(ConfigItem):
    default_policy: FirewallPolicy
    chains: List[FirewallChainConfig]
    id: str = field(default_factory=lambda: str(uuid4()))
